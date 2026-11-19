//! DB reads/writes for the CVE sources (Phase 1b).
//!
//! Field ownership: the cvelist writer owns `state`, `assigner`, `description`,
//! `published`, `cvelist_updated`, the `cna_*`/`adp_*` scores, SSVC, `refs` and
//! the `cna`/`adp` rows of `cve_affected`. The NVD writers own `nvd_*`, the
//! `nvd` affected rows and `fixed_nvd`. Both maintain their slice of `cvss_all`
//! and the derived `last_modified` / `fixed_versions`.

use std::collections::BTreeSet;

use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::de::DeserializeOwned;

use super::DbResult;
use crate::model::{Affected, Cvss, CvssSource, KevEntry, now_rfc3339};
use crate::monitors::cve::matcher::row_keys;
use crate::monitors::cve::normalize::{
    is_unknown, normalize_product, normalize_vendor, parse_cpe, squash,
};

/// CISA-ADP SSVC decision points (values lowercased).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ssvc {
    pub exploitation: Option<String>,
    pub automatable: Option<String>,
    pub technical_impact: Option<String>,
    pub timestamp: Option<String>,
}

/// A parsed cvelistV5 record, ready to persist.
#[derive(Debug, Clone, PartialEq)]
pub struct CvelistUpsert {
    pub cve_id: String,
    pub state: String,
    pub assigner: Option<String>,
    pub description: String,
    pub published: Option<String>,
    /// `cveMetadata.dateUpdated`, normalized by [`normalize_ts`].
    pub date_updated: String,
    /// Best CNA score (v4.0 > v3.1 > v3.0 > v2.0).
    pub cna_cvss: Option<Cvss>,
    /// Best ADP score.
    pub adp_cvss: Option<Cvss>,
    /// Every CNA and ADP metric seen.
    pub cvss_all: Vec<Cvss>,
    pub ssvc: Ssvc,
    pub adp_kev_date: Option<String>,
    /// Rows with source `Cna` or `Adp`.
    pub affected: Vec<Affected>,
    pub fixed_versions: Vec<String>,
    pub references: Vec<String>,
}

/// A parsed NVD 2.0 `cve` object, ready to persist.
#[derive(Debug, Clone, PartialEq)]
pub struct NvdUpsert {
    pub cve_id: String,
    /// `REJECTED` when `vulnStatus` is Rejected, else `PUBLISHED` (used on insert only).
    pub state: String,
    pub description: String,
    pub published: Option<String>,
    pub last_modified: String,
    pub vuln_status: Option<String>,
    /// Selected NVD score (Primary preferred, then highest version).
    pub cvss: Option<Cvss>,
    pub cvss_all: Vec<Cvss>,
    /// Rows with source `Nvd`.
    pub affected: Vec<Affected>,
    pub fixed_versions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertResult {
    Inserted,
    Updated,
    /// Stored data is already as new as the incoming record.
    Skipped,
}

/// Normalize an upstream timestamp (`...Z`, no zone, offset, with/without
/// fractional seconds) to `YYYY-MM-DDTHH:MM:SS.mmmZ`, so strings compare
/// chronologically. Unparseable input is returned unchanged.
pub fn normalize_ts(s: &str) -> String {
    let s = s.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return dt
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::Millis, true);
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(n) = NaiveDateTime::parse_from_str(s, fmt) {
            return n.and_utc().to_rfc3339_opts(SecondsFormat::Millis, true);
        }
    }
    s.to_owned()
}

// ---- cursors ---------------------------------------------------------------

/// Load a source's typed cursor (default when absent/unparseable) and ETag.
pub fn load_cursor<T: DeserializeOwned + Default>(
    conn: &Connection,
    source: &str,
) -> DbResult<(T, Option<String>)> {
    let st = super::repo::get_source_status(conn, source)?;
    Ok(match st {
        Some(s) => (
            s.cursor
                .and_then(|c| serde_json::from_str(&c).ok())
                .unwrap_or_default(),
            s.etag,
        ),
        None => (T::default(), None),
    })
}

/// Persist the cursor only (progress checkpoint; `last_success` is untouched).
pub fn save_cursor(conn: &Connection, source: &str, cursor: &str) -> DbResult<()> {
    conn.execute(
        "INSERT INTO source_status (source, cursor) VALUES (?1, ?2) \
         ON CONFLICT(source) DO UPDATE SET cursor = excluded.cursor",
        params![source, cursor],
    )?;
    Ok(())
}

// ---- cves ------------------------------------------------------------------

fn union_json(a: &[String], b: &[String]) -> DbResult<String> {
    let mut seen = BTreeSet::new();
    let v: Vec<&String> = a.iter().chain(b).filter(|x| seen.insert(*x)).collect();
    Ok(serde_json::to_string(&v)?)
}

fn merge_cvss_all(existing_json: &str, keep: &[CvssSource], new: &[Cvss]) -> DbResult<String> {
    let old: Vec<Cvss> = serde_json::from_str(existing_json).unwrap_or_default();
    let mut all: Vec<&Cvss> = old.iter().filter(|c| keep.contains(&c.source)).collect();
    all.extend(new.iter());
    Ok(serde_json::to_string(&all)?)
}

fn source_str(s: CvssSource) -> &'static str {
    match s {
        CvssSource::Cna => "cna",
        CvssSource::Adp => "adp",
        CvssSource::Nvd => "nvd",
    }
}

fn insert_affected(conn: &Connection, cve_id: &str, a: &Affected) -> DbResult<()> {
    let parsed = a.cpe.as_deref().and_then(parse_cpe);
    let vendor_raw = a
        .vendor
        .clone()
        .or_else(|| parsed.as_ref().map(|p| p.vendor.clone()));
    let product_raw = a
        .product
        .clone()
        .or_else(|| parsed.as_ref().map(|p| p.product.clone()));
    let vendor_norm = vendor_raw
        .as_deref()
        .filter(|v| !is_unknown(v))
        .map(normalize_vendor);
    let product_ok = product_raw.as_deref().filter(|p| !is_unknown(p));
    let product_norm = product_ok.map(normalize_product);
    let product_squash = product_ok.map(squash);
    let product_keys =
        product_ok.map(|p| row_keys(vendor_raw.as_deref().filter(|v| !is_unknown(v)), p));
    let mut st = conn.prepare_cached(
        "INSERT INTO cve_affected (cve_id, source, vendor_raw, product_raw, vendor_norm, \
             product_norm, product_squash, cpe, cpe_vendor, cpe_product, versions, product_keys) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
    )?;
    st.execute(params![
        cve_id,
        source_str(a.source),
        vendor_raw,
        product_raw,
        vendor_norm,
        product_norm,
        product_squash,
        a.cpe,
        parsed.as_ref().map(|p| p.vendor.as_str()),
        parsed.as_ref().map(|p| p.product.as_str()),
        serde_json::to_string(&a.versions)?,
        product_keys,
    ])?;
    Ok(())
}

/// Fill `product_keys` for rows written before migration 004. Returns rows updated.
pub fn backfill_product_keys(conn: &mut Connection) -> DbResult<usize> {
    let rows: Vec<(i64, Option<String>, String)> = {
        let mut st = conn.prepare(
            "SELECT id, vendor_raw, product_raw FROM cve_affected              WHERE product_keys IS NULL AND product_raw IS NOT NULL",
        )?;
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?
    };
    if rows.is_empty() {
        return Ok(0);
    }
    let tx = conn.transaction()?;
    for (id, v, p) in &rows {
        let keys = if is_unknown(p) {
            String::new()
        } else {
            row_keys(v.as_deref().filter(|v| !is_unknown(v)), p)
        };
        tx.execute(
            "UPDATE cve_affected SET product_keys = ?2 WHERE id = ?1",
            params![id, keys],
        )?;
    }
    tx.commit()?;
    Ok(rows.len())
}

fn replace_affected(
    conn: &Connection,
    cve_id: &str,
    sources: &[CvssSource],
    rows: &[Affected],
) -> DbResult<()> {
    for s in sources {
        conn.execute(
            "DELETE FROM cve_affected WHERE cve_id = ?1 AND source = ?2",
            params![cve_id, source_str(*s)],
        )?;
    }
    for a in rows {
        insert_affected(conn, cve_id, a)?;
    }
    Ok(())
}

/// Insert or update from a cvelist record. Skips when the stored
/// `cvelist_updated` is not older than the record's `dateUpdated`.
pub fn upsert_cvelist(conn: &Connection, r: &CvelistUpsert) -> DbResult<UpsertResult> {
    let existing: Option<(Option<String>, String, String)> = conn
        .query_row(
            "SELECT cvelist_updated, cvss_all, fixed_nvd FROM cves WHERE cve_id = ?1",
            [&r.cve_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((Some(stored), _, _)) = &existing
        && stored.as_str() >= r.date_updated.as_str()
    {
        return Ok(UpsertResult::Skipped);
    }
    let (old_all, old_fixed_nvd) = existing
        .as_ref()
        .map(|(_, a, f)| (a.as_str(), f.as_str()))
        .unwrap_or(("[]", "[]"));
    let cvss_all = merge_cvss_all(old_all, &[CvssSource::Nvd], &r.cvss_all)?;
    let fixed_nvd: Vec<String> = serde_json::from_str(old_fixed_nvd).unwrap_or_default();
    let fixed_cna = serde_json::to_string(&r.fixed_versions)?;
    let fixed_all = union_json(&r.fixed_versions, &fixed_nvd)?;
    let refs = serde_json::to_string(&r.references)?;
    let (cna, adp) = (r.cna_cvss.as_ref(), r.adp_cvss.as_ref());

    if existing.is_none() {
        conn.execute(
            "INSERT INTO cves (cve_id, state, assigner, description, published, last_modified, \
                 cvelist_updated, first_seen_at, cna_cvss_score, cna_cvss_vector, cna_cvss_version, \
                 adp_cvss_score, adp_cvss_vector, adp_cvss_version, cvss_all, ssvc_exploitation, \
                 ssvc_automatable, ssvc_tech_impact, ssvc_timestamp, adp_kev_date, fixed_versions, \
                 fixed_cna, refs) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
                 ?18, ?19, ?20, ?21, ?22)",
            params![
                r.cve_id,
                r.state,
                r.assigner,
                r.description,
                r.published,
                r.date_updated,
                now_rfc3339(),
                cna.map(|c| c.score),
                cna.and_then(|c| c.vector.as_deref()),
                cna.map(|c| c.version.as_str()),
                adp.map(|c| c.score),
                adp.and_then(|c| c.vector.as_deref()),
                adp.map(|c| c.version.as_str()),
                cvss_all,
                r.ssvc.exploitation,
                r.ssvc.automatable,
                r.ssvc.technical_impact,
                r.ssvc.timestamp,
                r.adp_kev_date,
                fixed_all,
                fixed_cna,
                refs,
            ],
        )?;
    } else {
        conn.execute(
            "UPDATE cves SET state = ?2, assigner = ?3, description = ?4, published = ?5, \
                 cvelist_updated = ?6, \
                 last_modified = max(?6, COALESCE(nvd_updated, '')), \
                 cna_cvss_score = ?7, cna_cvss_vector = ?8, cna_cvss_version = ?9, \
                 adp_cvss_score = ?10, adp_cvss_vector = ?11, adp_cvss_version = ?12, \
                 cvss_all = ?13, ssvc_exploitation = ?14, ssvc_automatable = ?15, \
                 ssvc_tech_impact = ?16, ssvc_timestamp = ?17, adp_kev_date = ?18, \
                 fixed_versions = ?19, fixed_cna = ?20, refs = ?21 \
             WHERE cve_id = ?1",
            params![
                r.cve_id,
                r.state,
                r.assigner,
                r.description,
                r.published,
                r.date_updated,
                cna.map(|c| c.score),
                cna.and_then(|c| c.vector.as_deref()),
                cna.map(|c| c.version.as_str()),
                adp.map(|c| c.score),
                adp.and_then(|c| c.vector.as_deref()),
                adp.map(|c| c.version.as_str()),
                cvss_all,
                r.ssvc.exploitation,
                r.ssvc.automatable,
                r.ssvc.technical_impact,
                r.ssvc.timestamp,
                r.adp_kev_date,
                fixed_all,
                fixed_cna,
                refs,
            ],
        )?;
    }
    replace_affected(
        conn,
        &r.cve_id,
        &[CvssSource::Cna, CvssSource::Adp],
        &r.affected,
    )?;
    Ok(if existing.is_none() {
        UpsertResult::Inserted
    } else {
        UpsertResult::Updated
    })
}

/// Apply NVD enrichment. Creates the row when absent; otherwise only touches
/// `nvd_*`, the nvd affected rows, `fixed_nvd` and the derived columns (the
/// description/published are filled only when empty).
pub fn upsert_nvd(conn: &Connection, r: &NvdUpsert) -> DbResult<UpsertResult> {
    let existing: Option<(Option<String>, String, String)> = conn
        .query_row(
            "SELECT nvd_updated, cvss_all, fixed_cna FROM cves WHERE cve_id = ?1",
            [&r.cve_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((Some(stored), _, _)) = &existing
        && stored.as_str() >= r.last_modified.as_str()
    {
        return Ok(UpsertResult::Skipped);
    }
    let (old_all, old_fixed_cna) = existing
        .as_ref()
        .map(|(_, a, f)| (a.as_str(), f.as_str()))
        .unwrap_or(("[]", "[]"));
    let cvss_all = merge_cvss_all(old_all, &[CvssSource::Cna, CvssSource::Adp], &r.cvss_all)?;
    let fixed_cna: Vec<String> = serde_json::from_str(old_fixed_cna).unwrap_or_default();
    let fixed_nvd = serde_json::to_string(&r.fixed_versions)?;
    let fixed_all = union_json(&fixed_cna, &r.fixed_versions)?;
    let c = r.cvss.as_ref();

    if existing.is_none() {
        conn.execute(
            "INSERT INTO cves (cve_id, state, description, published, last_modified, nvd_updated, \
                 nvd_status, first_seen_at, nvd_cvss_score, nvd_cvss_vector, nvd_cvss_version, \
                 nvd_cvss_primary, cvss_all, fixed_versions, fixed_nvd) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                r.cve_id,
                r.state,
                r.description,
                r.published,
                r.last_modified,
                r.vuln_status,
                now_rfc3339(),
                c.map(|c| c.score),
                c.and_then(|c| c.vector.as_deref()),
                c.map(|c| c.version.as_str()),
                c.is_some_and(|c| c.primary),
                cvss_all,
                fixed_all,
                fixed_nvd,
            ],
        )?;
    } else {
        conn.execute(
            "UPDATE cves SET nvd_updated = ?2, nvd_status = ?3, \
                 last_modified = max(?2, COALESCE(cvelist_updated, '')), \
                 nvd_cvss_score = ?4, nvd_cvss_vector = ?5, nvd_cvss_version = ?6, \
                 nvd_cvss_primary = ?7, cvss_all = ?8, fixed_versions = ?9, fixed_nvd = ?10, \
                 description = CASE WHEN description = '' THEN ?11 ELSE description END, \
                 published = COALESCE(published, ?12) \
             WHERE cve_id = ?1",
            params![
                r.cve_id,
                r.last_modified,
                r.vuln_status,
                c.map(|c| c.score),
                c.and_then(|c| c.vector.as_deref()),
                c.map(|c| c.version.as_str()),
                c.is_some_and(|c| c.primary),
                cvss_all,
                fixed_all,
                fixed_nvd,
                r.description,
                r.published,
            ],
        )?;
    }
    replace_affected(conn, &r.cve_id, &[CvssSource::Nvd], &r.affected)?;
    Ok(if existing.is_none() {
        UpsertResult::Inserted
    } else {
        UpsertResult::Updated
    })
}

/// Delete CVEs (and, by cascade, their affected rows) last modified before
/// `cutoff` (normalized RFC 3339) that match no tracked product, were never
/// delivered to any consumer and are not in KEV. Returns the number removed.
pub fn prune_unmatched(conn: &Connection, cutoff: &str) -> DbResult<usize> {
    Ok(conn.execute(
        "DELETE FROM cves WHERE last_modified < ?1            AND NOT EXISTS (SELECT 1 FROM cve_product_matches m WHERE m.cve_id = cves.cve_id)            AND NOT EXISTS (SELECT 1 FROM delivered d WHERE d.cve_id = cves.cve_id)            AND NOT EXISTS (SELECT 1 FROM kev k WHERE k.cve_id = cves.cve_id)",
        [cutoff],
    )?)
}

// ---- KEV / EPSS --------------------------------------------------------------

/// Upsert every KEV entry in one transaction. `first_seen_at` is written only
/// on insert; every other field (notably `ransomware`) is refreshed. Returns
/// the ids that were not in the table before.
pub fn upsert_kev(conn: &mut Connection, entries: &[KevEntry]) -> DbResult<Vec<String>> {
    let tx = conn.transaction()?;
    let mut new_ids = Vec::new();
    {
        let mut exists = tx.prepare("SELECT 1 FROM kev WHERE cve_id = ?1")?;
        let mut up = tx.prepare(
            "INSERT INTO kev (cve_id, vendor_project, product, name, date_added, due_date, \
                 ransomware, first_seen_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
             ON CONFLICT(cve_id) DO UPDATE SET vendor_project = excluded.vendor_project, \
                 product = excluded.product, name = excluded.name, \
                 date_added = excluded.date_added, due_date = excluded.due_date, \
                 ransomware = excluded.ransomware",
        )?;
        for e in entries {
            let existed = exists.exists([&e.cve_id])?;
            up.execute(params![
                e.cve_id,
                e.vendor_project,
                e.product,
                e.name,
                e.date_added,
                e.due_date,
                e.ransomware,
                e.first_seen_at,
            ])?;
            if !existed {
                new_ids.push(e.cve_id.clone());
            }
        }
    }
    tx.commit()?;
    Ok(new_ids)
}

/// Prepared bulk writer for the `epss` table.
pub struct EpssWriter<'a> {
    st: rusqlite::CachedStatement<'a>,
}

impl<'a> EpssWriter<'a> {
    pub fn new(tx: &'a Transaction<'_>) -> DbResult<Self> {
        Ok(Self {
            st: tx.prepare_cached(
                "INSERT INTO epss (cve_id, score, percentile, score_date) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(cve_id) DO UPDATE SET score = excluded.score, \
                     percentile = excluded.percentile, score_date = excluded.score_date",
            )?,
        })
    }

    pub fn write(&mut self, cve_id: &str, score: f64, percentile: f64, date: &str) -> DbResult<()> {
        self.st.execute(params![cve_id, score, percentile, date])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_normalize_to_comparable_millis() {
        assert_eq!(
            normalize_ts("2026-11-19T20:59:01.12"),
            "2026-11-19T20:59:01.120Z"
        );
        assert_eq!(
            normalize_ts("2026-11-19T20:59:01Z"),
            "2026-11-19T20:59:01.000Z"
        );
        assert_eq!(
            normalize_ts("2026-11-19T16:00:08-05:00"),
            "2026-11-19T21:00:08.000Z"
        );
        assert_eq!(normalize_ts("garbage"), "garbage");
    }
}
