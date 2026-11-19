//! Primary source: CVEProject/cvelistV5 GitHub release delta zips.
//!
//! Deltas are cumulative per UTC day (`cve_YYYY-MM-DD_HH00Z`), so each run
//! downloads the newest delta for the newest day and every missed day's
//! `end_of_day` delta (falling back to that day's last hourly one). Records
//! whose `dateUpdated` is not newer than the stored `cvelist_updated` are
//! skipped, which makes re-applying a cumulative zip cheap and idempotent.
//! ADP (CISA Vulnrichment) data is inside the same records.
//!
//! The release listing is read from the GitHub REST API (unauthenticated, or
//! with `GITHUB_TOKEN`); the asset URLs it returns are used as-is.
//!
//! Catch-up is capped at [`CvelistSource::max_catchup_days`] days. A larger gap
//! (or an empty database) is logged and NOT back-filled from the 667 MB
//! `all_CVEs_at_midnight` baseline: that is a deliberate, separate operation.

use std::io::{Cursor, Read};

use anyhow::{Context, Result, bail};
use chrono::NaiveDate;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Source, SourceContext, SyncOutcome, tracked};
use crate::db::{
    DbResult,
    cve_repo::{
        CvelistUpsert, Ssvc, UpsertResult, load_cursor, normalize_ts, save_cursor, upsert_cvelist,
    },
    repo,
};
use crate::model::{Affected, Cvss, CvssSource};

pub const SOURCE: &str = "cvelist";
pub const API_BASE: &str = "https://api.github.com";
pub const REPO: &str = "CVEProject/cvelistV5";

/// Persisted as JSON in `source_status.cursor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CvelistCursor {
    /// Last delta tag applied, e.g. `cve_2026-11-19_2100Z`.
    pub last_delta_tag: Option<String>,
    /// Max `dateUpdated` (ISO, ms) among applied records.
    pub max_date_updated: Option<String>,
}

pub struct CvelistSource {
    pub api_base: String,
    pub repo: String,
    /// Optional GitHub token (raises the API rate limit; never required).
    pub github_token: Option<String>,
    /// Most days of deltas fetched in one run.
    pub max_catchup_days: usize,
    /// Most release-list pages (100 releases each) read in one run.
    pub max_pages: usize,
}

impl Default for CvelistSource {
    fn default() -> Self {
        Self {
            api_base: API_BASE.into(),
            repo: REPO.into(),
            github_token: std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty()),
            max_catchup_days: 7,
            max_pages: 5,
        }
    }
}

// ---- release selection -------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TagKind {
    Hour(u32),
    EndOfDay,
}

fn parse_tag(tag: &str) -> Option<(NaiveDate, TagKind)> {
    let rest = tag.strip_prefix("cve_")?;
    let (day, kind) = rest.split_once('_')?;
    let day = NaiveDate::parse_from_str(day, "%Y-%m-%d").ok()?;
    let kind = if kind == "at_end_of_day" {
        TagKind::EndOfDay
    } else {
        let h = kind.strip_suffix("00Z")?;
        TagKind::Hour(h.parse().ok().filter(|h| *h < 24)?)
    };
    Some((day, kind))
}

/// One delta zip to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pick {
    pub tag: String,
    pub day: NaiveDate,
    pub url: String,
}

/// Choose the zips to download: per UTC day the `end_of_day` delta, else the
/// latest hourly one; days from the cursor's day (inclusive, because deltas
/// are cumulative) to the newest day; at most `max_days` of them (newest kept).
/// Without a cursor only the newest day is taken.
pub fn select_downloads(
    releases: &[Release],
    cursor_tag: Option<&str>,
    max_days: usize,
) -> Vec<Pick> {
    use std::collections::BTreeMap;
    let mut best: BTreeMap<NaiveDate, (TagKind, Pick)> = BTreeMap::new();
    for r in releases.iter().filter(|r| !r.draft) {
        let Some((day, kind)) = parse_tag(&r.tag_name) else {
            continue;
        };
        let Some(asset) = r
            .assets
            .iter()
            .find(|a| a.name.contains("delta_CVEs") && a.name.ends_with(".zip"))
        else {
            continue;
        };
        let pick = Pick {
            tag: r.tag_name.clone(),
            day,
            url: asset.browser_download_url.clone(),
        };
        match best.get(&day) {
            Some((k, _)) if *k >= kind => {}
            _ => {
                best.insert(day, (kind, pick));
            }
        }
    }
    let cursor_day = cursor_tag.and_then(parse_tag).map(|(d, _)| d);
    let mut picks: Vec<Pick> = best.into_values().map(|(_, p)| p).collect();
    match cursor_day {
        Some(cd) => {
            if picks.first().is_some_and(|p| p.day > cd) {
                tracing::warn!(
                    cursor_day = %cd,
                    oldest_available = %picks[0].day,
                    "cvelist: cursor is older than the fetched release window; the gap is not back-filled"
                );
            }
            picks.retain(|p| p.day >= cd);
        }
        None => {
            if picks.len() > 1 {
                picks.drain(..picks.len() - 1);
            }
            tracing::info!(
                "cvelist: no cursor, starting from the newest day only (no baseline back-fill)"
            );
        }
    }
    if picks.len() > max_days {
        tracing::warn!(
            wanted = picks.len(),
            cap = max_days,
            "cvelist: catch-up capped; older days are skipped"
        );
        picks.drain(..picks.len() - max_days);
    }
    picks.retain(|p| Some(p.tag.as_str()) != cursor_tag);
    picks
}

// ---- record parsing ----------------------------------------------------------

fn s(v: &Value) -> Option<String> {
    v.as_str()
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_owned)
}

fn version_rank(v: &str) -> u32 {
    match v {
        "4.0" => 4,
        "3.1" => 3,
        "3.0" => 2,
        _ => 1,
    }
}

/// All CVSS metrics in a container's `metrics[]`.
fn container_cvss(container: &Value, source: CvssSource) -> Vec<Cvss> {
    let mut out = Vec::new();
    let Some(metrics) = container.get("metrics").and_then(Value::as_array) else {
        return out;
    };
    for m in metrics {
        for (key, default_version) in [
            ("cvssV4_0", "4.0"),
            ("cvssV3_1", "3.1"),
            ("cvssV3_0", "3.0"),
            ("cvssV2_0", "2.0"),
        ] {
            let Some(d) = m.get(key) else { continue };
            let Some(score) = d.get("baseScore").and_then(Value::as_f64) else {
                continue;
            };
            out.push(Cvss {
                score,
                vector: d.get("vectorString").and_then(s),
                version: d
                    .get("version")
                    .and_then(Value::as_str)
                    .unwrap_or(default_version)
                    .to_owned(),
                source,
                primary: false,
            });
        }
    }
    out
}

fn best_cvss(list: &[Cvss]) -> Option<Cvss> {
    list.iter()
        .max_by_key(|c| version_rank(&c.version))
        .cloned()
}

/// Affected entries of a container as rows (one per CPE when CPEs are given).
fn container_affected(container: &Value, source: CvssSource) -> Vec<Affected> {
    let mut rows = Vec::new();
    for a in container
        .get("affected")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let vendor = a.get("vendor").and_then(s);
        let product = a
            .get("product")
            .and_then(s)
            .or_else(|| a.get("packageName").and_then(s));
        let versions = a
            .get("versions")
            .cloned()
            .unwrap_or_else(|| Value::Array(vec![]));
        let cpes: Vec<String> = a
            .get("cpes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(s)
            .collect();
        if cpes.is_empty() {
            if vendor.is_some() || product.is_some() {
                rows.push(Affected {
                    source,
                    vendor,
                    product,
                    cpe: None,
                    versions,
                });
            }
        } else {
            for cpe in cpes {
                rows.push(Affected {
                    source,
                    vendor: vendor.clone(),
                    product: product.clone(),
                    cpe: Some(cpe),
                    versions: versions.clone(),
                });
            }
        }
    }
    // CVE 5.2 `cpeApplicability`: nodes[].cpeMatch[] with optional ranges.
    for conf in container
        .get("cpeApplicability")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for node in conf
            .get("nodes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if node.get("negate").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            for m in node
                .get("cpeMatch")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if m.get("vulnerable").and_then(Value::as_bool) == Some(false) {
                    continue;
                }
                let Some(cpe) = m.get("criteria").and_then(s) else {
                    continue;
                };
                let mut range = serde_json::Map::new();
                for k in [
                    "versionStartIncluding",
                    "versionStartExcluding",
                    "versionEndIncluding",
                    "versionEndExcluding",
                ] {
                    if let Some(v) = m.get(k).and_then(s) {
                        range.insert(k.into(), Value::String(v));
                    }
                }
                let versions = if range.is_empty() {
                    Value::Array(vec![])
                } else {
                    Value::Array(vec![Value::Object(range)])
                };
                let row = Affected {
                    source,
                    vendor: None,
                    product: None,
                    cpe: Some(cpe),
                    versions,
                };
                if !rows.contains(&row) {
                    rows.push(row);
                }
            }
        }
    }
    rows
}

fn looks_like_version(v: &str) -> bool {
    let v = v.trim();
    !v.is_empty()
        && !v.contains('*')
        && !matches!(
            v.to_ascii_lowercase().as_str(),
            "n/a" | "unspecified" | "unknown" | "0" | "-"
        )
}

/// "Likely fixed in" versions from CNA `affected[].versions[]` (research 2.).
fn fixed_versions(cna: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |v: Option<&str>| {
        if let Some(v) = v.filter(|v| looks_like_version(v))
            && !out.iter().any(|o| o == v)
        {
            out.push(v.trim().to_owned());
        }
    };
    for a in cna
        .get("affected")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for v in a
            .get("versions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if v.get("versionType").and_then(Value::as_str) == Some("git") {
                continue;
            }
            let status = v.get("status").and_then(Value::as_str).unwrap_or("");
            match status {
                "affected" => push(v.get("lessThan").and_then(Value::as_str)),
                "unaffected" => {
                    if v.get("lessThan").is_none() && v.get("lessThanOrEqual").is_none() {
                        push(v.get("version").and_then(Value::as_str));
                    }
                }
                _ => {}
            }
            for c in v
                .get("changes")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if c.get("status").and_then(Value::as_str) == Some("unaffected") {
                    push(c.get("at").and_then(Value::as_str));
                }
            }
        }
    }
    out
}

fn en_text(list: Option<&Value>) -> Option<String> {
    let arr = list?.as_array()?;
    let pick = arr
        .iter()
        .find(|d| d.get("lang").and_then(Value::as_str) == Some("en"))
        .or_else(|| {
            arr.iter().find(|d| {
                d.get("lang")
                    .and_then(Value::as_str)
                    .is_some_and(|l| l.to_ascii_lowercase().starts_with("en"))
            })
        })
        .or(arr.first())?;
    pick.get("value").and_then(s)
}

fn parse_ssvc(adp: &Value, ssvc: &mut Ssvc, kev: &mut Option<String>) {
    for m in adp
        .get("metrics")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(other) = m.get("other") else {
            continue;
        };
        let content = other.get("content");
        match other.get("type").and_then(Value::as_str) {
            Some("ssvc") if ssvc.exploitation.is_none() => {
                let Some(c) = content else { continue };
                ssvc.timestamp = c.get("timestamp").and_then(s);
                for opt in c
                    .get("options")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let Some(obj) = opt.as_object() else { continue };
                    for (k, v) in obj {
                        let val = v.as_str().map(|x| x.trim().to_ascii_lowercase());
                        match k.to_ascii_lowercase().replace(' ', "").as_str() {
                            "exploitation" => ssvc.exploitation = val,
                            "automatable" => ssvc.automatable = val,
                            "technicalimpact" => ssvc.technical_impact = val,
                            _ => {}
                        }
                    }
                }
            }
            Some("kev") if kev.is_none() => {
                *kev = content.and_then(|c| c.get("dateAdded")).and_then(s);
            }
            _ => {}
        }
    }
}

/// Parse one CVE JSON 5.x record.
pub fn parse_record(bytes: &[u8]) -> Result<CvelistUpsert> {
    let v: Value = serde_json::from_slice(bytes).context("invalid JSON")?;
    let meta = v.get("cveMetadata").context("missing cveMetadata")?;
    let cve_id = meta
        .get("cveId")
        .and_then(s)
        .context("missing cveMetadata.cveId")?;
    let date_updated = meta
        .get("dateUpdated")
        .and_then(s)
        .or_else(|| meta.get("datePublished").and_then(s))
        .map(|d| normalize_ts(&d))
        .context("missing cveMetadata.dateUpdated")?;
    let empty = Value::Null;
    let containers = v.get("containers").unwrap_or(&empty);
    let cna = containers.get("cna").unwrap_or(&empty);
    let adps: Vec<&Value> = containers
        .get("adp")
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default();

    let description = en_text(cna.get("descriptions"))
        .or_else(|| en_text(cna.get("rejectedReasons")))
        .unwrap_or_default();

    let cna_scores = container_cvss(cna, CvssSource::Cna);
    let mut adp_scores = Vec::new();
    let mut ssvc = Ssvc::default();
    let mut adp_kev_date = None;
    let mut affected = container_affected(cna, CvssSource::Cna);
    for a in &adps {
        adp_scores.extend(container_cvss(a, CvssSource::Adp));
        parse_ssvc(a, &mut ssvc, &mut adp_kev_date);
        affected.extend(container_affected(a, CvssSource::Adp));
    }

    let mut references: Vec<String> = Vec::new();
    for r in cna
        .get("references")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(u) = r.get("url").and_then(s)
            && !references.contains(&u)
        {
            references.push(u);
        }
    }

    let mut cvss_all = cna_scores.clone();
    cvss_all.extend(adp_scores.iter().cloned());
    Ok(CvelistUpsert {
        cve_id,
        state: meta
            .get("state")
            .and_then(s)
            .unwrap_or_else(|| "PUBLISHED".into()),
        assigner: meta.get("assignerShortName").and_then(s),
        description,
        published: meta
            .get("datePublished")
            .and_then(s)
            .map(|d| normalize_ts(&d)),
        date_updated,
        cna_cvss: best_cvss(&cna_scores),
        adp_cvss: best_cvss(&adp_scores),
        cvss_all,
        ssvc,
        adp_kev_date,
        affected,
        fixed_versions: fixed_versions(cna),
        references,
    })
}

// ---- applying a zip ------------------------------------------------------------

/// Largest single JSON entry accepted from a zip (zip-bomb guard).
const MAX_ENTRY_BYTES: u64 = 20 * 1024 * 1024;
/// Most entries accepted in one zip (the full cvelistV5 delta is far smaller).
const MAX_ZIP_ENTRIES: usize = 100_000;

#[derive(Debug, Default)]
struct ApplyStats {
    out: SyncOutcome,
    max_date_updated: Option<String>,
    parse_errors: usize,
    /// Records skipped because their `dateUpdated` is not a valid timestamp.
    bad_timestamps: usize,
}

fn apply_zip(conn: &mut Connection, zip_bytes: &[u8]) -> DbResult<ApplyStats> {
    let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "zip has {} entries (limit {MAX_ZIP_ENTRIES})",
                archive.len()
            ),
        )
        .into());
    }
    let tx = conn.transaction()?;
    let mut st = ApplyStats::default();
    let mut buf = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let name = entry.name().map(|n| n.into_owned()).unwrap_or_default();
        let file = name.rsplit('/').next().unwrap_or(&name);
        if !entry.is_file() || !file.starts_with("CVE-") || !file.ends_with(".json") {
            continue;
        }
        if entry.size() > MAX_ENTRY_BYTES {
            tracing::warn!(%name, size = entry.size(), "cvelist: oversized entry skipped");
            st.parse_errors += 1;
            continue;
        }
        buf.clear();
        entry.by_ref().take(MAX_ENTRY_BYTES).read_to_end(&mut buf)?;
        let rec = match parse_record(&buf) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(%name, error = %e, "cvelist: unparseable record skipped");
                st.parse_errors += 1;
                continue;
            }
        };
        match upsert_cvelist(&tx, &rec)? {
            UpsertResult::Skipped => st.out.skipped += 1,
            UpsertResult::Rejected => {
                st.out.skipped += 1;
                st.bad_timestamps += 1;
            }
            r => {
                st.out.changed += 1;
                st.out.changed_ids.push(rec.cve_id.clone());
                if r == UpsertResult::Inserted {
                    st.out.new_ids.push(rec.cve_id.clone());
                }
                if st
                    .max_date_updated
                    .as_deref()
                    .is_none_or(|m| m < rec.date_updated.as_str())
                {
                    st.max_date_updated = Some(rec.date_updated.clone());
                }
            }
        }
    }
    tx.commit()?;
    if st.bad_timestamps > 0 {
        tracing::warn!(
            records = st.bad_timestamps,
            "cvelist: records skipped because dateUpdated is not a valid timestamp"
        );
    }
    Ok(st)
}

// ---- network -----------------------------------------------------------------------

impl CvelistSource {
    async fn list_releases(
        &self,
        client: &reqwest::Client,
        cursor_tag: Option<&str>,
    ) -> Result<Vec<Release>> {
        let cursor_day = cursor_tag.and_then(parse_tag).map(|(d, _)| d);
        let mut all: Vec<Release> = Vec::new();
        for page in 1..=self.max_pages {
            let url = format!(
                "{}/repos/{}/releases?per_page=100&page={page}",
                self.api_base.trim_end_matches('/'),
                self.repo
            );
            let mut req = client
                .get(&url)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28");
            if let Some(t) = &self.github_token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await.with_context(|| format!("GET {url}"))?;
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                bail!(
                    "GET {url}: {status}: {}",
                    body.chars().take(200).collect::<String>()
                );
            }
            let batch: Vec<Release> = resp.json().await.context("decoding releases")?;
            let n = batch.len();
            all.extend(batch);
            let oldest = all
                .iter()
                .filter_map(|r| parse_tag(&r.tag_name))
                .map(|(d, _)| d)
                .min();
            let days: std::collections::BTreeSet<_> = all
                .iter()
                .filter_map(|r| parse_tag(&r.tag_name))
                .map(|(d, _)| d)
                .collect();
            let enough = match cursor_day {
                Some(cd) => oldest.is_some_and(|o| o <= cd),
                None => true,
            } || days.len() > self.max_catchup_days;
            if n < 100 || enough {
                break;
            }
        }
        Ok(all)
    }

    async fn download(&self, client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
        let resp = client
            .get(url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?
            .error_for_status()
            .with_context(|| format!("GET {url}"))?;
        super::read_body_capped(resp, url, super::MAX_ZIP_BYTES).await
    }

    async fn run(&self, ctx: &SourceContext) -> Result<SyncOutcome> {
        let (mut cursor, _): (CvelistCursor, _) = ctx.db.call(|c| load_cursor(c, SOURCE)).await?;
        let releases = self
            .list_releases(&ctx.http, cursor.last_delta_tag.as_deref())
            .await?;
        let picks = select_downloads(
            &releases,
            cursor.last_delta_tag.as_deref(),
            self.max_catchup_days,
        );
        let mut total = SyncOutcome::default();
        for pick in picks {
            let bytes = self.download(&ctx.http, &pick.url).await?;
            let size = bytes.len();
            let started = std::time::Instant::now();
            let stats = ctx
                .db
                .call(move |c| apply_zip(c, &bytes))
                .await
                .with_context(|| format!("applying {}", pick.tag))?;
            tracing::info!(
                tag = %pick.tag,
                zip_bytes = size,
                changed = stats.out.changed,
                skipped = stats.out.skipped,
                parse_errors = stats.parse_errors,
                ms = started.elapsed().as_millis() as u64,
                "cvelist: delta applied"
            );
            cursor.last_delta_tag = Some(pick.tag.clone());
            if let Some(m) = stats.max_date_updated
                && cursor
                    .max_date_updated
                    .as_deref()
                    .is_none_or(|c| c < m.as_str())
            {
                cursor.max_date_updated = Some(m);
            }
            let json = serde_json::to_string(&cursor)?;
            ctx.db.call(move |c| save_cursor(c, SOURCE, &json)).await?;
            total.changed += stats.out.changed;
            total.skipped += stats.out.skipped;
            total.changed_ids.extend(stats.out.changed_ids);
            total.new_ids.extend(stats.out.new_ids);
        }
        let json = serde_json::to_string(&cursor)?;
        ctx.db
            .call(move |c| repo::mark_success(c, SOURCE, Some(&json), None))
            .await?;
        Ok(total)
    }
}

impl Source for CvelistSource {
    fn name(&self) -> &'static str {
        SOURCE
    }

    async fn sync(&self, ctx: &SourceContext) -> Result<SyncOutcome> {
        tracked(ctx, SOURCE, self.run(ctx)).await
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::db::Db;
    use crate::monitors::cve::sources::testutil::{Canned, ctx, fixture, serve};

    const IDS: [&str; 6] = [
        "CVE-2012-20008",
        "CVE-2024-10441",
        "CVE-2026-123146",
        "CVE-2026-123637",
        "CVE-2025-48042",
        "CVE-2026-110513",
    ];

    fn make_zip(ids: &[&str]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        for id in ids {
            w.start_file(format!("deltaCves/{id}.json"), opts).unwrap();
            w.write_all(&fixture(&format!("cvelist/{id}.json")))
                .unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn rec(id: &str) -> CvelistUpsert {
        parse_record(&fixture(&format!("cvelist/{id}.json"))).unwrap()
    }

    #[test]
    fn parses_cna_cvss_ssvc_kev_and_ranges() {
        let r = rec("CVE-2024-10441");
        assert_eq!(r.state, "PUBLISHED");
        assert_eq!(r.assigner.as_deref(), Some("synology"));
        assert_eq!(r.ssvc.exploitation.as_deref(), Some("active"));
        assert_eq!(r.ssvc.automatable.as_deref(), Some("yes"));
        assert_eq!(r.ssvc.technical_impact.as_deref(), Some("total"));
        assert_eq!(r.adp_kev_date.as_deref(), Some("2026-11-18"));
        assert!(r.fixed_versions.contains(&"7.2.2-72806-1".to_owned()));
        assert!(r.affected.iter().all(|a| a.source != CvssSource::Nvd));
        assert!(r.date_updated.ends_with('Z'));

        let v = rec("CVE-2012-20008");
        let c = v.cna_cvss.as_ref().expect("cna cvss");
        assert_eq!(c.version, "4.0");
        assert_eq!(c.source, CvssSource::Cna);
        assert_eq!(v.ssvc.exploitation.as_deref(), Some("poc"));
        let cpe_row = v.affected.iter().find(|a| a.cpe.is_some()).unwrap();
        assert!(cpe_row.cpe.as_deref().unwrap().contains("opensis"));
        assert_eq!(
            cpe_row.versions.to_string(),
            "[{\"versionEndExcluding\":\"9.0\",\"versionStartIncluding\":\"5.1\"}]"
        );
    }

    #[test]
    fn parses_rejected_changes_and_cpes() {
        let r = rec("CVE-2026-123146");
        assert_eq!(r.state, "REJECTED");
        assert_eq!(r.description, "Inline mitigations exists.");
        assert!(r.affected.is_empty());

        // `changes[].at` with status unaffected counts as a fix; "*" lessThan does not.
        let b = rec("CVE-2026-123637");
        assert!(
            b.fixed_versions
                .iter()
                .any(|v| v.starts_with("BIGIP-17.1.3.7"))
        );
        assert!(!b.fixed_versions.iter().any(|v| v.contains('*')));

        let e = rec("CVE-2025-48042");
        assert!(
            e.affected
                .iter()
                .any(|a| a.cpe.as_deref().is_some_and(|c| c.contains("ash-project")))
        );
    }

    #[test]
    fn adp_cvss_is_stored_separately() {
        let r = rec("CVE-2026-110513");
        assert!(r.adp_cvss.is_some(), "ADP cvssV3_1 expected");
        assert_eq!(r.adp_cvss.as_ref().unwrap().source, CvssSource::Adp);
        assert!(r.cvss_all.iter().any(|c| c.source == CvssSource::Adp));
    }

    #[test]
    fn upsert_skips_not_newer_and_updates_newer() {
        let db = Db::open_in_memory().unwrap();
        db.with_conn(|c| {
            let mut r = rec("CVE-2024-10441");
            assert_eq!(upsert_cvelist(c, &r)?, UpsertResult::Inserted);
            assert_eq!(upsert_cvelist(c, &r)?, UpsertResult::Skipped);
            r.date_updated = "2099-01-01T00:00:00.000Z".into();
            r.description = "changed".into();
            assert_eq!(upsert_cvelist(c, &r)?, UpsertResult::Updated);
            let (d, lm, n): (String, String, i64) = c.query_row(
                "SELECT description, last_modified, (SELECT count(*) FROM cve_affected WHERE cve_id = cves.cve_id) FROM cves",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            assert_eq!(d, "changed");
            assert_eq!(lm, "2099-01-01T00:00:00.000Z");
            assert!(n >= 2, "affected rows replaced, not duplicated: {n}");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn unparseable_timestamp_is_rejected_not_stored() {
        let db = Db::open_in_memory().unwrap();
        db.with_conn(|c| {
            let mut r = rec("CVE-2024-10441");
            r.date_updated = "zzzz-not-a-date".into();
            assert_eq!(upsert_cvelist(c, &r)?, UpsertResult::Rejected);
            let n: i64 = c.query_row("SELECT count(*) FROM cves", [], |row| row.get(0))?;
            assert_eq!(n, 0, "nothing stored for a bad timestamp");
            // a good record, then a bad "newer" one: the bad one cannot freeze the row
            let good = rec("CVE-2024-10441");
            assert_eq!(upsert_cvelist(c, &good)?, UpsertResult::Inserted);
            assert_eq!(upsert_cvelist(c, &r)?, UpsertResult::Rejected);
            let mut newer = good.clone();
            newer.date_updated = "2099-01-01T00:00:00.000Z".into();
            assert_eq!(upsert_cvelist(c, &newer)?, UpsertResult::Updated);
            Ok(())
        })
        .unwrap();
    }

    fn release(tag: &str, base: &str) -> serde_json::Value {
        let day = tag.trim_start_matches("cve_").split('_').next().unwrap();
        serde_json::json!({
            "tag_name": tag, "draft": false,
            "assets": [
                {"name": format!("{day}_all_CVEs_at_midnight.zip.zip"), "browser_download_url": format!("{base}/big/{tag}")},
                {"name": format!("{day}_delta_CVEs_at_x.zip"), "browser_download_url": format!("{base}/dl/{tag}")},
            ]
        })
    }

    fn releases(base: &str, tags: &[&str]) -> Vec<Release> {
        serde_json::from_value(serde_json::Value::Array(
            tags.iter().map(|t| release(t, base)).collect(),
        ))
        .unwrap()
    }

    #[test]
    fn selection_prefers_end_of_day_and_latest_hour() {
        let rs = releases(
            "http://x",
            &[
                "cve_2026-11-19_2100Z",
                "cve_2026-11-19_2000Z",
                "cve_2026-11-18_at_end_of_day",
                "cve_2026-11-18_2300Z",
                "cve_2026-11-17_2300Z",
                "cve_2026-11-16_at_end_of_day",
                "not_a_tag",
            ],
        );
        let tags = |c: Option<&str>, max| {
            select_downloads(&rs, c, max)
                .into_iter()
                .map(|p| p.tag)
                .collect::<Vec<_>>()
        };
        // No cursor: newest day only.
        assert_eq!(tags(None, 7), ["cve_2026-11-19_2100Z"]);
        // Cursor mid-way on the 17th: its day is re-read (cumulative) through today.
        assert_eq!(
            tags(Some("cve_2026-11-17_1000Z"), 7),
            [
                "cve_2026-11-17_2300Z",
                "cve_2026-11-18_at_end_of_day",
                "cve_2026-11-19_2100Z"
            ]
        );
        // Already at the newest hour: nothing to do.
        assert!(tags(Some("cve_2026-11-19_2100Z"), 7).is_empty());
        // Cap keeps the newest days.
        assert_eq!(
            tags(Some("cve_2026-11-16_0100Z"), 2),
            ["cve_2026-11-18_at_end_of_day", "cve_2026-11-19_2100Z"]
        );
    }

    #[tokio::test]
    async fn sync_downloads_applies_and_advances_cursor() {
        let zip = make_zip(&IDS);
        let server = serve(move |req, _| {
            let p = req.path_and_query.as_str();
            if p.starts_with("/repos/CVEProject/cvelistV5/releases") {
                let host = req.headers.get("host").unwrap().to_str().unwrap();
                Canned::ok(
                    serde_json::to_vec(&vec![release(
                        "cve_2026-11-19_2100Z",
                        &format!("http://{host}"),
                    )])
                    .unwrap(),
                )
            } else if p == "/dl/cve_2026-11-19_2100Z" {
                Canned::ok(zip.clone())
            } else {
                Canned::status(404)
            }
        })
        .await;
        let src = CvelistSource {
            api_base: server.base.clone(),
            repo: REPO.into(),
            github_token: None,
            max_catchup_days: 3,
            max_pages: 2,
        };
        let ctx = ctx();
        let out = src.sync(&ctx).await.unwrap();
        assert_eq!(out.changed, IDS.len());
        assert_eq!(out.new_ids.len(), IDS.len());
        let (n, rejected): (i64, i64) = ctx
            .db
            .with_conn(|c| {
                Ok((
                    c.query_row("SELECT count(*) FROM cves", [], |r| r.get(0))?,
                    c.query_row(
                        "SELECT count(*) FROM cves WHERE state='REJECTED'",
                        [],
                        |r| r.get(0),
                    )?,
                ))
            })
            .unwrap();
        assert_eq!((n, rejected), (IDS.len() as i64, 1));
        let st = ctx
            .db
            .with_conn(|c| Ok(repo::get_source_status(c, SOURCE)?.unwrap()))
            .unwrap();
        assert!(st.last_success.is_some() && st.last_error.is_none());
        let cur: CvelistCursor = serde_json::from_str(st.cursor.as_deref().unwrap()).unwrap();
        assert_eq!(cur.last_delta_tag.as_deref(), Some("cve_2026-11-19_2100Z"));
        assert!(cur.max_date_updated.is_some());

        // Same tag again: no zip download, nothing changes.
        let hits_before = server.hits();
        let out2 = src.sync(&ctx).await.unwrap();
        assert_eq!(out2.changed, 0);
        assert_eq!(
            server.hits(),
            hits_before + 1,
            "only the release listing is fetched"
        );
    }

    #[tokio::test]
    async fn api_failure_is_recorded_and_cursor_kept() {
        let server = serve(|_, _| Canned::status(403)).await;
        let src = CvelistSource {
            api_base: server.base.clone(),
            repo: REPO.into(),
            github_token: None,
            max_catchup_days: 3,
            max_pages: 1,
        };
        let ctx = ctx();
        assert!(src.sync(&ctx).await.is_err());
        let st = ctx
            .db
            .with_conn(|c| Ok(repo::get_source_status(c, SOURCE)?.unwrap()))
            .unwrap();
        assert!(st.last_error.unwrap().contains("403"));
        assert!(st.last_success.is_none());
    }

    /// Live: real GitHub release listing + newest delta zip (about 5 MB).
    #[tokio::test]
    #[ignore = "hits the real GitHub API"]
    async fn live_cvelist_sync() {
        let ctx = ctx();
        let t = std::time::Instant::now();
        let out = CvelistSource::default().sync(&ctx).await.unwrap();
        let n: i64 = ctx
            .db
            .with_conn(|c| Ok(c.query_row("SELECT count(*) FROM cves", [], |r| r.get(0))?))
            .unwrap();
        let aff: i64 = ctx
            .db
            .with_conn(|c| Ok(c.query_row("SELECT count(*) FROM cve_affected", [], |r| r.get(0))?))
            .unwrap();
        println!(
            "LIVE cvelist: changed={} skipped={} cves={n} affected_rows={aff} in {:?}",
            out.changed,
            out.skipped,
            t.elapsed()
        );
        assert!(out.changed > 0);
    }
}
