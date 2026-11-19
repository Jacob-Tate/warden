//! The agent-facing "what's new" view.
//!
//! # Semantics
//!
//! A *delivered* row records what a consumer has seen for a `(cve, product)` pair together
//! with a snapshot of the chosen CVSS, the KEV flag and the CVE state. [`get_new`] only
//! records a *pending* snapshot (`pending_*` columns: what it just showed) and never
//! hides anything; [`ack`] promotes the pending snapshot to the acked one (falling back to
//! the current state when nothing was delivered), so a change that lands between the get
//! and the ack is surfaced again instead of being swallowed.
//!
//! For each matched `(cve, product)` and consumer:
//!
//! * **No acked row** -> `new`, subject to the backfill policy below. Rejected
//!   CVEs are hidden.
//! * **Acked row** -> hidden, unless since the snapshot the CVE
//!   * entered KEV (`kev_added`),
//!   * its chosen CVSS moved by >= 1.0 or crossed a severity band, or got its
//!     first score (`cvss_changed`), or
//!   * was REJECTED (`rejected`, surfaced once; the ack then records the state).
//!
//! # Backfill policy (newly tracked products)
//!
//! Matching a new product against the stored CVEs must not flood the agent with
//! old news. A matched CVE without an acked row is eligible only if
//! `published >= product.created_at - backfill_days` (default 14, env
//! `WARDEN_BACKFILL_DAYS`), or it was added to KEV (`kev.date_added`) within that
//! window. Items published before `product.created_at` get `change = backfill`;
//! items eligible only through KEV get `kev_added`; items published after the
//! product was added are plain `new`. Everything else stays hidden.
//!
//! # CVSS choice
//!
//! NVD Primary (nvd@nist.gov) > CNA > CISA-ADP > NVD Secondary. Each source's
//! own best version (4.0 > 3.1 > 3.0 > 2.0) is stored by the sync; severity is
//! derived from the score (>= 9 critical, >= 7 high, >= 4 medium, > 0 low).

use std::cmp::Ordering;
use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use super::sources::{SourceContext, nvd_api::NvdApi};
use crate::db::{Db, DbResult, cve_repo::normalize_ts, match_repo, repo};
use crate::model::{Change, Cvss, CvssSource, FeedEnvelope, FeedItem, SourceHealth, now_rfc3339};

pub const DEFAULT_LIMIT: usize = 50;
pub const MAX_LIMIT: usize = 200;
pub const DEFAULT_BACKFILL_DAYS: i64 = 14;

/// Sources shown in `health`, with the age after which each counts as stale.
const STALE_AFTER_HOURS: &[(&str, i64)] =
    &[("cvelist", 3), ("nvd_feed", 26), ("kev", 26), ("epss", 50)];
/// Sources whose staleness marks the whole feed stale.
const CORE_SOURCES: &[&str] = &["cvelist", "kev"];

#[derive(Debug, Clone)]
pub struct FeedOptions {
    /// Items returned at most (clamped to 1..=200).
    pub limit: usize,
    /// Only this tracked product (id or display name, case-insensitive).
    pub product: Option<String>,
    pub min_cvss: Option<f64>,
    /// Also list acked, unchanged items (reported as `change = new`).
    pub include_acked: bool,
    pub backfill_days: i64,
}

impl Default for FeedOptions {
    fn default() -> Self {
        Self {
            limit: DEFAULT_LIMIT,
            product: None,
            min_cvss: None,
            include_acked: false,
            backfill_days: DEFAULT_BACKFILL_DAYS,
        }
    }
}

// ---- pure helpers ---------------------------------------------------------------

/// Pick the displayed score: NVD Primary > CNA > ADP > NVD Secondary.
pub fn choose_cvss(
    cna: Option<f64>,
    adp: Option<f64>,
    nvd: Option<f64>,
    nvd_primary: bool,
) -> Option<(f64, CvssSource)> {
    match (nvd, nvd_primary, cna, adp) {
        (Some(n), true, _, _) => Some((n, CvssSource::Nvd)),
        (_, _, Some(c), _) => Some((c, CvssSource::Cna)),
        (_, _, None, Some(a)) => Some((a, CvssSource::Adp)),
        (Some(n), false, None, None) => Some((n, CvssSource::Nvd)),
        _ => None,
    }
}

/// Qualitative severity from a CVSS base score (same bands for v3.x and v4).
pub fn severity(score: f64) -> &'static str {
    if score >= 9.0 {
        "critical"
    } else if score >= 7.0 {
        "high"
    } else if score >= 4.0 {
        "medium"
    } else if score > 0.0 {
        "low"
    } else {
        "none"
    }
}

/// Description cut to at most 200 characters (including the ellipsis) at a word boundary.
pub fn summarize(description: &str) -> String {
    const MAX: usize = 200;
    let text = description.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() <= MAX {
        return text;
    }
    let head: String = text.chars().take(MAX - 1).collect();
    let next_is_space = text.chars().nth(MAX - 1).is_some_and(char::is_whitespace);
    let cut = if next_is_space {
        head.as_str()
    } else {
        head.rsplit_once(' ').map_or(head.as_str(), |(h, _)| h)
    };
    format!("{}…", cut.trim_end_matches(|c: char| !c.is_alphanumeric()))
}

fn cvss_moved(old: Option<f64>, new: Option<f64>) -> bool {
    match (old, new) {
        (Some(a), Some(b)) => (a - b).abs() >= 1.0 || severity(a) != severity(b),
        (None, Some(_)) => true,
        _ => false,
    }
}

fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&normalize_ts(s))
        .ok()
        .map(|d| d.with_timezone(&Utc))
        .or_else(|| {
            NaiveDate::parse_from_str(s.get(..10)?, "%Y-%m-%d")
                .ok()
                .map(|d| d.and_hms_opt(0, 0, 0).expect("midnight").and_utc())
        })
}

// ---- row loading ------------------------------------------------------------------

/// One `(cve, product)` pair with everything needed to classify and render it.
#[derive(Debug, Clone)]
struct Row {
    cve_id: String,
    product_id: String,
    product_name: String,
    product_created: String,
    state: String,
    published: Option<String>,
    first_seen: String,
    description: String,
    fixed_versions: Vec<String>,
    cvss: Option<(f64, CvssSource)>,
    kev: bool,
    kev_date: Option<String>,
    epss: Option<f64>,
    matched: bool,
    acked: bool,
    snap_cvss: Option<f64>,
    snap_kev: bool,
    snap_state: Option<String>,
    /// The state `get_new` last showed this consumer (not yet acked), if any.
    pending: Option<Snapshot>,
}

#[derive(Debug, Clone, PartialEq)]
struct Snapshot {
    cvss: Option<f64>,
    kev: bool,
    state: String,
}

impl Row {
    /// The state as it is right now.
    fn current(&self) -> Snapshot {
        Snapshot {
            cvss: self.cvss.map(|c| c.0),
            kev: self.kev,
            state: self.state.clone(),
        }
    }

    fn rejected(&self) -> bool {
        self.state.eq_ignore_ascii_case("REJECTED")
    }
}

/// Matched pairs plus pairs this consumer already acked (so REJECTED CVEs, whose
/// matches the matcher drops, can still be reported once).
fn load_rows(conn: &Connection, consumer: &str) -> DbResult<Vec<Row>> {
    let mut st = conn.prepare(
        "WITH pairs AS ( \
             SELECT cve_id, product_id FROM cve_product_matches \
             UNION \
             SELECT cve_id, product_id FROM delivered WHERE consumer = ?1 AND acked_at IS NOT NULL \
         ) \
         SELECT c.cve_id, p.id, p.name, p.created_at, c.state, c.published, c.first_seen_at, \
                c.description, c.fixed_versions, c.cna_cvss_score, c.adp_cvss_score, \
                c.nvd_cvss_score, c.nvd_cvss_primary, k.cve_id IS NOT NULL, k.date_added, e.score, \
                EXISTS (SELECT 1 FROM cve_product_matches m \
                        WHERE m.cve_id = pr.cve_id AND m.product_id = pr.product_id), \
                d.acked_at IS NOT NULL, \
                CASE WHEN d.acked_at IS NOT NULL THEN d.snapshot_cvss END, \
                CASE WHEN d.acked_at IS NOT NULL THEN d.snapshot_kev ELSE 0 END, \
                CASE WHEN d.acked_at IS NOT NULL THEN d.snapshot_state END, \
                d.pending_at IS NOT NULL, d.pending_cvss, COALESCE(d.pending_kev, 0), \
                COALESCE(d.pending_state, '') \
         FROM pairs pr \
         JOIN cves c ON c.cve_id = pr.cve_id \
         JOIN tracked_products p ON p.id = pr.product_id \
         LEFT JOIN kev k ON k.cve_id = c.cve_id \
         LEFT JOIN epss e ON e.cve_id = c.cve_id \
         LEFT JOIN delivered d ON d.consumer = ?1 AND d.cve_id = pr.cve_id \
              AND d.product_id = pr.product_id",
    )?;
    let rows = st.query_map([consumer], |r| {
        let fixed: String = r.get(8)?;
        Ok(Row {
            cve_id: r.get(0)?,
            product_id: r.get(1)?,
            product_name: r.get(2)?,
            product_created: r.get(3)?,
            state: r.get(4)?,
            published: r.get(5)?,
            first_seen: r.get(6)?,
            description: r.get(7)?,
            fixed_versions: serde_json::from_str(&fixed).unwrap_or_default(),
            cvss: choose_cvss(r.get(9)?, r.get(10)?, r.get(11)?, r.get(12)?),
            kev: r.get(13)?,
            kev_date: r.get(14)?,
            epss: r.get(15)?,
            matched: r.get(16)?,
            acked: r.get(17)?,
            snap_cvss: r.get(18)?,
            snap_kev: r.get(19)?,
            snap_state: r.get(20)?,
            pending: if r.get::<_, bool>(21)? {
                Some(Snapshot {
                    cvss: r.get(22)?,
                    kev: r.get(23)?,
                    state: r.get(24)?,
                })
            } else {
                None
            },
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Why (if at all) `r` belongs in the feed.
fn classify(r: &Row, backfill_days: i64, include_acked: bool) -> Option<Change> {
    if r.acked {
        if r.rejected() {
            let was = r
                .snap_state
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case("REJECTED"));
            return (!was).then_some(Change::Rejected);
        }
        if !r.matched {
            return None;
        }
        if r.kev && !r.snap_kev {
            return Some(Change::KevAdded);
        }
        if cvss_moved(r.snap_cvss, r.cvss.map(|c| c.0)) {
            return Some(Change::CvssChanged);
        }
        return include_acked.then_some(Change::New);
    }
    if r.rejected() || !r.matched {
        return None;
    }
    let created = parse_ts(&r.product_created)?;
    let cutoff = created - Duration::days(backfill_days);
    let published = r
        .published
        .as_deref()
        .and_then(parse_ts)
        .or_else(|| parse_ts(&r.first_seen));
    match published {
        None => Some(Change::New),
        Some(p) if p >= created => Some(Change::New),
        Some(p) if p >= cutoff => Some(Change::Backfill),
        Some(_) => r
            .kev_date
            .as_deref()
            .and_then(parse_ts)
            .filter(|d| *d >= cutoff)
            .map(|_| Change::KevAdded),
    }
}

fn to_item(r: &Row, change: Change) -> FeedItem {
    FeedItem {
        cve: r.cve_id.clone(),
        product: r.product_name.clone(),
        published: r.published.clone(),
        cvss: r.cvss.map(|c| c.0),
        cvss_source: r.cvss.map(|c| c.1),
        severity: r.cvss.map(|c| severity(c.0).to_owned()),
        kev: r.kev,
        epss: r.epss,
        change,
        summary: summarize(&r.description),
        fixed_versions: r.fixed_versions.clone(),
        source_url: format!("https://nvd.nist.gov/vuln/detail/{}", r.cve_id),
    }
}

fn rank(a: &FeedItem, b: &FeedItem) -> Ordering {
    b.kev
        .cmp(&a.kev)
        .then_with(|| match (a.cvss, b.cvss) {
            (Some(x), Some(y)) => y.total_cmp(&x),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        })
        .then_with(|| b.published.cmp(&a.published))
        .then_with(|| a.cve.cmp(&b.cve))
        .then_with(|| a.product.cmp(&b.product))
}

/// Per-source health as of `now`.
pub fn source_health(
    conn: &Connection,
    now: DateTime<Utc>,
) -> DbResult<BTreeMap<String, SourceHealth>> {
    let mut out = BTreeMap::new();
    for (name, hours) in STALE_AFTER_HOURS {
        let st = repo::get_source_status(conn, name)?.unwrap_or_default();
        let fresh = st
            .last_success
            .as_deref()
            .and_then(parse_ts)
            .is_some_and(|t| now - t <= Duration::hours(*hours));
        out.insert(
            (*name).to_owned(),
            SourceHealth {
                last_success: st.last_success,
                last_error: st.last_error,
                stale: !fresh,
            },
        );
    }
    Ok(out)
}

/// Store, per returned `(cve, product)`, the state that was shown (the pending snapshot).
/// Never touches `acked_at` or the acked snapshot, so nothing is hidden by a fetch.
fn record_delivered<'a>(
    conn: &mut Connection,
    consumer: &str,
    rows: impl Iterator<Item = &'a Row>,
) -> DbResult<()> {
    let tx = conn.transaction()?;
    let now = now_rfc3339();
    {
        let mut st = tx.prepare_cached(
            "INSERT INTO delivered (consumer, cve_id, product_id, delivered_at, pending_at, \
                 pending_cvss, pending_kev, pending_state) \
             VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6, ?7) \
             ON CONFLICT(consumer, cve_id, product_id) DO UPDATE SET pending_at = excluded.pending_at, \
                 pending_cvss = excluded.pending_cvss, pending_kev = excluded.pending_kev, \
                 pending_state = excluded.pending_state",
        )?;
        for r in rows {
            let s = r.current();
            st.execute(params![
                consumer,
                r.cve_id,
                r.product_id,
                now,
                s.cvss,
                s.kev,
                s.state
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Compute the feed for `consumer`. Only bookkeeping is written (see [`record_delivered`]);
/// nothing is consumed.
pub async fn get_new(db: &Db, consumer: &str, opts: &FeedOptions) -> Result<FeedEnvelope> {
    let (consumer, opts) = (consumer.to_owned(), opts.clone());
    Ok(db
        .call(move |conn| {
            let wanted = opts.product.as_deref().map(str::to_lowercase);
            let mut items: Vec<(FeedItem, Row)> = load_rows(conn, &consumer)?
                .into_iter()
                .filter(|r| {
                    wanted.as_ref().is_none_or(|w| {
                        r.product_id.to_lowercase() == *w || r.product_name.to_lowercase() == *w
                    })
                })
                .filter(|r| {
                    opts.min_cvss
                        .is_none_or(|m| r.cvss.is_some_and(|c| c.0 >= m))
                })
                .filter_map(|r| {
                    classify(&r, opts.backfill_days, opts.include_acked)
                        .map(|c| (to_item(&r, c), r))
                })
                .collect();
            items.sort_by(|a, b| rank(&a.0, &b.0));
            let limit = opts.limit.clamp(1, MAX_LIMIT);
            let more = items.len().saturating_sub(limit);
            items.truncate(limit);
            // Remember exactly what is being handed over; best effort (without it `ack`
            // falls back to the state at ack time).
            if let Err(e) = record_delivered(conn, &consumer, items.iter().map(|(_, r)| r)) {
                tracing::warn!(error = %e, "recording delivered snapshots failed");
            }
            let items: Vec<FeedItem> = items.into_iter().map(|(i, _)| i).collect();
            let health = source_health(conn, Utc::now())?;
            let stale = CORE_SOURCES
                .iter()
                .any(|s| health.get(*s).is_none_or(|h| h.stale));
            Ok(FeedEnvelope {
                generated_at: now_rfc3339(),
                items,
                more,
                stale,
                health,
            })
        })
        .await?)
}

// ---- ack ------------------------------------------------------------------------------

fn ack_rows(conn: &mut Connection, consumer: &str, pick: impl Fn(&Row) -> bool) -> DbResult<usize> {
    let rows: Vec<Row> = load_rows(conn, consumer)?
        .into_iter()
        .filter(|r| (r.matched || r.acked) && pick(r))
        .collect();
    let tx = conn.transaction()?;
    let now = now_rfc3339();
    for r in &rows {
        // What the consumer was actually shown, else (never delivered) the state right now.
        let snap = r.pending.clone().unwrap_or_else(|| r.current());
        tx.execute(
            "INSERT INTO delivered (consumer, cve_id, product_id, delivered_at, acked_at, \
                 snapshot_cvss, snapshot_kev, snapshot_state) \
             VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6, ?7) \
             ON CONFLICT(consumer, cve_id, product_id) DO UPDATE SET acked_at = excluded.acked_at, \
                 snapshot_cvss = excluded.snapshot_cvss, snapshot_kev = excluded.snapshot_kev, \
                 snapshot_state = excluded.snapshot_state, \
                 pending_at = NULL, pending_cvss = NULL, pending_kev = NULL, pending_state = NULL",
            params![
                consumer,
                r.cve_id,
                r.product_id,
                now,
                snap.cvss,
                snap.kev,
                snap.state
            ],
        )?;
    }
    tx.commit()?;
    Ok(rows.len())
}

/// Acknowledge CVE ids for every product they match: promotes the snapshot `get_new`
/// recorded (what the consumer was shown) to the acked snapshot, or records the current
/// chosen CVSS, KEV flag and state when nothing was delivered. Returns the number of
/// `(cve, product)` rows written. Unknown ids are ignored.
pub async fn ack(db: &Db, consumer: &str, cve_ids: &[String]) -> Result<usize> {
    let consumer = consumer.to_owned();
    let ids: Vec<String> = cve_ids.iter().map(|c| c.trim().to_uppercase()).collect();
    Ok(db
        .call(move |c| ack_rows(c, &consumer, |r| ids.contains(&r.cve_id)))
        .await?)
}

/// Acknowledge exactly the `(cve, product)` pairs of feed items (product by display name).
pub async fn ack_items(db: &Db, consumer: &str, items: &[FeedItem]) -> Result<usize> {
    let consumer = consumer.to_owned();
    let pairs: Vec<(String, String)> = items
        .iter()
        .map(|i| (i.cve.clone(), i.product.clone()))
        .collect();
    Ok(db
        .call(move |c| {
            ack_rows(c, &consumer, |r| {
                pairs
                    .iter()
                    .any(|(c, p)| *c == r.cve_id && *p == r.product_name)
            })
        })
        .await?)
}

// ---- cve_detail ----------------------------------------------------------------------

fn read_detail(conn: &Connection, id: &str) -> DbResult<Option<Value>> {
    type Head = (
        String,
        Option<String>,
        String,
        Option<String>,
        String,
        Option<String>,
        String,
        [Option<f64>; 3],
        bool,
        String,
        [Option<String>; 4],
        String,
        String,
    );
    let head: Option<Head> = conn
        .query_row(
            "SELECT state, assigner, description, published, last_modified, nvd_status, \
                    first_seen_at, cna_cvss_score, adp_cvss_score, nvd_cvss_score, \
                    nvd_cvss_primary, cvss_all, ssvc_exploitation, ssvc_automatable, \
                    ssvc_tech_impact, ssvc_timestamp, fixed_versions, refs \
             FROM cves WHERE cve_id = ?1",
            [id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    [r.get(7)?, r.get(8)?, r.get(9)?],
                    r.get(10)?,
                    r.get(11)?,
                    [r.get(12)?, r.get(13)?, r.get(14)?, r.get(15)?],
                    r.get(16)?,
                    r.get(17)?,
                ))
            },
        )
        .optional()?;
    let Some((
        state,
        assigner,
        description,
        published,
        last_modified,
        nvd_status,
        first_seen,
        [cna, adp, nvd],
        primary,
        cvss_all,
        [ssvc_x, ssvc_a, ssvc_t, ssvc_ts],
        fixed,
        refs,
    )) = head
    else {
        return Ok(None);
    };
    let all: Vec<Cvss> = serde_json::from_str(&cvss_all).unwrap_or_default();
    let chosen = choose_cvss(cna, adp, nvd, primary).map(
        |(score, source)| json!({"score": score, "source": source, "severity": severity(score)}),
    );
    let json_col = |s: &str| serde_json::from_str::<Value>(s).unwrap_or(Value::Null);

    let mut st = conn.prepare(
        "SELECT source, vendor_raw, product_raw, cpe, versions FROM cve_affected \
         WHERE cve_id = ?1 ORDER BY id",
    )?;
    let affected: Vec<Value> = st
        .query_map([id], |r| {
            let versions: String = r.get(4)?;
            Ok(json!({
                "source": r.get::<_, String>(0)?,
                "vendor": r.get::<_, Option<String>>(1)?,
                "product": r.get::<_, Option<String>>(2)?,
                "cpe": r.get::<_, Option<String>>(3)?,
                "versions": serde_json::from_str::<Value>(&versions).unwrap_or(Value::Null),
            }))
        })?
        .collect::<Result<_, _>>()?;

    let kev: Option<Value> = conn
        .query_row(
            "SELECT vendor_project, product, name, date_added, due_date, ransomware \
             FROM kev WHERE cve_id = ?1",
            [id],
            |r| {
                Ok(json!({
                    "vendor_project": r.get::<_, Option<String>>(0)?,
                    "product": r.get::<_, Option<String>>(1)?,
                    "name": r.get::<_, Option<String>>(2)?,
                    "date_added": r.get::<_, Option<String>>(3)?,
                    "due_date": r.get::<_, Option<String>>(4)?,
                    "ransomware": r.get::<_, bool>(5)?,
                }))
            },
        )
        .optional()?;
    let epss: Option<Value> = conn
        .query_row(
            "SELECT score, percentile, score_date FROM epss WHERE cve_id = ?1",
            [id],
            |r| {
                Ok(json!({
                    "score": r.get::<_, f64>(0)?,
                    "percentile": r.get::<_, f64>(1)?,
                    "date": r.get::<_, String>(2)?,
                }))
            },
        )
        .optional()?;
    let mut st = conn.prepare(
        "SELECT p.id, p.name, m.matched_by, m.matched_at FROM cve_product_matches m \
         JOIN tracked_products p ON p.id = m.product_id WHERE m.cve_id = ?1 ORDER BY p.id",
    )?;
    let matches: Vec<Value> = st
        .query_map([id], |r| {
            Ok(json!({
                "product_id": r.get::<_, String>(0)?,
                "product": r.get::<_, String>(1)?,
                "matched_by": r.get::<_, String>(2)?,
                "matched_at": r.get::<_, String>(3)?,
            }))
        })?
        .collect::<Result<_, _>>()?;

    Ok(Some(json!({
        "cve": id,
        "state": state,
        "assigner": assigner,
        "description": description,
        "published": published,
        "last_modified": last_modified,
        "first_seen_at": first_seen,
        "nvd_status": nvd_status,
        "cvss": {"chosen": chosen, "all": all},
        "kev": kev,
        "epss": epss,
        "ssvc": {
            "exploitation": ssvc_x,
            "automatable": ssvc_a,
            "technical_impact": ssvc_t,
            "timestamp": ssvc_ts,
        },
        "fixed_versions": json_col(&fixed),
        "references": json_col(&refs),
        "affected": affected,
        "matches": matches,
        "source_url": format!("https://nvd.nist.gov/vuln/detail/{id}"),
    })))
}

/// Full normalized record for one CVE id. Unknown locally -> NVD API lookup, stored
/// (and matched against tracked products), then returned. `None` if NVD does not
/// know the id either.
pub async fn cve_detail(ctx: &SourceContext, api: &NvdApi, cve_id: &str) -> Result<Option<Value>> {
    let id = cve_id.trim().to_uppercase();
    let valid = id.strip_prefix("CVE-").is_some_and(|rest| {
        rest.split_once('-').is_some_and(|(y, n)| {
            y.len() == 4
                && n.len() >= 4
                && y.bytes().all(|b| b.is_ascii_digit())
                && n.bytes().all(|b| b.is_ascii_digit())
        })
    });
    if !valid {
        bail!("not a CVE id: {cve_id}");
    }
    let q = id.clone();
    if let Some(v) = ctx.db.call(move |c| read_detail(c, &q)).await? {
        return Ok(Some(v));
    }
    if !api
        .lookup_and_store(ctx, &id)
        .await
        .with_context(|| format!("NVD lookup of {id}"))?
    {
        return Ok(None);
    }
    let q = id.clone();
    Ok(ctx
        .db
        .call(move |c| {
            match_repo::match_cves(c, std::slice::from_ref(&q))?;
            read_detail(c, &q)
        })
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CnaName, MatchMode, TrackedProduct};

    fn mem() -> Db {
        Db::open_in_memory().unwrap()
    }

    fn product(id: &str, created: &str) -> TrackedProduct {
        TrackedProduct {
            id: id.into(),
            name: id.to_uppercase(),
            cpes: vec![],
            cna_names: vec![CnaName {
                vendor: "Acme".into(),
                product: id.into(),
                source_cna: None,
            }],
            kev_names: vec![],
            aliases: vec![],
            keywords: vec![],
            exclude_keywords: vec![],
            match_mode: MatchMode::CpeNames,
            confirmed_by: "test".into(),
            created_at: created.into(),
            updated_at: created.into(),
        }
    }

    /// Insert a CVE matched to `widget`.
    fn cve(
        c: &Connection,
        id: &str,
        published: &str,
        cna: Option<f64>,
        nvd: Option<(f64, bool)>,
        desc: &str,
    ) {
        c.execute(
            "INSERT INTO cves (cve_id, description, published, last_modified, first_seen_at, \
                 cna_cvss_score, nvd_cvss_score, nvd_cvss_primary) \
             VALUES (?1, ?2, ?3, ?3, ?3, ?4, ?5, ?6)",
            params![
                id,
                desc,
                published,
                cna,
                nvd.map(|n| n.0),
                nvd.is_some_and(|n| n.1)
            ],
        )
        .unwrap();
        c.execute(
            "INSERT INTO cve_product_matches (cve_id, product_id, matched_by, matched_at) \
             VALUES (?1, 'widget', 'cna_name', 'x')",
            [id],
        )
        .unwrap();
    }

    fn fresh_sources(c: &Connection) {
        for s in ["cvelist", "nvd_feed", "kev", "epss"] {
            repo::mark_success(c, s, None, None).unwrap();
        }
    }

    fn setup() -> Db {
        let db = mem();
        db.with_conn(|c| {
            repo::upsert_product(c, &product("widget", "2026-11-10T00:00:00.000Z"))?;
            fresh_sources(c);
            Ok(())
        })
        .unwrap();
        db
    }

    fn opts() -> FeedOptions {
        FeedOptions::default()
    }

    #[test]
    fn summary_cuts_at_word_boundary() {
        assert_eq!(summarize("short  text\n here"), "short text here");
        let long = "word ".repeat(80);
        let s = summarize(&long);
        assert!(s.chars().count() <= 200 && s.ends_with("word…"), "{s}");
        let one = "x".repeat(300);
        assert_eq!(summarize(&one).chars().count(), 200);
    }

    #[test]
    fn cvss_precedence_and_severity() {
        use CvssSource::*;
        assert_eq!(
            choose_cvss(Some(5.0), Some(6.0), Some(9.0), true),
            Some((9.0, Nvd))
        );
        assert_eq!(
            choose_cvss(Some(5.0), Some(6.0), Some(9.0), false),
            Some((5.0, Cna))
        );
        assert_eq!(
            choose_cvss(None, Some(6.0), Some(9.0), false),
            Some((6.0, Adp))
        );
        assert_eq!(choose_cvss(None, None, Some(9.0), false), Some((9.0, Nvd)));
        assert_eq!(choose_cvss(None, None, None, false), None);
        assert_eq!(severity(9.0), "critical");
        assert_eq!(severity(8.9), "high");
        assert_eq!(severity(4.0), "medium");
        assert_eq!(severity(0.1), "low");
    }

    #[tokio::test]
    async fn new_sorting_filters_and_limit() {
        let db = setup();
        db.with_conn(|c| {
            cve(c, "CVE-2026-1001", "2026-11-12T00:00:00.000Z", Some(5.0), None, "medium");
            cve(c, "CVE-2026-1002", "2026-11-13T00:00:00.000Z", Some(9.8), None, "crit");
            cve(c, "CVE-2026-1003", "2026-11-14T00:00:00.000Z", None, None, "unrated");
            cve(c, "CVE-2026-1004", "2026-11-15T00:00:00.000Z", Some(2.0), None, "low kev");
            c.execute(
                "INSERT INTO kev (cve_id, date_added, first_seen_at) VALUES ('CVE-2026-1004', '2026-11-15', 'x')",
                [],
            )?;
            c.execute(
                "INSERT INTO epss (cve_id, score, percentile, score_date) VALUES ('CVE-2026-1002', 0.5, 0.9, 'x')",
                [],
            )?;
            Ok(())
        })
        .unwrap();
        let env = get_new(&db, "me", &opts()).await.unwrap();
        let ids: Vec<&str> = env.items.iter().map(|i| i.cve.as_str()).collect();
        assert_eq!(
            ids,
            [
                "CVE-2026-1004",
                "CVE-2026-1002",
                "CVE-2026-1001",
                "CVE-2026-1003"
            ]
        );
        assert!(!env.stale && env.more == 0);
        let top = &env.items[1];
        assert_eq!(
            (top.cvss, top.severity.as_deref(), top.epss, top.change),
            (Some(9.8), Some("critical"), Some(0.5), Change::New)
        );
        assert_eq!(top.product, "WIDGET");
        assert_eq!(
            top.source_url,
            "https://nvd.nist.gov/vuln/detail/CVE-2026-1002"
        );

        let env = get_new(&db, "me", &FeedOptions { limit: 2, ..opts() })
            .await
            .unwrap();
        assert_eq!((env.items.len(), env.more), (2, 2));
        let env = get_new(
            &db,
            "me",
            &FeedOptions {
                min_cvss: Some(5.0),
                ..opts()
            },
        )
        .await
        .unwrap();
        assert_eq!(env.items.len(), 2);
        let env = get_new(
            &db,
            "me",
            &FeedOptions {
                product: Some("widget".into()),
                ..opts()
            },
        )
        .await
        .unwrap();
        assert_eq!(env.items.len(), 4);
        let env = get_new(
            &db,
            "me",
            &FeedOptions {
                product: Some("other".into()),
                ..opts()
            },
        )
        .await
        .unwrap();
        assert!(env.items.is_empty());
    }

    #[tokio::test]
    async fn change_between_get_and_ack_is_resurfaced() {
        let db = setup();
        db.with_conn(|c| {
            cve(
                c,
                "CVE-2026-3001",
                "2026-11-12T00:00:00.000Z",
                Some(5.0),
                None,
                "a",
            );
            cve(
                c,
                "CVE-2026-3002",
                "2026-11-12T00:00:00.000Z",
                Some(7.5),
                None,
                "b",
            );
            Ok(())
        })
        .unwrap();
        let env = get_new(&db, "me", &opts()).await.unwrap();
        assert_eq!(env.items.len(), 2);
        // fetching again (pending but unacked) still lists everything: nothing consumed
        assert_eq!(get_new(&db, "me", &opts()).await.unwrap().items.len(), 2);
        // while the agent is summarizing: 3001 enters KEV, 3002's score jumps a band
        db.with_conn(|c| {
            c.execute("INSERT INTO kev (cve_id, date_added, first_seen_at) VALUES ('CVE-2026-3001', '2026-11-18', 'x')", [])?;
            c.execute("UPDATE cves SET cna_cvss_score = 9.8 WHERE cve_id = 'CVE-2026-3002'", [])?;
            Ok(())
        })
        .unwrap();
        // ack what was delivered (ids from the first get)
        let ids: Vec<String> = env.items.iter().map(|i| i.cve.clone()).collect();
        // (a consumer that re-fetched after the change would have been shown the new state;
        // here the ack is for the state it actually saw)
        let n = ack(&db, "me", &ids).await.unwrap();
        assert_eq!(n, 2);
        let after = get_new(&db, "me", &opts()).await.unwrap();
        let got: Vec<(&str, Change)> = after
            .items
            .iter()
            .map(|i| (i.cve.as_str(), i.change))
            .collect();
        assert_eq!(
            got,
            [
                ("CVE-2026-3001", Change::KevAdded),
                ("CVE-2026-3002", Change::CvssChanged)
            ],
            "changes after delivery must come back after the ack"
        );
        // acking the re-surfaced state settles it; nothing left
        let ids: Vec<String> = after.items.iter().map(|i| i.cve.clone()).collect();
        ack(&db, "me", &ids).await.unwrap();
        assert!(get_new(&db, "me", &opts()).await.unwrap().items.is_empty());
        // ack without any prior get falls back to the current state
        db.with_conn(|c| {
            cve(
                c,
                "CVE-2026-3003",
                "2026-11-12T00:00:00.000Z",
                Some(5.0),
                None,
                "c",
            );
            Ok(())
        })
        .unwrap();
        assert_eq!(
            ack(&db, "fresh", &["CVE-2026-3003".into()]).await.unwrap(),
            1
        );
        db.with_conn(|c| {
            c.execute(
                "UPDATE cves SET cna_cvss_score = 9.9 WHERE cve_id = 'CVE-2026-3003'",
                [],
            )?;
            Ok(())
        })
        .unwrap();
        // that consumer snapshotted 5.0 at ack time, so the jump shows
        let env = get_new(&db, "fresh", &opts()).await.unwrap();
        assert!(
            env.items
                .iter()
                .any(|i| i.cve == "CVE-2026-3003" && i.change == Change::CvssChanged)
        );
    }

    #[tokio::test]
    async fn pending_snapshot_tracks_the_latest_delivery_and_is_cleared_by_ack() {
        let db = setup();
        db.with_conn(|c| {
            cve(
                c,
                "CVE-2026-3101",
                "2026-11-12T00:00:00.000Z",
                Some(5.0),
                None,
                "a",
            );
            Ok(())
        })
        .unwrap();
        get_new(&db, "me", &opts()).await.unwrap();
        db.with_conn(|c| {
            c.execute(
                "UPDATE cves SET cna_cvss_score = 9.0 WHERE cve_id = 'CVE-2026-3101'",
                [],
            )?;
            Ok(())
        })
        .unwrap();
        // a second get shows (and records) the new score, so acking it is final
        let env = get_new(&db, "me", &opts()).await.unwrap();
        assert_eq!(env.items[0].cvss, Some(9.0));
        ack(&db, "me", &["CVE-2026-3101".into()]).await.unwrap();
        assert!(get_new(&db, "me", &opts()).await.unwrap().items.is_empty());
        let pending: i64 = db
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT COUNT(*) FROM delivered WHERE pending_at IS NOT NULL",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(pending, 0);
    }

    #[tokio::test]
    async fn ack_hides_and_changes_resurface() {
        let db = setup();
        db.with_conn(|c| {
            cve(
                c,
                "CVE-2026-2001",
                "2026-11-12T00:00:00.000Z",
                Some(5.0),
                None,
                "a",
            );
            cve(
                c,
                "CVE-2026-2002",
                "2026-11-12T00:00:00.000Z",
                Some(5.0),
                None,
                "b",
            );
            cve(
                c,
                "CVE-2026-2003",
                "2026-11-12T00:00:00.000Z",
                Some(7.5),
                None,
                "c",
            );
            Ok(())
        })
        .unwrap();
        // fetching does not consume
        assert_eq!(get_new(&db, "me", &opts()).await.unwrap().items.len(), 3);
        assert_eq!(get_new(&db, "me", &opts()).await.unwrap().items.len(), 3);
        let n = ack(
            &db,
            "me",
            &[
                "cve-2026-2001".into(),
                "CVE-2026-2002".into(),
                "CVE-2026-2003".into(),
                "CVE-NOPE".into(),
            ],
        )
        .await
        .unwrap();
        assert_eq!(n, 3);
        assert!(get_new(&db, "me", &opts()).await.unwrap().items.is_empty());
        // another consumer is unaffected
        assert_eq!(get_new(&db, "other", &opts()).await.unwrap().items.len(), 3);

        db.with_conn(|c| {
            // 2001: KEV; 2002: 5.0 -> 5.9 (no change); 2003: 7.5 -> 9.1 (band + >=1)
            c.execute("INSERT INTO kev (cve_id, date_added, first_seen_at) VALUES ('CVE-2026-2001', '2026-11-18', 'x')", [])?;
            c.execute("UPDATE cves SET cna_cvss_score = 5.9 WHERE cve_id = 'CVE-2026-2002'", [])?;
            c.execute("UPDATE cves SET cna_cvss_score = 9.1 WHERE cve_id = 'CVE-2026-2003'", [])?;
            Ok(())
        })
        .unwrap();
        let env = get_new(&db, "me", &opts()).await.unwrap();
        let got: Vec<(&str, Change)> = env
            .items
            .iter()
            .map(|i| (i.cve.as_str(), i.change))
            .collect();
        assert_eq!(
            got,
            [
                ("CVE-2026-2001", Change::KevAdded),
                ("CVE-2026-2003", Change::CvssChanged)
            ]
        );
        // acking again re-snapshots; feed empties
        let n = ack_items(&db, "me", &env.items).await.unwrap();
        assert_eq!(n, 2);
        assert!(get_new(&db, "me", &opts()).await.unwrap().items.is_empty());
        let all = get_new(
            &db,
            "me",
            &FeedOptions {
                include_acked: true,
                ..opts()
            },
        )
        .await
        .unwrap();
        assert_eq!(all.items.len(), 3);

        // band crossing below 1.0 delta: 5.9 -> 6.9 is >= 1.0; 3.9 -> 4.0 crosses band
        assert!(cvss_moved(Some(3.9), Some(4.0)));
        assert!(!cvss_moved(Some(5.0), Some(5.9)));
    }

    #[tokio::test]
    async fn rejected_surfaces_once_only_if_delivered() {
        let db = setup();
        db.with_conn(|c| {
            cve(
                c,
                "CVE-2026-3001",
                "2026-11-12T00:00:00.000Z",
                Some(5.0),
                None,
                "a",
            );
            cve(
                c,
                "CVE-2026-3002",
                "2026-11-12T00:00:00.000Z",
                Some(5.0),
                None,
                "b",
            );
            Ok(())
        })
        .unwrap();
        ack(&db, "me", &["CVE-2026-3001".into()]).await.unwrap();
        db.with_conn(|c| {
            // rejection: matcher drops the matches, state flips
            c.execute("UPDATE cves SET state = 'REJECTED'", [])?;
            c.execute("DELETE FROM cve_product_matches", [])?;
            Ok(())
        })
        .unwrap();
        let env = get_new(&db, "me", &opts()).await.unwrap();
        assert_eq!(env.items.len(), 1);
        assert_eq!(
            (env.items[0].cve.as_str(), env.items[0].change),
            ("CVE-2026-3001", Change::Rejected)
        );
        ack_items(&db, "me", &env.items).await.unwrap();
        assert!(get_new(&db, "me", &opts()).await.unwrap().items.is_empty());
    }

    #[tokio::test]
    async fn backfill_policy_for_new_products() {
        let db = setup(); // widget created 2026-11-10, window 14d -> cutoff 2026-10-27
        db.with_conn(|c| {
            cve(c, "CVE-2026-4001", "2026-11-12T00:00:00.000Z", Some(5.0), None, "after");
            cve(c, "CVE-2026-4002", "2026-11-01T00:00:00.000Z", Some(5.0), None, "in window");
            cve(c, "CVE-2026-4003", "2026-06-01T00:00:00.000Z", Some(9.0), None, "old");
            cve(c, "CVE-2026-4004", "2026-06-01T00:00:00.000Z", Some(9.0), None, "old kev recent");
            cve(c, "CVE-2026-4005", "2026-06-01T00:00:00.000Z", Some(9.0), None, "old kev old");
            c.execute("INSERT INTO kev (cve_id, date_added, first_seen_at) VALUES ('CVE-2026-4004', '2026-11-05', 'x')", [])?;
            c.execute("INSERT INTO kev (cve_id, date_added, first_seen_at) VALUES ('CVE-2026-4005', '2026-08-05', 'x')", [])?;
            Ok(())
        })
        .unwrap();
        let env = get_new(&db, "me", &opts()).await.unwrap();
        let got: Vec<(&str, Change)> = env
            .items
            .iter()
            .map(|i| (i.cve.as_str(), i.change))
            .collect();
        assert_eq!(
            got,
            [
                ("CVE-2026-4004", Change::KevAdded),
                ("CVE-2026-4001", Change::New),
                ("CVE-2026-4002", Change::Backfill),
            ]
        );
        let env = get_new(
            &db,
            "me",
            &FeedOptions {
                backfill_days: 0,
                ..opts()
            },
        )
        .await
        .unwrap();
        let ids: Vec<&str> = env.items.iter().map(|i| i.cve.as_str()).collect();
        assert_eq!(ids, ["CVE-2026-4001"]);
    }

    #[tokio::test]
    async fn health_and_staleness() {
        let db = mem();
        let env = get_new(&db, "me", &opts()).await.unwrap();
        assert!(env.stale, "never synced is stale");
        assert_eq!(env.health.len(), 4);
        db.with_conn(|c| {
            fresh_sources(c);
            // cvelist older than 3h
            c.execute(
                "UPDATE source_status SET last_success = ?1 WHERE source = 'cvelist'",
                [(Utc::now() - Duration::hours(4)).to_rfc3339()],
            )?;
            // epss 30h old is fine (50h), nvd_feed 30h is stale (26h) but not core
            c.execute(
                "UPDATE source_status SET last_success = ?1 WHERE source IN ('epss', 'nvd_feed')",
                [(Utc::now() - Duration::hours(30)).to_rfc3339()],
            )?;
            repo::mark_error(c, "kev", "boom")?;
            Ok(())
        })
        .unwrap();
        let env = get_new(&db, "me", &opts()).await.unwrap();
        assert!(env.stale);
        assert!(env.health["cvelist"].stale && env.health["nvd_feed"].stale);
        assert!(!env.health["epss"].stale && !env.health["kev"].stale);
        assert_eq!(env.health["kev"].last_error.as_deref(), Some("boom"));
        db.with_conn(|c| {
            fresh_sources(c);
            Ok(())
        })
        .unwrap();
        assert!(!get_new(&db, "me", &opts()).await.unwrap().stale);
    }

    #[test]
    fn detail_reads_everything() {
        let db = setup();
        db.with_conn(|c| {
            cve(c, "CVE-2026-5001", "2026-11-12T00:00:00.000Z", Some(5.0), Some((7.0, false)), "desc");
            c.execute(
                "INSERT INTO cve_affected (cve_id, source, vendor_raw, product_raw) VALUES ('CVE-2026-5001', 'cna', 'Acme', 'widget')",
                [],
            )?;
            let v = read_detail(c, "CVE-2026-5001")?.unwrap();
            assert_eq!(v["cvss"]["chosen"]["source"], "cna");
            assert_eq!(v["affected"][0]["product"], "widget");
            assert_eq!(v["matches"][0]["product_id"], "widget");
            assert!(v["kev"].is_null());
            assert!(read_detail(c, "CVE-2026-9999")?.is_none());
            Ok(())
        })
        .unwrap();
    }
}
