//! NVD API 2.0: single-CVE lookups and outage catch-up windows only. Limits:
//! 5 requests / 30 s without a key (50 with one); lastMod windows must be
//! <= 120 days and a 404 means an invalid range, not a missing CVE.
//!
//! Requests are spaced (`min_interval`: 6 s without a key, 0.7 s with one) and
//! retried with exponential backoff on 403/429/5xx and network errors,
//! honouring `Retry-After`. Records are parsed with the same code as the
//! modified feed (`nvd_parse`).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use super::{
    Source, SourceContext, SyncOutcome,
    nvd_parse::{NvdPage, NvdVuln},
    tracked,
};
use crate::db::{
    cve_repo::{NvdUpsert, UpsertResult, load_cursor, save_cursor, upsert_nvd},
    repo,
};

pub const SOURCE: &str = "nvd_api";

pub const BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

pub const RESULTS_PER_PAGE: usize = 2000;
pub const MAX_WINDOW_DAYS: i64 = 120;

/// Persisted as JSON in `source_status.cursor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvdApiCursor {
    /// `lastModEndDate` of the last successful catch-up window (RFC 3339).
    pub last_mod_end: Option<String>,
}

pub struct NvdApi {
    pub base_url: String,
    pub api_key: Option<String>,
    /// Minimum gap between request starts.
    pub min_interval: Duration,
    /// First backoff delay; doubles per attempt (capped at 2 minutes).
    pub backoff_base: Duration,
    pub max_attempts: u32,
    next_slot: Mutex<Instant>,
}

impl NvdApi {
    pub fn new(api_key: Option<String>) -> Self {
        let min_interval = if api_key.is_some() {
            Duration::from_millis(700)
        } else {
            Duration::from_secs(6)
        };
        Self {
            base_url: BASE_URL.into(),
            api_key,
            min_interval,
            backoff_base: Duration::from_secs(10),
            max_attempts: 5,
            next_slot: Mutex::new(Instant::now()),
        }
    }

    /// Key from `NVD_API_KEY` if set.
    pub fn from_env() -> Self {
        Self::new(
            std::env::var("NVD_API_KEY")
                .ok()
                .filter(|k| !k.trim().is_empty()),
        )
    }

    async fn throttle(&self) {
        let wait = {
            let mut next = self.next_slot.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            let start = (*next).max(now);
            *next = start + self.min_interval;
            start - now
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }

    /// GET with spacing and retries. `Ok(None)` on 404.
    async fn get_json(
        &self,
        client: &reqwest::Client,
        query: &[(&str, String)],
    ) -> Result<Option<NvdPage>> {
        let mut last_err = String::new();
        for attempt in 0..self.max_attempts {
            self.throttle().await;
            let mut req = client.get(&self.base_url).query(query);
            if let Some(k) = &self.api_key {
                req = req.header("apiKey", k);
            }
            let backoff =
                (self.backoff_base * 2u32.saturating_pow(attempt)).min(Duration::from_secs(120));
            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    last_err = format!("request error: {e}");
                    tokio::time::sleep(backoff).await;
                    continue;
                }
            };
            let status = resp.status();
            match status.as_u16() {
                200 => {
                    return Ok(Some(resp.json().await.context("decoding NVD response")?));
                }
                404 => return Ok(None),
                403 | 429 | 500 | 502 | 503 | 504 => {
                    let retry_after = resp
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(|s| Duration::from_secs(s.min(120)));
                    last_err = format!("HTTP {status}");
                    tracing::warn!(%status, attempt, "nvd_api: retrying");
                    tokio::time::sleep(retry_after.unwrap_or(backoff)).await;
                }
                _ => {
                    let body = resp.text().await.unwrap_or_default();
                    bail!(
                        "NVD API {status}: {}",
                        body.chars().take(200).collect::<String>()
                    );
                }
            }
        }
        bail!(
            "NVD API failed after {} attempts ({last_err})",
            self.max_attempts
        )
    }

    /// Single lookup by id. `None` when NVD does not have the CVE (yet).
    pub async fn fetch_cve(
        &self,
        client: &reqwest::Client,
        cve_id: &str,
    ) -> Result<Option<NvdUpsert>> {
        let Some(page) = self
            .get_json(client, &[("cveId", cve_id.to_owned())])
            .await?
        else {
            return Ok(None);
        };
        Ok(page
            .vulnerabilities
            .into_iter()
            .find_map(|v| v.cve.into_upsert()))
    }

    /// Every CVE modified in `[start, end]` (at most 120 days), all pages.
    /// Holds the whole result in memory; prefer [`Self::sync_window`] for big windows.
    pub async fn fetch_modified_window(
        &self,
        client: &reqwest::Client,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Vec<NvdUpsert>> {
        let mut out = Vec::new();
        self.for_each_page(client, start, end, |page| {
            out.extend(page);
            Ok(())
        })
        .await?;
        Ok(out)
    }

    async fn for_each_page(
        &self,
        client: &reqwest::Client,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        mut on_page: impl FnMut(Vec<NvdUpsert>) -> Result<()>,
    ) -> Result<()> {
        validate_window(start, end)?;
        let fmt = |d: DateTime<Utc>| d.to_rfc3339_opts(SecondsFormat::Millis, true);
        let mut index = 0usize;
        loop {
            let q = [
                ("lastModStartDate", fmt(start)),
                ("lastModEndDate", fmt(end)),
                ("resultsPerPage", RESULTS_PER_PAGE.to_string()),
                ("startIndex", index.to_string()),
            ];
            let Some(page) = self.get_json(client, &q).await? else {
                bail!(
                    "NVD API 404 for window {} .. {} (invalid range)",
                    fmt(start),
                    fmt(end)
                );
            };
            let total = page.total_results;
            let n = page.vulnerabilities.len();
            on_page(
                page.vulnerabilities
                    .into_iter()
                    .filter_map(|v: NvdVuln| v.cve.into_upsert())
                    .collect(),
            )?;
            index += n;
            if n == 0 || index >= total {
                return Ok(());
            }
        }
    }

    /// Fetch a window and persist it page by page.
    pub async fn sync_window(
        &self,
        ctx: &SourceContext,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<SyncOutcome> {
        let mut out = SyncOutcome::default();
        validate_window(start, end)?;
        let fmt = |d: DateTime<Utc>| d.to_rfc3339_opts(SecondsFormat::Millis, true);
        let mut index = 0usize;
        loop {
            let q = [
                ("lastModStartDate", fmt(start)),
                ("lastModEndDate", fmt(end)),
                ("resultsPerPage", RESULTS_PER_PAGE.to_string()),
                ("startIndex", index.to_string()),
            ];
            let Some(page) = self.get_json(&ctx.http, &q).await? else {
                bail!(
                    "NVD API 404 for window {} .. {} (invalid range)",
                    fmt(start),
                    fmt(end)
                );
            };
            let (total, n) = (page.total_results, page.vulnerabilities.len());
            let recs: Vec<NvdUpsert> = page
                .vulnerabilities
                .into_iter()
                .filter_map(|v| v.cve.into_upsert())
                .collect();
            let applied = apply_records(ctx, vec![recs]).await?;
            out.changed += applied.changed;
            out.skipped += applied.skipped;
            out.changed_ids.extend(applied.changed_ids);
            out.new_ids.extend(applied.new_ids);
            index += n;
            if n == 0 || index >= total {
                return Ok(out);
            }
        }
    }

    /// Look one CVE up and store it. Returns whether NVD knew it.
    pub async fn lookup_and_store(&self, ctx: &SourceContext, cve_id: &str) -> Result<bool> {
        let Some(rec) = self.fetch_cve(&ctx.http, cve_id).await? else {
            return Ok(false);
        };
        apply_records(ctx, vec![vec![rec]]).await?;
        Ok(true)
    }
}

fn validate_window(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<()> {
    if end <= start {
        bail!("NVD window end must be after start");
    }
    if (end - start).num_days() > MAX_WINDOW_DAYS
        || ((end - start).num_days() == MAX_WINDOW_DAYS && (end - start).num_seconds() % 86400 != 0)
    {
        bail!("NVD lastMod window must be <= {MAX_WINDOW_DAYS} days");
    }
    Ok(())
}

async fn apply_records(ctx: &SourceContext, pages: Vec<Vec<NvdUpsert>>) -> Result<SyncOutcome> {
    Ok(ctx
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let mut out = SyncOutcome::default();
            for rec in pages.iter().flatten() {
                match upsert_nvd(&tx, rec)? {
                    UpsertResult::Skipped => out.skipped += 1,
                    r => {
                        out.changed += 1;
                        out.changed_ids.push(rec.cve_id.clone());
                        if r == UpsertResult::Inserted {
                            out.new_ids.push(rec.cve_id.clone());
                        }
                    }
                }
            }
            tx.commit()?;
            Ok(out)
        })
        .await?)
}

pub struct NvdApiSource {
    pub api: NvdApi,
    /// Most 120-day windows processed per run.
    pub max_windows: usize,
}

impl NvdApiSource {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            api: NvdApi::new(api_key),
            max_windows: 3,
        }
    }

    /// Catch up everything modified in `(since, now]` in <=120-day windows.
    pub async fn catch_up(
        &self,
        ctx: &SourceContext,
        since: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<SyncOutcome> {
        let mut total = SyncOutcome::default();
        let mut start = since;
        for _ in 0..self.max_windows {
            if start >= now {
                break;
            }
            let end = (start + chrono::Duration::days(MAX_WINDOW_DAYS)).min(now);
            let out = self.api.sync_window(ctx, start, end).await?;
            total.changed += out.changed;
            total.skipped += out.skipped;
            total.changed_ids.extend(out.changed_ids);
            total.new_ids.extend(out.new_ids);
            let cur = serde_json::to_string(&NvdApiCursor {
                last_mod_end: Some(end.to_rfc3339_opts(SecondsFormat::Millis, true)),
            })?;
            ctx.db
                .call(move |c| {
                    save_cursor(c, SOURCE, &cur)?;
                    repo::mark_success(c, SOURCE, Some(&cur), None)
                })
                .await?;
            start = end;
        }
        Ok(total)
    }

    async fn run(&self, ctx: &SourceContext) -> Result<SyncOutcome> {
        let (cursor, _): (NvdApiCursor, _) = ctx.db.call(|c| load_cursor(c, SOURCE)).await?;
        let now = Utc::now();
        let Some(since) = cursor
            .last_mod_end
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc))
        else {
            // First run: nothing to catch up; start the clock.
            let cur = serde_json::to_string(&NvdApiCursor {
                last_mod_end: Some(now.to_rfc3339_opts(SecondsFormat::Millis, true)),
            })?;
            ctx.db
                .call(move |c| repo::mark_success(c, SOURCE, Some(&cur), None))
                .await?;
            return Ok(SyncOutcome::default());
        };
        let out = self.catch_up(ctx, since, now).await?;
        // Make sure last_success moves even when the window was empty.
        let (cur, _): (NvdApiCursor, _) = ctx.db.call(|c| load_cursor(c, SOURCE)).await?;
        let json = serde_json::to_string(&cur)?;
        ctx.db
            .call(move |c| repo::mark_success(c, SOURCE, Some(&json), None))
            .await?;
        Ok(out)
    }
}

impl Source for NvdApiSource {
    fn name(&self) -> &'static str {
        SOURCE
    }

    async fn sync(&self, ctx: &SourceContext) -> Result<SyncOutcome> {
        tracked(ctx, SOURCE, self.run(ctx)).await
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::monitors::cve::sources::testutil::{Canned, ctx, fixture, serve};

    fn fast(base: &str, key: Option<&str>) -> NvdApi {
        let mut a = NvdApi::new(key.map(str::to_owned));
        a.base_url = format!("{base}/rest/json/cves/2.0");
        a.min_interval = Duration::ZERO;
        a.backoff_base = Duration::from_millis(5);
        a
    }

    fn page(vulns: &[serde_json::Value], total: usize, start: usize) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "resultsPerPage": vulns.len(), "startIndex": start, "totalResults": total,
            "format": "NVD_CVE", "version": "2.0", "vulnerabilities": vulns
        }))
        .unwrap()
    }

    fn fixture_vulns() -> Vec<serde_json::Value> {
        let v: serde_json::Value = serde_json::from_slice(&fixture("nvd-modified.json")).unwrap();
        v["vulnerabilities"].as_array().unwrap().clone()
    }

    #[tokio::test]
    async fn fetch_cve_sends_key_retries_503_and_429() {
        let vulns = fixture_vulns();
        let one = page(&vulns[..1], 1, 0);
        let server = serve(move |_, n| match n {
            0 => Canned::status(503),
            1 => Canned::status(429).header("retry-after", "0"),
            _ => Canned::ok(one.clone()),
        })
        .await;
        let api = fast(&server.base, Some("secret-key"));
        let client = crate::monitors::cve::sources::build_client().unwrap();
        let rec = api
            .fetch_cve(&client, "CVE-2020-25657")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.cve_id, "CVE-2020-25657");
        assert_eq!(server.hits(), 3);
        let reqs = server.requests();
        assert!(
            reqs.iter()
                .all(|r| r.headers.get("apikey").unwrap() == "secret-key")
        );
        assert!(reqs[0].path_and_query.contains("cveId=CVE-2020-25657"));
    }

    #[tokio::test]
    async fn no_key_header_without_key_and_gives_up_after_max_attempts() {
        let server = serve(|_, _| Canned::status(403)).await;
        let mut api = fast(&server.base, None);
        api.max_attempts = 3;
        let client = crate::monitors::cve::sources::build_client().unwrap();
        let err = api.fetch_cve(&client, "CVE-1-1").await.unwrap_err();
        assert!(format!("{err:#}").contains("3 attempts"));
        assert_eq!(server.hits(), 3);
        assert!(server.requests()[0].headers.get("apikey").is_none());
    }

    #[tokio::test]
    async fn missing_cve_is_none() {
        let server = serve(|_, _| Canned::ok(page(&[], 0, 0))).await;
        let api = fast(&server.base, None);
        let client = crate::monitors::cve::sources::build_client().unwrap();
        assert!(
            api.fetch_cve(&client, "CVE-2099-1")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn window_pages_until_total_and_persists() {
        let vulns = fixture_vulns();
        let (p0, p1) = (page(&vulns[..2], 3, 0), page(&vulns[2..], 3, 2));
        let server = serve(move |req, _| {
            if req.path_and_query.contains("startIndex=0") {
                Canned::ok(p0.clone())
            } else {
                Canned::ok(p1.clone())
            }
        })
        .await;
        let api = fast(&server.base, None);
        let ctx = ctx();
        let start = Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2026, 11, 19, 0, 0, 0).unwrap();
        let recs = api
            .fetch_modified_window(&ctx.http, start, end)
            .await
            .unwrap();
        assert_eq!(recs.len(), 3);
        let reqs = server.requests();
        assert_eq!(reqs.len(), 2);
        assert!(
            reqs[0]
                .path_and_query
                .contains("lastModStartDate=2026-11-01T00%3A00%3A00.000Z")
        );
        assert!(reqs[0].path_and_query.contains("resultsPerPage=2000"));
        assert!(reqs[1].path_and_query.contains("startIndex=2"));

        let out = api.sync_window(&ctx, start, end).await.unwrap();
        assert_eq!(out.changed, 3);
        let n: i64 = ctx
            .db
            .with_conn(|c| Ok(c.query_row("SELECT count(*) FROM cves", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(n, 3);
        // Re-running is idempotent.
        assert_eq!(api.sync_window(&ctx, start, end).await.unwrap().changed, 0);
    }

    #[tokio::test]
    async fn window_over_120_days_is_rejected_without_a_request() {
        let server = serve(|_, _| Canned::status(500)).await;
        let api = fast(&server.base, None);
        let client = crate::monitors::cve::sources::build_client().unwrap();
        let start = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        assert!(
            api.fetch_modified_window(&client, start, end)
                .await
                .is_err()
        );
        assert_eq!(server.hits(), 0);
        assert!(validate_window(start, start + chrono::Duration::days(120)).is_ok());
        assert!(validate_window(start, start + chrono::Duration::days(121)).is_err());
    }

    #[tokio::test]
    async fn source_first_run_sets_cursor_then_catches_up() {
        let vulns = fixture_vulns();
        let p = page(&vulns, 3, 0);
        let server = serve(move |_, _| Canned::ok(p.clone())).await;
        let src = NvdApiSource {
            api: fast(&server.base, None),
            max_windows: 2,
        };
        let ctx = ctx();
        let out = src.sync(&ctx).await.unwrap();
        assert_eq!(server.hits(), 0, "first run only starts the clock");
        assert_eq!(out.changed, 0);
        // Pretend the last window ended 2 days ago.
        let old =
            (Utc::now() - chrono::Duration::days(2)).to_rfc3339_opts(SecondsFormat::Millis, true);
        let cur = serde_json::to_string(&NvdApiCursor {
            last_mod_end: Some(old),
        })
        .unwrap();
        ctx.db.with_conn(|c| save_cursor(c, SOURCE, &cur)).unwrap();
        let out = src.sync(&ctx).await.unwrap();
        assert_eq!(out.changed, 3);
    }

    /// Live: one CVE lookup plus a 30-minute window (6 s spacing, no key unless NVD_API_KEY is set).
    #[tokio::test]
    #[ignore = "hits the real NVD API"]
    async fn live_nvd_api() {
        let ctx = ctx();
        let api = NvdApi::from_env();
        let t = std::time::Instant::now();
        let rec = api
            .fetch_cve(&ctx.http, "CVE-2021-44228")
            .await
            .unwrap()
            .unwrap();
        println!(
            "LIVE nvd_api: fetch_cve {} status={:?} cvss={:?} affected_rows={} in {:?}",
            rec.cve_id,
            rec.vuln_status,
            rec.cvss.as_ref().map(|c| c.score),
            rec.affected.len(),
            t.elapsed()
        );
        assert!(rec.cvss.is_some() && !rec.affected.is_empty());
        let end = Utc::now() - chrono::Duration::hours(1);
        let start = end - chrono::Duration::minutes(30);
        let t = std::time::Instant::now();
        let out = api.sync_window(&ctx, start, end).await.unwrap();
        println!(
            "LIVE nvd_api: window {start}..{end} changed={} in {:?}",
            out.changed,
            t.elapsed()
        );
    }
}
