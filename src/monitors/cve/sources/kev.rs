//! CISA Known Exploited Vulnerabilities catalog. One ~1.9 MB JSON file, polled
//! with `If-None-Match` (ETag lives in `source_status.etag`); a 304 only marks
//! the run successful. On a 200 every entry is upserted: `first_seen_at` is set
//! on insert only, everything else (notably the ransomware flag, which can
//! flip later) is refreshed. Newly inserted CVE ids are returned in
//! `SyncOutcome::new_ids`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::{Source, SourceContext, SyncOutcome, tracked};
use crate::db::{cve_repo, cve_repo::load_cursor, repo};
use crate::model::{KevEntry, now_rfc3339};

pub const SOURCE: &str = "kev";

pub const URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// Persisted as JSON in `source_status.cursor` (the ETag is stored separately).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KevCursor {
    pub catalog_version: Option<String>,
    pub date_released: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Catalog {
    catalog_version: Option<String>,
    date_released: Option<String>,
    #[serde(default)]
    vulnerabilities: Vec<Item>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Item {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(default)]
    vendor_project: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    vulnerability_name: String,
    #[serde(default)]
    date_added: String,
    due_date: Option<String>,
    known_ransomware_campaign_use: Option<String>,
}

pub struct KevSource {
    pub url: String,
}

impl Default for KevSource {
    fn default() -> Self {
        Self { url: URL.into() }
    }
}

/// Parse the catalog JSON into entries (`first_seen_at` = `now`).
fn parse_catalog(bytes: &[u8], now: &str) -> Result<(KevCursor, Vec<KevEntry>)> {
    let cat: Catalog = serde_json::from_slice(bytes).context("parsing KEV JSON")?;
    let entries = cat
        .vulnerabilities
        .into_iter()
        .filter(|i| !i.cve_id.trim().is_empty())
        .map(|i| KevEntry {
            cve_id: i.cve_id.trim().to_owned(),
            vendor_project: i.vendor_project,
            product: i.product,
            name: i.vulnerability_name,
            date_added: i.date_added,
            due_date: i.due_date.filter(|d| !d.is_empty()),
            ransomware: i
                .known_ransomware_campaign_use
                .is_some_and(|v| v.eq_ignore_ascii_case("known")),
            first_seen_at: now.to_owned(),
        })
        .collect();
    Ok((
        KevCursor {
            catalog_version: cat.catalog_version,
            date_released: cat.date_released,
        },
        entries,
    ))
}

impl KevSource {
    async fn run(&self, ctx: &SourceContext) -> Result<SyncOutcome> {
        let (cursor, etag): (KevCursor, Option<String>) =
            ctx.db.call(|c| load_cursor(c, SOURCE)).await?;
        let mut req = ctx.http.get(&self.url);
        if let Some(e) = &etag {
            req = req.header(reqwest::header::IF_NONE_MATCH, e);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("GET {}", self.url))?;
        let cursor_json = serde_json::to_string(&cursor)?;
        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            ctx.db
                .call(move |c| repo::mark_success(c, SOURCE, Some(&cursor_json), etag.as_deref()))
                .await?;
            return Ok(SyncOutcome::default());
        }
        let resp = resp
            .error_for_status()
            .with_context(|| format!("GET {}", self.url))?;
        let new_etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = resp.bytes().await.context("reading KEV body")?;
        let (new_cursor, entries) = parse_catalog(&body, &now_rfc3339())?;
        let total = entries.len();
        let json = serde_json::to_string(&new_cursor)?;
        let new_ids = ctx
            .db
            .call(move |c| {
                let ids = cve_repo::upsert_kev(c, &entries)?;
                repo::mark_success(c, SOURCE, Some(&json), new_etag.as_deref())?;
                Ok(ids)
            })
            .await?;
        Ok(SyncOutcome {
            changed: new_ids.len(),
            skipped: total - new_ids.len(),
            changed_ids: new_ids.clone(),
            new_ids,
        })
    }
}

impl Source for KevSource {
    fn name(&self) -> &'static str {
        SOURCE
    }

    async fn sync(&self, ctx: &SourceContext) -> Result<SyncOutcome> {
        tracked(ctx, SOURCE, self.run(ctx)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitors::cve::sources::testutil::{Canned, ctx, fixture, serve};

    #[test]
    fn parses_fixture() {
        let (cur, entries) = parse_catalog(&fixture("kev.json"), "now").unwrap();
        assert_eq!(cur.catalog_version.as_deref(), Some("2026.11.18"));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].cve_id, "CVE-2024-10441");
        assert_eq!(entries[0].date_added, "2026-11-18");
        assert!(!entries[0].ransomware);
        assert_eq!(entries[0].due_date.as_deref(), Some("2026-11-21"));
    }

    #[tokio::test]
    async fn etag_flow_inserts_updates_and_304s() {
        let body = fixture("kev.json");
        let flipped = String::from_utf8(body.clone()).unwrap().replacen(
            "\"knownRansomwareCampaignUse\":\"Unknown\"",
            "\"knownRansomwareCampaignUse\":\"Known\"",
            1,
        );
        let server = serve(move |req, n| {
            let inm = req
                .headers
                .get("if-none-match")
                .and_then(|v| v.to_str().ok());
            match n {
                0 => {
                    assert!(inm.is_none());
                    Canned::ok(body.clone()).header("etag", "\"v1\"")
                }
                1 => {
                    assert_eq!(inm, Some("\"v1\""));
                    Canned::status(304)
                }
                _ => Canned::ok(flipped.clone()).header("etag", "\"v2\""),
            }
        })
        .await;
        let ctx = ctx();
        let src = KevSource {
            url: format!("{}/kev.json", server.base),
        };
        let out = src.sync(&ctx).await.unwrap();
        assert_eq!(out.new_ids, ["CVE-2024-10441", "CVE-2026-40217"]);
        let first_seen: String = ctx
            .db
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT first_seen_at FROM kev WHERE cve_id = 'CVE-2024-10441'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();

        // 304: nothing new, etag kept, still counted as success.
        let out = src.sync(&ctx).await.unwrap();
        assert!(out.new_ids.is_empty() && out.changed == 0);
        let st = ctx
            .db
            .with_conn(|c| Ok(repo::get_source_status(c, SOURCE)?.unwrap()))
            .unwrap();
        assert_eq!(st.etag.as_deref(), Some("\"v1\""));
        assert!(st.last_error.is_none());

        // 200 again with a flipped ransomware flag: no new ids, flag updated, first_seen kept.
        let out = src.sync(&ctx).await.unwrap();
        assert!(out.new_ids.is_empty());
        ctx.db
            .with_conn(|c| {
                let (r, fs): (i64, String) = c.query_row(
                    "SELECT ransomware, first_seen_at FROM kev WHERE cve_id = 'CVE-2024-10441'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                assert_eq!(r, 1);
                assert_eq!(fs, first_seen);
                Ok(())
            })
            .unwrap();
    }

    #[tokio::test]
    async fn http_error_is_recorded() {
        let server = serve(|_, _| Canned::status(503)).await;
        let ctx = ctx();
        let src = KevSource {
            url: format!("{}/kev.json", server.base),
        };
        assert!(src.sync(&ctx).await.is_err());
        let st = ctx
            .db
            .with_conn(|c| Ok(repo::get_source_status(c, SOURCE)?.unwrap()))
            .unwrap();
        assert!(st.last_error.unwrap().contains("503"));
    }

    /// Live: the real CISA catalog (about 1.9 MB), twice to exercise the ETag.
    #[tokio::test]
    #[ignore = "hits the real CISA endpoint"]
    async fn live_kev_sync() {
        let ctx = ctx();
        let src = KevSource::default();
        let t = std::time::Instant::now();
        let out = src.sync(&ctx).await.unwrap();
        let first = t.elapsed();
        let n: i64 = ctx
            .db
            .with_conn(|c| Ok(c.query_row("SELECT count(*) FROM kev", [], |r| r.get(0))?))
            .unwrap();
        let t2 = std::time::Instant::now();
        let out2 = src.sync(&ctx).await.unwrap();
        let st = ctx
            .db
            .with_conn(|c| Ok(repo::get_source_status(c, SOURCE)?.unwrap()))
            .unwrap();
        println!(
            "LIVE kev: rows={n} new={} in {first:?}; second run new={} in {:?}; etag={:?}",
            out.new_ids.len(),
            out2.new_ids.len(),
            t2.elapsed(),
            st.etag
        );
        assert!(n > 1000);
    }
}
