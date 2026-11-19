//! FIRST EPSS scores from the daily bulk CSV (never the per-CVE API: its batch
//! endpoint silently returns nothing for long URLs). The redirect chain
//! (cyentia -> empiricalsecurity -> dated file) is followed by the HTTP client.
//! Line 1 is `#model_version:...,score_date:<ts>`; line 2 the column header.
//!
//! Skip logic: `If-None-Match` with the stored ETag (cheap 304), and after a
//! download, a run whose header `score_date` equals the cursor is a no-op.
//!
//! Storage decision: ALL rows are stored (about 400k), in one transaction via a
//! single prepared upsert. Measured live (see the ignored test) this stays well
//! under the 10 s threshold, so no tracked-CVE filtering is applied and the
//! feed can show EPSS for any CVE, including ones tracked later.

use std::io::{BufRead, BufReader};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use super::{Source, SourceContext, SyncOutcome, tracked};
use crate::db::{
    DbResult,
    cve_repo::{EpssWriter, load_cursor},
    repo,
};

pub const SOURCE: &str = "epss";

pub const URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";

/// Persisted as JSON in `source_status.cursor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpssCursor {
    /// Full `score_date` value of the header, e.g. `2026-11-19T12:00:23Z`.
    pub score_date: Option<String>,
    pub model_version: Option<String>,
}

pub struct EpssSource {
    pub url: String,
}

impl Default for EpssSource {
    fn default() -> Self {
        Self { url: URL.into() }
    }
}

/// Parse `#model_version:v2026.06.15,score_date:2026-11-19T12:00:23Z`.
pub fn parse_header(line: &str) -> Option<EpssCursor> {
    let body = line.trim().strip_prefix('#')?;
    let mut c = EpssCursor::default();
    for part in body.split(',') {
        match part.split_once(':') {
            Some(("model_version", v)) => c.model_version = Some(v.trim().to_owned()),
            Some(("score_date", v)) => c.score_date = Some(v.trim().to_owned()),
            _ => {}
        }
    }
    c.score_date.is_some().then_some(c)
}

/// `CVE-...,0.04753,0.92065` -> (id, score, percentile).
pub fn parse_row(line: &str) -> Option<(&str, f64, f64)> {
    let mut it = line.trim().split(',');
    let id = it.next().filter(|i| i.starts_with("CVE-"))?;
    let score = it.next()?.parse().ok()?;
    let pct = it.next()?.parse().ok()?;
    Some((id, score, pct))
}

#[derive(Debug)]
enum Applied {
    /// Header date equals the cursor; nothing written.
    Unchanged(EpssCursor),
    Imported {
        header: EpssCursor,
        rows: usize,
        bad_rows: usize,
    },
}

/// Parse `gz_bytes` and bulk upsert (one transaction, one prepared statement).
fn apply(
    conn: &mut rusqlite::Connection,
    gz_bytes: &[u8],
    current: &EpssCursor,
) -> DbResult<Applied> {
    let plain: Box<dyn std::io::Read + '_> = if gz_bytes.starts_with(&[0x1f, 0x8b]) {
        Box::new(super::CapReader::new(
            flate2::read::GzDecoder::new(gz_bytes),
            super::MAX_DECOMPRESSED_BYTES,
        ))
    } else {
        Box::new(gz_bytes)
    };
    let mut lines = BufReader::new(plain).lines();
    let first = lines.next().transpose()?.unwrap_or_default();
    let Some(header) = parse_header(&first) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("EPSS file has no '#model_version...,score_date:' header (got {first:?})"),
        )
        .into());
    };
    if header.score_date == current.score_date {
        return Ok(Applied::Unchanged(header));
    }
    let date = header
        .score_date
        .as_deref()
        .and_then(|d| d.get(..10))
        .unwrap_or_default()
        .to_owned();
    let tx = conn.transaction()?;
    let (mut rows, mut bad_rows) = (0usize, 0usize);
    {
        let mut w = EpssWriter::new(&tx)?;
        for line in lines {
            let line = line?;
            if line.is_empty() || line.starts_with("cve,") {
                continue;
            }
            match parse_row(&line) {
                Some((id, score, pct)) => {
                    w.write(id, score, pct, &date)?;
                    rows += 1;
                }
                None => bad_rows += 1,
            }
        }
    }
    if rows == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "EPSS file contained no score rows",
        )
        .into());
    }
    tx.commit()?;
    Ok(Applied::Imported {
        header,
        rows,
        bad_rows,
    })
}

impl EpssSource {
    async fn run(&self, ctx: &SourceContext) -> Result<SyncOutcome> {
        let (cursor, etag): (EpssCursor, Option<String>) =
            ctx.db.call(|c| load_cursor(c, SOURCE)).await?;
        let mut req = ctx.http.get(&self.url);
        if let (Some(e), Some(_)) = (&etag, &cursor.score_date) {
            req = req.header(reqwest::header::IF_NONE_MATCH, e);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("GET {}", self.url))?;
        let cur_json = serde_json::to_string(&cursor)?;
        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            ctx.db
                .call(move |c| repo::mark_success(c, SOURCE, Some(&cur_json), etag.as_deref()))
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
        let body = super::read_body_capped(resp, &self.url, super::MAX_EPSS_GZ_BYTES).await?;
        if body.is_empty() {
            bail!("EPSS download was empty");
        }
        let started = std::time::Instant::now();
        let current = cursor.clone();
        let (applied, etag_out) = ctx
            .db
            .call(move |c| Ok((apply(c, &body, &current)?, new_etag)))
            .await?;
        match applied {
            Applied::Unchanged(h) => {
                let json = serde_json::to_string(&h)?;
                ctx.db
                    .call(move |c| repo::mark_success(c, SOURCE, Some(&json), etag_out.as_deref()))
                    .await?;
                Ok(SyncOutcome::default())
            }
            Applied::Imported {
                header,
                rows,
                bad_rows,
            } => {
                tracing::info!(
                    rows,
                    bad_rows,
                    score_date = ?header.score_date,
                    ms = started.elapsed().as_millis() as u64,
                    "epss: imported"
                );
                let json = serde_json::to_string(&header)?;
                ctx.db
                    .call(move |c| repo::mark_success(c, SOURCE, Some(&json), etag_out.as_deref()))
                    .await?;
                Ok(SyncOutcome {
                    changed: rows,
                    skipped: bad_rows,
                    ..SyncOutcome::default()
                })
            }
        }
    }
}

impl Source for EpssSource {
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
    use crate::monitors::cve::sources::testutil::{Canned, ctx, fixture, serve};

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn header_and_rows_parse() {
        let h = parse_header("#model_version:v2026.06.15,score_date:2026-11-19T12:00:23Z").unwrap();
        assert_eq!(h.model_version.as_deref(), Some("v2026.06.15"));
        assert_eq!(h.score_date.as_deref(), Some("2026-11-19T12:00:23Z"));
        assert!(parse_header("cve,epss,percentile").is_none());
        assert_eq!(
            parse_row("CVE-1999-0001,0.04753,0.92065"),
            Some(("CVE-1999-0001", 0.04753, 0.92065))
        );
        assert!(parse_row("cve,epss,percentile").is_none());
        assert!(parse_row("CVE-1-1,abc,0.1").is_none());
    }

    #[tokio::test]
    async fn imports_skips_same_date_and_updates_new_date() {
        let csv = fixture("epss.csv");
        let newer = String::from_utf8(csv.clone())
            .unwrap()
            .replace("2026-11-19T12:00:23Z", "2026-11-20T12:00:11Z")
            .replace("0.50000,0.97000", "0.60000,0.98000");
        let (g1, g2) = (gz(&csv), gz(newer.as_bytes()));
        // No ETag support: the date check must do the skipping.
        let server =
            serve(move |_, n| Canned::ok(if n < 2 { g1.clone() } else { g2.clone() })).await;
        let ctx = ctx();
        let src = EpssSource {
            url: format!("{}/epss.csv.gz", server.base),
        };
        let out = src.sync(&ctx).await.unwrap();
        assert_eq!(out.changed, 3);
        let score: f64 = ctx
            .db
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT score FROM epss WHERE cve_id='CVE-2024-10441'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(score, 0.5);

        let out = src.sync(&ctx).await.unwrap();
        assert_eq!(out.changed, 0, "same score_date is a no-op");

        let out = src.sync(&ctx).await.unwrap();
        assert_eq!(out.changed, 3);
        ctx.db
            .with_conn(|c| {
                let (s, d): (f64, String) = c.query_row(
                    "SELECT score, score_date FROM epss WHERE cve_id='CVE-2024-10441'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                assert_eq!((s, d.as_str()), (0.6, "2026-11-20"));
                let n: i64 = c.query_row("SELECT count(*) FROM epss", [], |r| r.get(0))?;
                assert_eq!(n, 3);
                Ok(())
            })
            .unwrap();
        let st = ctx
            .db
            .with_conn(|c| Ok(repo::get_source_status(c, SOURCE)?.unwrap()))
            .unwrap();
        assert!(st.cursor.unwrap().contains("2026-11-20T12:00:11Z"));
    }

    #[tokio::test]
    async fn etag_304_short_circuits() {
        let g = gz(&fixture("epss.csv"));
        let server = serve(move |req, _| {
            if req.headers.get("if-none-match").is_some() {
                Canned::status(304)
            } else {
                Canned::ok(g.clone()).header("etag", "\"e1\"")
            }
        })
        .await;
        let ctx = ctx();
        let src = EpssSource {
            url: format!("{}/x.gz", server.base),
        };
        assert_eq!(src.sync(&ctx).await.unwrap().changed, 3);
        assert_eq!(src.sync(&ctx).await.unwrap().changed, 0);
        let st = ctx
            .db
            .with_conn(|c| Ok(repo::get_source_status(c, SOURCE)?.unwrap()))
            .unwrap();
        assert_eq!(st.etag.as_deref(), Some("\"e1\""));
    }

    #[tokio::test]
    async fn garbage_body_is_an_error() {
        let server = serve(|_, _| Canned::ok(gz(b"not,an,epss\nfile\n"))).await;
        let ctx = ctx();
        let src = EpssSource {
            url: format!("{}/x.gz", server.base),
        };
        assert!(src.sync(&ctx).await.is_err());
    }

    /// Live: real bulk CSV (about 2.9 MB gz, ~400k rows): measures the bulk upsert.
    #[tokio::test]
    #[ignore = "hits the real EPSS host"]
    async fn live_epss_sync() {
        let ctx = ctx();
        let t = std::time::Instant::now();
        let out = EpssSource::default().sync(&ctx).await.unwrap();
        let n: i64 = ctx
            .db
            .with_conn(|c| Ok(c.query_row("SELECT count(*) FROM epss", [], |r| r.get(0))?))
            .unwrap();
        println!(
            "LIVE epss: rows={} stored={n} total {:?}",
            out.changed,
            t.elapsed()
        );
        assert!(n > 300_000);
    }
}
