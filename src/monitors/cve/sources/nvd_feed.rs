//! Enrichment source: NVD JSON 2.0 `modified` feed (CPE configurations, NVD
//! CVSS, vulnStatus, fixed versions). Poll the `.meta` file, compare `sha256`
//! with the cursor, and only then download and apply the `.json.gz`. The feed
//! covers a rolling ~8 days.
//!
//! The gz is downloaded to a temp file and stream-parsed (gunzip -> serde_json
//! visitor -> one record at a time), so memory stays flat even though the JSON
//! is ~64 MB. All records are applied in one transaction; the `.meta` sha256 is
//! of the uncompressed JSON and is verified before commit (mismatch = rollback).
//! Records for CVEs not yet in the database are created from NVD data.

use std::io::{self, BufReader, Read};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{Source, SourceContext, SyncOutcome, download_to_temp, nvd_parse, to_hex, tracked};
use crate::db::{
    DbResult,
    cve_repo::{UpsertResult, load_cursor, save_cursor, upsert_nvd},
    repo,
};

pub const SOURCE: &str = "nvd_feed";

pub const META_URL: &str = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.meta";
pub const FEED_URL: &str = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz";

/// Persisted as JSON in `source_status.cursor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvdFeedCursor {
    /// `sha256` from the last applied `.meta`.
    pub sha256: Option<String>,
    pub last_modified_date: Option<String>,
    /// Max NVD `lastModified` among applied records.
    pub max_last_modified: Option<String>,
}

pub struct NvdFeedSource {
    pub meta_url: String,
    pub feed_url: String,
}

impl Default for NvdFeedSource {
    fn default() -> Self {
        Self {
            meta_url: META_URL.into(),
            feed_url: FEED_URL.into(),
        }
    }
}

struct HashRead<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> Read for HashRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

#[derive(Debug, Default)]
struct FeedStats {
    out: SyncOutcome,
    max_last_modified: Option<String>,
    sha256: String,
}

/// Apply a feed file (gzip or plain JSON) in one transaction.
fn apply_feed(
    conn: &mut rusqlite::Connection,
    path: PathBuf,
    expected_sha: Option<String>,
) -> DbResult<FeedStats> {
    let mut f = std::fs::File::open(&path)?;
    let mut magic = [0u8; 2];
    let n = f.read(&mut magic)?;
    drop(f);
    // reqwest may already have inflated a `Content-Encoding: gzip` response.
    let file = std::fs::File::open(&path)?;
    let plain: Box<dyn Read> = if n == 2 && magic == [0x1f, 0x8b] {
        Box::new(flate2::read::GzDecoder::new(BufReader::new(file)))
    } else {
        Box::new(file)
    };
    let mut reader = BufReader::with_capacity(
        64 * 1024,
        HashRead {
            inner: plain,
            hasher: Sha256::new(),
        },
    );

    let tx = conn.transaction()?;
    let mut stats = FeedStats::default();
    let parse = nvd_parse::stream_vulnerabilities(&mut reader, |v| {
        let Some(rec) = v.cve.into_upsert() else {
            stats.out.skipped += 1;
            return Ok(());
        };
        let id = rec.cve_id.clone();
        let lm = rec.last_modified.clone();
        match upsert_nvd(&tx, &rec).map_err(|e| anyhow::anyhow!("{e}"))? {
            UpsertResult::Skipped => stats.out.skipped += 1,
            r => {
                stats.out.changed += 1;
                if r == UpsertResult::Inserted {
                    stats.out.new_ids.push(id.clone());
                }
                stats.out.changed_ids.push(id);
                if stats
                    .max_last_modified
                    .as_deref()
                    .is_none_or(|m| m < lm.as_str())
                {
                    stats.max_last_modified = Some(lm);
                }
            }
        }
        Ok(())
    });
    parse.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:#}")))?;
    // Hash the whole stream, including anything after the JSON document.
    io::copy(&mut reader, &mut io::sink())?;
    let digest = reader.into_inner().hasher.finalize();
    stats.sha256 = to_hex(&digest);
    if let Some(exp) = expected_sha
        && !exp.eq_ignore_ascii_case(&stats.sha256)
    {
        // Dropping the transaction rolls everything back.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "sha256 mismatch: .meta says {exp}, downloaded {}",
                stats.sha256
            ),
        )
        .into());
    }
    tx.commit()?;
    Ok(stats)
}

impl NvdFeedSource {
    async fn run(&self, ctx: &SourceContext) -> Result<SyncOutcome> {
        let (mut cursor, _): (NvdFeedCursor, _) = ctx.db.call(|c| load_cursor(c, SOURCE)).await?;
        let meta_text = ctx
            .http
            .get(&self.meta_url)
            .timeout(std::time::Duration::from_secs(40))
            .send()
            .await
            .with_context(|| format!("GET {}", self.meta_url))?
            .error_for_status()?
            .text()
            .await
            .context("reading .meta")?;
        let meta = nvd_parse::parse_meta(&meta_text);
        let Some(sha) = meta.sha256.clone() else {
            bail!(".meta has no sha256 line");
        };
        if cursor.sha256.as_deref() == Some(sha.as_str()) {
            tracing::debug!("nvd_feed: unchanged (sha256 match)");
            let json = serde_json::to_string(&cursor)?;
            ctx.db
                .call(move |c| repo::mark_success(c, SOURCE, Some(&json), None))
                .await?;
            return Ok(SyncOutcome::default());
        }

        let started = std::time::Instant::now();
        let tmp = download_to_temp(&ctx.http, &self.feed_url).await?;
        let path = tmp.path().to_path_buf();
        let stats = ctx
            .db
            .call(move |c| apply_feed(c, path, Some(sha)))
            .await
            .context("applying NVD modified feed")?;
        drop(tmp);
        tracing::info!(
            changed = stats.out.changed,
            skipped = stats.out.skipped,
            ms = started.elapsed().as_millis() as u64,
            "nvd_feed: applied"
        );
        cursor.sha256 = Some(stats.sha256.clone());
        cursor.last_modified_date = meta.last_modified_date;
        if stats.max_last_modified.is_some() {
            cursor.max_last_modified = stats.max_last_modified.clone();
        }
        let json = serde_json::to_string(&cursor)?;
        ctx.db
            .call(move |c| {
                save_cursor(c, SOURCE, &json)?;
                repo::mark_success(c, SOURCE, Some(&json), None)
            })
            .await?;
        Ok(stats.out)
    }
}

impl Source for NvdFeedSource {
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
    use crate::db::cve_repo::{CvelistUpsert, Ssvc, upsert_cvelist};
    use crate::model::{Cvss, CvssSource};
    use crate::monitors::cve::sources::testutil::{Canned, ctx, fixture, serve};

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn sha(data: &[u8]) -> String {
        to_hex(&Sha256::digest(data))
    }

    fn meta_for(json: &[u8]) -> String {
        format!(
            "lastModifiedDate:2026-11-19T16:00:08-05:00\nsize:{}\nsha256:{}\n",
            json.len(),
            sha(json).to_ascii_uppercase()
        )
    }

    fn source(base: &str) -> NvdFeedSource {
        NvdFeedSource {
            meta_url: format!("{base}/m.meta"),
            feed_url: format!("{base}/m.json.gz"),
        }
    }

    #[tokio::test]
    async fn applies_feed_then_skips_when_sha_unchanged() {
        let json = fixture("nvd-modified.json");
        let (meta, gzbytes) = (meta_for(&json), gz(&json));
        let server = serve(move |req, _| {
            if req.path_and_query.ends_with(".meta") {
                Canned::ok(meta.clone())
            } else {
                Canned::ok(gzbytes.clone())
            }
        })
        .await;
        let ctx = ctx();
        let src = source(&server.base);
        let out = src.sync(&ctx).await.unwrap();
        assert_eq!(out.changed, 3);
        assert_eq!(out.new_ids.len(), 3);

        ctx.db
            .with_conn(|c| {
                let (st, score, primary, fixed): (String, f64, i64, String) = c.query_row(
                    "SELECT nvd_status, nvd_cvss_score, nvd_cvss_primary, fixed_versions \
                     FROM cves WHERE cve_id = 'CVE-2020-25657'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )?;
                assert_eq!((st.as_str(), score, primary), ("Analyzed", 5.9, 1));
                assert!(fixed.contains("0.39.0"));
                let n: i64 = c.query_row(
                    "SELECT count(*) FROM cve_affected WHERE cve_id = 'CVE-2020-25657' AND source = 'nvd' AND cpe_vendor IS NOT NULL",
                    [],
                    |r| r.get(0),
                )?;
                assert!(n > 3);
                let rej: String = c.query_row(
                    "SELECT state FROM cves WHERE cve_id = 'CVE-2000-0744'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(rej, "REJECTED");
                let secondary: i64 = c.query_row(
                    "SELECT nvd_cvss_primary FROM cves WHERE cve_id = 'CVE-2026-6889'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(secondary, 0);
                Ok(())
            })
            .unwrap();

        // Second run: only the .meta is fetched.
        let hits = server.hits();
        let out2 = src.sync(&ctx).await.unwrap();
        assert_eq!(out2.changed, 0);
        assert_eq!(server.hits(), hits + 1);
        let (cur, _): (NvdFeedCursor, _) = ctx.db.with_conn(|c| load_cursor(c, SOURCE)).unwrap();
        assert_eq!(cur.sha256.unwrap(), sha(&json));
        assert_eq!(
            cur.max_last_modified.as_deref(),
            Some("2026-11-19T19:49:58.280Z")
        );
    }

    #[tokio::test]
    async fn sha_mismatch_rolls_back_and_keeps_cursor() {
        let json = fixture("nvd-modified.json");
        let gzbytes = gz(&json);
        let server = serve(move |req, _| {
            if req.path_and_query.ends_with(".meta") {
                Canned::ok(format!("sha256:{}\n", "0".repeat(64)))
            } else {
                Canned::ok(gzbytes.clone())
            }
        })
        .await;
        let ctx = ctx();
        let err = source(&server.base).sync(&ctx).await.unwrap_err();
        assert!(format!("{err:#}").contains("sha256 mismatch"));
        ctx.db
            .with_conn(|c| {
                let n: i64 = c.query_row("SELECT count(*) FROM cves", [], |r| r.get(0))?;
                assert_eq!(n, 0, "transaction rolled back");
                let st = repo::get_source_status(c, SOURCE)?.unwrap();
                assert!(st.last_error.is_some() && st.cursor.is_none());
                Ok(())
            })
            .unwrap();
    }

    #[tokio::test]
    async fn does_not_clobber_cvelist_owned_fields() {
        let json = fixture("nvd-modified.json");
        let (meta, gzbytes) = (meta_for(&json), gz(&json));
        let server = serve(move |req, _| {
            if req.path_and_query.ends_with(".meta") {
                Canned::ok(meta.clone())
            } else {
                Canned::ok(gzbytes.clone())
            }
        })
        .await;
        let ctx = ctx();
        ctx.db
            .with_conn(|c| {
                upsert_cvelist(
                    c,
                    &CvelistUpsert {
                        cve_id: "CVE-2020-25657".into(),
                        state: "PUBLISHED".into(),
                        assigner: Some("redhat".into()),
                        description: "CNA description".into(),
                        published: Some("2021-01-01T00:00:00.000Z".into()),
                        date_updated: "2026-11-19T10:00:00.000Z".into(),
                        cna_cvss: Some(Cvss {
                            score: 7.5,
                            vector: Some("CVSS:3.1/AV:N".into()),
                            version: "3.1".into(),
                            source: CvssSource::Cna,
                            primary: false,
                        }),
                        adp_cvss: None,
                        cvss_all: vec![Cvss {
                            score: 7.5,
                            vector: None,
                            version: "3.1".into(),
                            source: CvssSource::Cna,
                            primary: false,
                        }],
                        ssvc: Ssvc {
                            exploitation: Some("poc".into()),
                            ..Ssvc::default()
                        },
                        adp_kev_date: None,
                        affected: vec![crate::model::Affected {
                            source: CvssSource::Cna,
                            vendor: Some("Red Hat".into()),
                            product: Some("m2crypto".into()),
                            cpe: None,
                            versions: serde_json::json!([]),
                        }],
                        fixed_versions: vec!["0.40.0".into()],
                        references: vec!["https://example.test".into()],
                    },
                )?;
                Ok(())
            })
            .unwrap();
        source(&server.base).sync(&ctx).await.unwrap();
        ctx.db
            .with_conn(|c| {
                let r = c.query_row(
                    "SELECT description, assigner, cna_cvss_score, ssvc_exploitation, nvd_cvss_score, \
                            cvelist_updated, last_modified, fixed_versions, cvss_all, first_seen_at \
                     FROM cves WHERE cve_id = 'CVE-2020-25657'",
                    [],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, f64>(2)?,
                            r.get::<_, String>(3)?,
                            r.get::<_, f64>(4)?,
                            r.get::<_, String>(5)?,
                            r.get::<_, String>(6)?,
                            r.get::<_, String>(7)?,
                            r.get::<_, String>(8)?,
                        ))
                    },
                )?;
                assert_eq!(r.0, "CNA description");
                assert_eq!(r.1, "redhat");
                assert_eq!(r.2, 7.5);
                assert_eq!(r.3, "poc");
                assert_eq!(r.4, 5.9);
                assert_eq!(r.5, "2026-11-19T10:00:00.000Z");
                assert_eq!(r.6, "2026-11-19T19:49:58.280Z", "max(cvelist, nvd)");
                assert!(r.7.contains("0.40.0") && r.7.contains("0.39.0"), "{}", r.7);
                assert!(r.8.contains("\"cna\"") && r.8.contains("\"nvd\""));
                let cna_rows: i64 = c.query_row(
                    "SELECT count(*) FROM cve_affected WHERE cve_id='CVE-2020-25657' AND source='cna'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(cna_rows, 1);
                Ok(())
            })
            .unwrap();
    }

    /// Live: real modified feed (about 5 MB gz, ~64 MB JSON).
    #[tokio::test]
    #[ignore = "hits the real NVD feed"]
    async fn live_nvd_feed_sync() {
        let ctx = ctx();
        let t = std::time::Instant::now();
        let out = NvdFeedSource::default().sync(&ctx).await.unwrap();
        let (n, aff): (i64, i64) = ctx
            .db
            .with_conn(|c| {
                Ok((
                    c.query_row("SELECT count(*) FROM cves", [], |r| r.get(0))?,
                    c.query_row(
                        "SELECT count(*) FROM cve_affected WHERE source='nvd'",
                        [],
                        |r| r.get(0),
                    )?,
                ))
            })
            .unwrap();
        println!(
            "LIVE nvd_feed: changed={} skipped={} cves={n} nvd_affected_rows={aff} in {:?}",
            out.changed,
            out.skipped,
            t.elapsed()
        );
        assert!(out.changed > 1000);
    }
}
