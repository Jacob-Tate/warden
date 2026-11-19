//! Sync orchestration.
//!
//! One run, in order: `cvelist` -> `nvd_feed` -> `kev` -> `epss`, then the CVE
//! ids that were created or changed (union of every source's `changed_ids` and
//! `new_ids`, which includes newly added KEV ids) are matched against the tracked
//! products. Each source records its own outcome in `source_status`; a failing
//! source is logged, reported in the [`RunSummary`] and never stops the others.
//!
//! * `nvd_api` is only a catch-up: when `nvd_feed` last succeeded more than
//!   [`NVD_CATCHUP_AFTER_DAYS`] ago (the feed window is ~8 days) the CVEs modified
//!   since then are pulled from the API. Never on a normal hourly run.
//! * KEV CVEs that match a tracked product but are not stored (old CVEs newly
//!   added to KEV, which no delta contains) are fetched from NVD by id.
//! * Runs never overlap ([`Syncer::trigger_sync`] returns `None` while one is in
//!   progress), so it is safe to call from a scheduler, the CLI and later MCP.
//! * Once a day, CVEs that match no product, were never delivered, are not in KEV
//!   and were last modified more than `retention_days` ago are deleted.

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use chrono::{DateTime, SecondsFormat, Utc};

use super::sources::{
    Source, SourceContext, SyncOutcome,
    cvelist::CvelistSource,
    epss::EpssSource,
    kev::KevSource,
    nvd_api::{self, NvdApiSource},
    nvd_feed::{self, NvdFeedSource},
    tracked,
};
use super::tracked::fetch_missing_kev;
use crate::db::{Db, cve_repo, match_repo, repo};
use crate::model::now_rfc3339;

/// `nvd_feed` older than this triggers an `nvd_api` catch-up.
pub const NVD_CATCHUP_AFTER_DAYS: i64 = 7;
/// Seconds between retention prunes.
const PRUNE_EVERY: chrono::Duration = chrono::Duration::hours(24);
const PRUNE_KEY: &str = "retention";
/// Delay before the first scheduled run.
pub const FIRST_RUN_DELAY: Duration = Duration::from_secs(20);

/// What one source did in a run.
#[derive(Debug, Clone)]
pub struct StepReport {
    pub source: &'static str,
    pub error: Option<String>,
    pub changed: usize,
    pub new: usize,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct RunSummary {
    pub steps: Vec<StepReport>,
    /// CVEs evaluated by the matcher.
    pub cves_matched: usize,
    /// Matches stored for those CVEs afterwards.
    pub matches_stored: usize,
    /// KEV CVEs fetched from NVD because they were missing locally.
    pub kev_fetched: usize,
    /// Rows removed by retention (only on the run that prunes).
    pub pruned: Option<usize>,
    /// Non-source errors (matching, pruning).
    pub errors: Vec<String>,
    pub elapsed: Duration,
}

impl RunSummary {
    pub fn failed_sources(&self) -> Vec<&'static str> {
        self.steps
            .iter()
            .filter(|s| s.error.is_some())
            .map(|s| s.source)
            .collect()
    }

    /// One log line.
    pub fn line(&self) -> String {
        let mut parts: Vec<String> = self
            .steps
            .iter()
            .map(|s| match &s.error {
                None => format!(
                    "{} ok {} changed/{} new {:.1}s",
                    s.source,
                    s.changed,
                    s.new,
                    s.elapsed.as_secs_f32()
                ),
                Some(_) => format!("{} FAILED {:.1}s", s.source, s.elapsed.as_secs_f32()),
            })
            .collect();
        parts.push(format!(
            "matched {} cves -> {} matches",
            self.cves_matched, self.matches_stored
        ));
        if self.kev_fetched > 0 {
            parts.push(format!("{} kev cves fetched", self.kev_fetched));
        }
        if let Some(n) = self.pruned {
            parts.push(format!("pruned {n}"));
        }
        for e in &self.errors {
            parts.push(format!("error: {e}"));
        }
        format!(
            "sync {:.1}s: {}",
            self.elapsed.as_secs_f32(),
            parts.join("; ")
        )
    }
}

/// Whether the NVD API catch-up is needed given when `nvd_feed` last succeeded.
/// `None` (never succeeded) means a fresh install: the feed itself covers 8 days.
pub fn nvd_catchup_since(
    feed_last_success: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    feed_last_success
        .filter(|t| now - *t > chrono::Duration::days(NVD_CATCHUP_AFTER_DAYS))
        .map(|t| t - chrono::Duration::hours(1))
}

pub struct Syncer {
    pub ctx: SourceContext,
    pub cvelist: CvelistSource,
    pub nvd_feed: NvdFeedSource,
    pub kev: KevSource,
    pub epss: EpssSource,
    pub nvd_api: NvdApiSource,
    pub retention_days: i64,
    pub backfill_days: i64,
    running: tokio::sync::Mutex<()>,
    last_run: std::sync::Mutex<Option<LastRun>>,
    last_started: std::sync::Mutex<Option<DateTime<Utc>>>,
}

/// Outcome of the most recent finished pass, kept in memory for `sync_status`.
#[derive(Debug, Clone)]
pub struct LastRun {
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub ok: bool,
    pub line: String,
}

impl Syncer {
    pub fn new(
        ctx: SourceContext,
        nvd_api_key: Option<String>,
        retention_days: i64,
        backfill_days: i64,
    ) -> Self {
        Self {
            ctx,
            cvelist: CvelistSource::default(),
            nvd_feed: NvdFeedSource::default(),
            kev: KevSource::default(),
            epss: EpssSource::default(),
            nvd_api: NvdApiSource::new(nvd_api_key),
            retention_days,
            backfill_days,
            running: tokio::sync::Mutex::new(()),
            last_run: std::sync::Mutex::new(None),
            last_started: std::sync::Mutex::new(None),
        }
    }

    pub fn db(&self) -> &Db {
        &self.ctx.db
    }

    /// The most recent finished pass of this process, if any.
    pub fn last_run(&self) -> Option<LastRun> {
        self.last_run
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// When the most recent pass (running or finished) started.
    pub fn last_started(&self) -> Option<DateTime<Utc>> {
        *self.last_started.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether a pass is running right now.
    pub fn is_running(&self) -> bool {
        self.running.try_lock().is_err()
    }

    /// Run one full pass now. Returns `None` (without doing anything) if a run is
    /// already in progress.
    pub async fn trigger_sync(&self) -> Option<RunSummary> {
        let Ok(_guard) = self.running.try_lock() else {
            tracing::info!("sync already running; skipping");
            return None;
        };
        let started_at = Utc::now();
        *self.last_started.lock().unwrap_or_else(|e| e.into_inner()) = Some(started_at);
        let summary = self.run().await;
        *self.last_run.lock().unwrap_or_else(|e| e.into_inner()) = Some(LastRun {
            started_at,
            finished_at: Utc::now(),
            ok: summary.failed_sources().is_empty() && summary.errors.is_empty(),
            line: summary.line(),
        });
        if summary.failed_sources().is_empty() && summary.errors.is_empty() {
            tracing::info!("{}", summary.line());
        } else {
            tracing::warn!("{}", summary.line());
        }
        Some(summary)
    }

    async fn step<S: Source>(&self, src: &S, ids: &mut BTreeSet<String>) -> StepReport {
        let t = Instant::now();
        let r = src.sync(&self.ctx).await;
        Self::report(src.name(), r, t, ids)
    }

    fn report(
        source: &'static str,
        r: Result<SyncOutcome>,
        t: Instant,
        ids: &mut BTreeSet<String>,
    ) -> StepReport {
        match r {
            Ok(o) => {
                ids.extend(o.changed_ids.iter().cloned());
                ids.extend(o.new_ids.iter().cloned());
                StepReport {
                    source,
                    error: None,
                    changed: o.changed,
                    new: o.new_ids.len(),
                    elapsed: t.elapsed(),
                }
            }
            Err(e) => StepReport {
                source,
                error: Some(format!("{e:#}")),
                changed: 0,
                new: 0,
                elapsed: t.elapsed(),
            },
        }
    }

    async fn run(&self) -> RunSummary {
        let t0 = Instant::now();
        let mut s = RunSummary::default();
        let mut ids: BTreeSet<String> = BTreeSet::new();

        let prev_feed: Option<DateTime<Utc>> = self
            .ctx
            .db
            .call(|c| repo::get_source_status(c, nvd_feed::SOURCE))
            .await
            .ok()
            .flatten()
            .and_then(|st| st.last_success)
            .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
            .map(|t| t.with_timezone(&Utc));

        s.steps.push(self.step(&self.cvelist, &mut ids).await);
        s.steps.push(self.step(&self.nvd_feed, &mut ids).await);

        if let Some(since) = nvd_catchup_since(prev_feed, Utc::now()) {
            tracing::info!(%since, "nvd_feed was not synced for over a week; catching up via the NVD API");
            let t = Instant::now();
            let r = tracked(
                &self.ctx,
                nvd_api::SOURCE,
                self.nvd_api.catch_up(&self.ctx, since, Utc::now()),
            )
            .await;
            s.steps.push(Self::report(nvd_api::SOURCE, r, t, &mut ids));
        }

        let t = Instant::now();
        let kev_result = self.kev.sync(&self.ctx).await;
        let kev_new = kev_result
            .as_ref()
            .map(|o| o.new_ids.clone())
            .unwrap_or_default();
        s.steps.push(Self::report("kev", kev_result, t, &mut ids));

        s.steps.push(self.step(&self.epss, &mut ids).await);

        // KEV additions for CVEs we never stored (and that matter to a tracked product).
        if !kev_new.is_empty() {
            let min = Utc::now() - chrono::Duration::days(self.backfill_days);
            match self.db().call(|c| repo::list_products(c)).await {
                Ok(products) => {
                    match fetch_missing_kev(
                        &self.ctx,
                        &self.nvd_api.api,
                        &products,
                        Some(&kev_new),
                        min,
                    )
                    .await
                    {
                        Ok(fetched) => {
                            s.kev_fetched = fetched.len();
                            ids.extend(fetched);
                        }
                        Err(e) => s.errors.push(format!("kev fetch: {e:#}")),
                    }
                }
                Err(e) => s.errors.push(format!("listing products: {e}")),
            }
        }

        let all: Vec<String> = ids.into_iter().collect();
        s.cves_matched = all.len();
        if !all.is_empty() {
            match self
                .ctx
                .db
                .call(move |c| match_repo::match_cves(c, &all))
                .await
            {
                Ok(n) => s.matches_stored = n,
                Err(e) => s.errors.push(format!("matching: {e}")),
            }
        }

        match self.maybe_prune().await {
            Ok(p) => s.pruned = p,
            Err(e) => s.errors.push(format!("retention: {e:#}")),
        }
        s.elapsed = t0.elapsed();
        s
    }

    /// Prune if the last prune was over a day ago. `None` = not due.
    async fn maybe_prune(&self) -> Result<Option<usize>> {
        let days = self.retention_days;
        Ok(self
            .ctx
            .db
            .call(move |c| {
                let last = repo::get_source_status(c, PRUNE_KEY)?
                    .and_then(|s| s.last_success)
                    .and_then(|t| DateTime::parse_from_rfc3339(&t).ok());
                if last.is_some_and(|t| Utc::now() - t.with_timezone(&Utc) < PRUNE_EVERY) {
                    return Ok(None);
                }
                let n = prune(c, days)?;
                crate::oauth::cleanup(c)?;
                repo::mark_success(c, PRUNE_KEY, None, None)?;
                Ok(Some(n))
            })
            .await?)
    }
}

/// Delete unmatched, undelivered, non-KEV CVEs last modified over `days` ago.
pub fn prune(conn: &rusqlite::Connection, days: i64) -> crate::db::DbResult<usize> {
    let cutoff =
        (Utc::now() - chrono::Duration::days(days)).to_rfc3339_opts(SecondsFormat::Millis, true);
    cve_repo::prune_unmatched(conn, &cutoff)
}

/// Scheduler loop: first run after [`FIRST_RUN_DELAY`], then every `interval`.
/// Runs until the task is dropped/aborted.
pub async fn run_scheduler(syncer: Arc<Syncer>, interval: Duration) {
    tokio::time::sleep(FIRST_RUN_DELAY).await;
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let started = now_rfc3339();
        tracing::debug!(%started, "scheduled sync");
        syncer.trigger_sync().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitors::cve::sources::testutil::{Canned, ctx, fixture, serve};
    use rusqlite::params;

    #[test]
    fn catchup_only_after_a_week() {
        let now = Utc::now();
        assert_eq!(nvd_catchup_since(None, now), None);
        assert_eq!(
            nvd_catchup_since(Some(now - chrono::Duration::days(2)), now),
            None
        );
        assert_eq!(
            nvd_catchup_since(Some(now - chrono::Duration::days(7)), now),
            None
        );
        let t = now - chrono::Duration::days(20);
        assert_eq!(
            nvd_catchup_since(Some(t), now),
            Some(t - chrono::Duration::hours(1))
        );
    }

    fn add_cve(c: &rusqlite::Connection, id: &str, modified: &str) {
        c.execute(
            "INSERT INTO cves (cve_id, description, last_modified, first_seen_at) \
             VALUES (?1, 'x', ?2, ?2)",
            params![id, modified],
        )
        .unwrap();
        c.execute(
            "INSERT INTO cve_affected (cve_id, source, product_raw) VALUES (?1, 'cna', 'x')",
            [id],
        )
        .unwrap();
    }

    #[test]
    fn prune_keeps_matched_delivered_kev_and_recent() {
        let ctx = ctx();
        ctx.db
            .with_conn(|c| {
                let old = "2020-01-01T00:00:00.000Z";
                let new = now_rfc3339();
                for id in ["OLD", "OLD-MATCHED", "OLD-DELIVERED", "OLD-KEV"] {
                    add_cve(c, id, old);
                }
                add_cve(c, "RECENT", &new);
                c.execute(
                    "INSERT INTO tracked_products (id, name, created_at, updated_at) VALUES ('p', 'P', 'x', 'x')",
                    [],
                )?;
                c.execute(
                    "INSERT INTO cve_product_matches VALUES ('OLD-MATCHED', 'p', 'cna_name', 'x')",
                    [],
                )?;
                c.execute(
                    "INSERT INTO delivered (consumer, cve_id, product_id, delivered_at) VALUES ('me', 'OLD-DELIVERED', 'gone', 'x')",
                    [],
                )?;
                c.execute(
                    "INSERT INTO kev (cve_id, first_seen_at) VALUES ('OLD-KEV', 'x')",
                    [],
                )?;
                assert_eq!(prune(c, 180)?, 1);
                let left: Vec<String> = c
                    .prepare("SELECT cve_id FROM cves ORDER BY 1")?
                    .query_map([], |r| r.get(0))?
                    .collect::<Result<_, _>>()?;
                assert_eq!(left, ["OLD-DELIVERED", "OLD-KEV", "OLD-MATCHED", "RECENT"]);
                let aff: i64 =
                    c.query_row("SELECT COUNT(*) FROM cve_affected", [], |r| r.get(0))?;
                assert_eq!(aff, 4, "affected rows cascade with their CVE");
                Ok(())
            })
            .unwrap();
    }

    #[tokio::test]
    async fn one_failing_source_does_not_stop_the_others_and_runs_do_not_overlap() {
        let kev_body = fixture("kev.json");
        let server = serve(move |req, _| {
            if req.path_and_query.starts_with("/kev") {
                Canned::ok(kev_body.clone())
            } else {
                Canned::status(500)
            }
        })
        .await;
        let mut syncer = Syncer::new(ctx(), None, 180, 14);
        syncer.cvelist.api_base = server.base.clone();
        syncer.nvd_feed.meta_url = format!("{}/nvd.meta", server.base);
        syncer.nvd_feed.feed_url = format!("{}/nvd.zip", server.base);
        syncer.kev.url = format!("{}/kev", server.base);
        syncer.epss.url = format!("{}/epss", server.base);
        let syncer = Arc::new(syncer);

        let (a, b) = tokio::join!(syncer.trigger_sync(), syncer.trigger_sync());
        let (ran, skipped) = if a.is_some() { (a, b) } else { (b, a) };
        assert!(skipped.is_none(), "second concurrent run must be refused");
        let summary = ran.expect("one run completes");
        assert_eq!(summary.failed_sources(), ["cvelist", "nvd_feed", "epss"]);
        let kev = summary.steps.iter().find(|s| s.source == "kev").unwrap();
        assert!(kev.error.is_none());
        assert_eq!(kev.new, 2);
        assert_eq!(summary.cves_matched, 2);
        assert!(summary.pruned.is_some(), "first run prunes");

        let st = syncer
            .db()
            .with_conn(|c| repo::list_source_status(c))
            .unwrap();
        let get = |n: &str| st.iter().find(|s| s.source == n).unwrap().clone();
        assert!(get("kev").last_success.is_some() && get("kev").last_error.is_none());
        assert!(get("cvelist").last_error.is_some() && get("cvelist").last_success.is_none());
        assert!(get("epss").last_error.is_some());

        // sequential run works again and does not prune twice in a day
        let again = syncer.trigger_sync().await.unwrap();
        assert!(again.pruned.is_none());
        assert!(summary.line().contains("FAILED"));
    }
}
