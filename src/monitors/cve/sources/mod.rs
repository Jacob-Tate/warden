//! Upstream data sources. Each source persists its own cursor in
//! `source_status` (see `db::repo::{get_source_status, mark_success, mark_error}`).

pub mod cvelist;
pub mod epss;
pub mod kev;
pub mod nvd_api;
pub mod nvd_feed;

use crate::db::Db;

/// Shared dependencies handed to every source run.
#[derive(Clone)]
pub struct SourceContext {
    pub db: Db,
    pub http: reqwest::Client,
}

/// What one sync run accomplished.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    /// Records created or changed.
    pub changed: usize,
    /// Records skipped as unchanged / not tracked.
    pub skipped: usize,
}

/// A pollable upstream source.
///
/// Implementations load their cursor from `source_status`, fetch, apply, and
/// call `mark_success`/`mark_error` themselves so the scheduler stays generic.
#[allow(async_fn_in_trait)] // used with concrete types only, never as `dyn`
pub trait Source {
    /// Stable key used in `source_status.source` and in feed health.
    fn name(&self) -> &'static str;

    /// Run one sync pass.
    async fn sync(&self, ctx: &SourceContext) -> anyhow::Result<SyncOutcome>;
}
