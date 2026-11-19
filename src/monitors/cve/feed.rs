//! The agent-facing "what's new" view.
//!
//! `get_new` returns, per consumer, matched CVEs that are not yet acknowledged
//! (`change = new`) or whose KEV flag / CVSS changed since the `delivered`
//! snapshot (`kev_added`, `cvss_changed`). Sorted KEV first, then CVSS
//! descending. Fetching never consumes: only [`ack`] writes `delivered`.

use anyhow::{Result, bail};

use crate::db::Db;
use crate::model::FeedEnvelope;

/// Compute the feed for `consumer`. Not wired up yet.
pub async fn get_new(_db: &Db, _consumer: &str, _limit: usize) -> Result<FeedEnvelope> {
    // TODO(phase 1b): query matches vs delivered, build items and source health.
    bail!("feed not implemented yet")
}

/// Mark CVE ids as delivered for `consumer`, snapshotting cvss/kev/state.
pub async fn ack(_db: &Db, _consumer: &str, _cve_ids: &[String]) -> Result<usize> {
    // TODO(phase 1b): upsert `delivered` rows from current state.
    bail!("ack not implemented yet")
}
