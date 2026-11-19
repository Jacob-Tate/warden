//! Sync orchestration: runs the sources in pipeline order (KEV, cvelist, NVD
//! feed, EPSS; NVD API only for gaps), then re-matches changed CVEs.
//! Each source records its own outcome in `source_status`, so one failing
//! source never blocks the others.

use anyhow::{Result, bail};

use super::sources::SourceContext;

/// Run one full pass. Not wired up yet (the scheduler in `main` will call it
/// every `Config::sync_interval` once sources are implemented).
pub async fn run_once(_ctx: &SourceContext) -> Result<()> {
    // TODO(phase 1b): sequence sources, then matcher over changed CVEs.
    bail!("sync not implemented yet")
}
