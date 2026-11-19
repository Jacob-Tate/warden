//! Primary source: CVEProject/cvelistV5 GitHub release delta zips.
//!
//! Deltas are cumulative per UTC day (`cve_YYYY-MM-DD_HH00Z`), so each run
//! downloads the newest delta for today and keeps records whose
//! `cveMetadata.dateUpdated` is newer than the cursor. Catch-up after downtime
//! uses each missed day's `end_of_day` delta. ADP (CISA Vulnrichment) data is
//! inside the same records. Tags are derived from the clock, not the GitHub API.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::{Source, SourceContext, SyncOutcome};

pub const SOURCE: &str = "cvelist";

/// Persisted as JSON in `source_status.cursor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CvelistCursor {
    /// Last delta tag applied, e.g. `cve_2026-11-19_2100Z`.
    pub last_delta_tag: Option<String>,
    /// Max `dateUpdated` (ISO, ms) among applied records.
    pub max_date_updated: Option<String>,
}

pub struct CvelistSource;

impl Source for CvelistSource {
    fn name(&self) -> &'static str {
        SOURCE
    }

    async fn sync(&self, _ctx: &SourceContext) -> Result<SyncOutcome> {
        // TODO(phase 1b): tag derivation, zip download, record parsing, upsert.
        bail!("cvelist sync not implemented yet")
    }
}
