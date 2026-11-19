//! FIRST EPSS scores from the daily bulk CSV (never the per-CVE API: its batch
//! endpoint silently returns nothing for long URLs). The redirect chain must be
//! followed. Line 1 is `#model_version:...,score_date:<ts>`; skip the run when
//! `score_date` equals the cursor. Only rows for tracked CVEs are stored.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::{Source, SourceContext, SyncOutcome};

pub const SOURCE: &str = "epss";

pub const URL: &str = "https://epss.cyentia.com/epss_scores-current.csv.gz";

/// Persisted as JSON in `source_status.cursor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpssCursor {
    pub score_date: Option<String>,
}

pub struct EpssSource;

impl Source for EpssSource {
    fn name(&self) -> &'static str {
        SOURCE
    }

    async fn sync(&self, _ctx: &SourceContext) -> Result<SyncOutcome> {
        // TODO(phase 1b): after ~12:30Z, download gz, parse header + rows, upsert tracked.
        bail!("epss sync not implemented yet")
    }
}
