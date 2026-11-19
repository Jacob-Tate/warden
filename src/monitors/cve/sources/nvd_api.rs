//! NVD API 2.0: single-CVE lookups and outage catch-up windows only. Limits:
//! 5 requests / 30 s without a key (50 with one); lastMod windows must be
//! <= 120 days and a 404 means an invalid range, not a missing CVE.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::{Source, SourceContext, SyncOutcome};
use crate::model::CveRecord;

pub const SOURCE: &str = "nvd_api";

pub const BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// Persisted as JSON in `source_status.cursor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvdApiCursor {
    /// `lastModEndDate` of the last successful catch-up window.
    pub last_mod_end: Option<String>,
}

/// Fetch one CVE by id (`?cveId=`). Not wired up yet.
pub async fn lookup_cve(_ctx: &SourceContext, _cve_id: &str) -> Result<Option<CveRecord>> {
    // TODO(phase 1b): request with backoff, 6 s spacing, optional apiKey header.
    bail!("nvd_api lookup not implemented yet")
}

pub struct NvdApiSource {
    pub api_key: Option<String>,
}

impl Source for NvdApiSource {
    fn name(&self) -> &'static str {
        SOURCE
    }

    async fn sync(&self, _ctx: &SourceContext) -> Result<SyncOutcome> {
        // TODO(phase 1b): catch-up by lastMod window, only when the other feeds missed a gap.
        bail!("nvd_api catch-up not implemented yet")
    }
}
