//! Enrichment source: NVD JSON 2.0 `modified` feed (CPE configurations, NVD
//! CVSS, vulnStatus, fixed versions). Poll the `.meta` file, compare `sha256`
//! with the cursor, and only then download and apply the `.json.gz`, limited to
//! CVEs already tracked. The feed covers a rolling ~8 days.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::{Source, SourceContext, SyncOutcome};

pub const SOURCE: &str = "nvd_feed";

pub const META_URL: &str = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.meta";
pub const FEED_URL: &str = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz";

/// Persisted as JSON in `source_status.cursor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvdFeedCursor {
    /// `sha256` from the last applied `.meta`.
    pub sha256: Option<String>,
    pub last_modified_date: Option<String>,
}

pub struct NvdFeedSource;

impl Source for NvdFeedSource {
    fn name(&self) -> &'static str {
        SOURCE
    }

    async fn sync(&self, _ctx: &SourceContext) -> Result<SyncOutcome> {
        // TODO(phase 1b): .meta check, gz download, sha256 verify, apply to tracked CVEs.
        bail!("nvd_feed sync not implemented yet")
    }
}
