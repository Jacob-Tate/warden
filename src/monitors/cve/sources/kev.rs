//! CISA Known Exploited Vulnerabilities catalog. One ~1.9 MB JSON file, polled
//! with `If-None-Match` (ETag lives in `source_status.etag`). New entries are
//! found by diffing the `cveID` set against the `kev` table; the ransomware
//! flag is refreshed for every entry because it can flip later.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::{Source, SourceContext, SyncOutcome};

pub const SOURCE: &str = "kev";

pub const URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// Persisted as JSON in `source_status.cursor` (the ETag is stored separately).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KevCursor {
    pub catalog_version: Option<String>,
    pub date_released: Option<String>,
}

pub struct KevSource;

impl Source for KevSource {
    fn name(&self) -> &'static str {
        SOURCE
    }

    async fn sync(&self, _ctx: &SourceContext) -> Result<SyncOutcome> {
        // TODO(phase 1b): conditional GET, diff cveID set, upsert `kev`.
        bail!("kev sync not implemented yet")
    }
}
