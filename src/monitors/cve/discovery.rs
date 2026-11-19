//! Product discovery: turn a plain name ("FortiClient EMS") into candidate
//! `TrackedProduct` definitions the agent can confirm (NVD CPE dictionary
//! search, CNA string sampling, KEV name lookup, keyword fallback). See
//! docs/research/product-discovery.md section 2.

use anyhow::{Result, bail};
use serde::Serialize;

use super::sources::SourceContext;
use crate::model::TrackedProduct;

/// One proposed definition with the evidence behind it.
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    pub product: TrackedProduct,
    pub score: f64,
    pub live_rows: u32,
    pub cve_count: Option<u64>,
    pub noise_flags: Vec<String>,
}

/// Rank candidates for `query`. Not wired up yet.
pub async fn discover(_ctx: &SourceContext, _query: &str) -> Result<Vec<Candidate>> {
    // TODO(phase 1b/2): CPE dictionary search, scoring, CNA sampling, KEV lookup.
    bail!("discovery not implemented yet")
}
