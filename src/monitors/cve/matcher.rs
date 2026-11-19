//! Links CVEs to tracked products.
//!
//! A CVE matches a product if ANY of: (a) an NVD/ADP/CNA CPE `vendor:product`
//! equals one of the product's `cpes`; (b) a CNA/ADP `(vendor, product)`
//! normalizes into the product's `cna_names` or aliases (squashed or
//! word-boundary prefix, never substring); (c) a KEV row's name matches
//! `kev_names`; (d) a keyword occurs in the description and no
//! `exclude_keywords` do. All affected entries are checked (records are often
//! multi-product).

use crate::model::{CveRecord, TrackedProduct};

/// Why a CVE matched a product; stored in `cve_product_matches.matched_by`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchedBy {
    Cpe,
    CnaName,
    KevName,
    Keyword,
}

impl MatchedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpe => "cpe",
            Self::CnaName => "cna_name",
            Self::KevName => "kev_name",
            Self::Keyword => "keyword",
        }
    }
}

/// Best reason `record` matches `product`, or `None`.
pub fn match_record(_product: &TrackedProduct, _record: &CveRecord) -> Option<MatchedBy> {
    // TODO(phase 1b): implement using monitors::cve::normalize.
    unimplemented!("matcher is a Phase 1b deliverable")
}
