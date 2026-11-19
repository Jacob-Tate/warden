//! Shared domain types. Timestamps are RFC 3339 UTC strings.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Current time as an RFC 3339 UTC string with millisecond precision.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchMode {
    /// Structured match (CPE and normalized CNA/KEV names), plus keywords if given.
    #[serde(rename = "cpe+names")]
    CpeNames,
    /// Keyword-only (products with no CPE / CNA footprint).
    #[serde(rename = "keyword")]
    Keyword,
}

impl MatchMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CpeNames => "cpe+names",
            Self::Keyword => "keyword",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cpe+names" => Some(Self::CpeNames),
            "keyword" => Some(Self::Keyword),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpeRef {
    pub part: String,
    pub vendor: String,
    pub product: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnaName {
    pub vendor: String,
    pub product: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_cna: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KevName {
    pub vendor_project: String,
    pub product: String,
}

/// A product the user wants CVEs for (shape from docs/research/product-discovery.md).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackedProduct {
    pub id: String,
    pub name: String,
    pub cpes: Vec<CpeRef>,
    pub cna_names: Vec<CnaName>,
    pub kev_names: Vec<KevName>,
    pub aliases: Vec<String>,
    pub keywords: Vec<String>,
    pub exclude_keywords: Vec<String>,
    pub match_mode: MatchMode,
    pub confirmed_by: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Which source a CVSS score / affected entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CvssSource {
    Cna,
    Adp,
    Nvd,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cvss {
    pub score: f64,
    pub vector: Option<String>,
    /// "3.1", "4.0", ...
    pub version: String,
    pub source: CvssSource,
    /// NVD only: true when issued by nvd@nist.gov (Primary), false for Secondary.
    #[serde(default)]
    pub primary: bool,
}

/// One affected-product entry flattened for matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Affected {
    pub source: CvssSource,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub cpe: Option<String>,
    /// Raw CNA/NVD version objects.
    pub versions: serde_json::Value,
}

/// Normalized CVE record merged from cvelist (CNA + ADP) and NVD.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CveRecord {
    pub cve_id: String,
    pub state: String,
    pub assigner: Option<String>,
    pub description: String,
    pub published: Option<String>,
    pub last_modified: String,
    pub nvd_status: Option<String>,
    pub cvss: Vec<Cvss>,
    pub affected: Vec<Affected>,
    pub ssvc_exploitation: Option<String>,
    pub fixed_versions: Vec<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KevEntry {
    pub cve_id: String,
    pub vendor_project: String,
    pub product: String,
    pub name: String,
    pub date_added: String,
    pub due_date: Option<String>,
    pub ransomware: bool,
    pub first_seen_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EpssScore {
    pub cve_id: String,
    pub score: f64,
    pub percentile: f64,
    pub score_date: String,
}

/// What a consumer acknowledged for a (cve, product), captured at that time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Delivered {
    pub consumer: String,
    pub cve_id: String,
    pub product_id: String,
    pub delivered_at: String,
    pub acked_at: Option<String>,
    pub snapshot_cvss: Option<f64>,
    pub snapshot_kev: bool,
    pub snapshot_state: Option<String>,
}

/// Persisted per-source sync state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceStatus {
    pub source: String,
    /// Source-specific cursor, opaque JSON.
    pub cursor: Option<String>,
    pub etag: Option<String>,
    pub last_attempt: Option<String>,
    pub last_success: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    New,
    KevAdded,
    CvssChanged,
    /// Published before the product was tracked (inside the backfill window).
    Backfill,
    /// The CVE was rejected after it was delivered.
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedItem {
    pub cve: String,
    /// Tracked product display name.
    pub product: String,
    pub published: Option<String>,
    pub cvss: Option<f64>,
    pub cvss_source: Option<CvssSource>,
    pub severity: Option<String>,
    pub kev: bool,
    pub epss: Option<f64>,
    pub change: Change,
    /// At most 200 chars, cut at a word boundary (ends with an ellipsis if cut).
    pub summary: String,
    pub fixed_versions: Vec<String>,
    pub source_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceHealth {
    pub last_success: Option<String>,
    pub last_error: Option<String>,
    pub stale: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedEnvelope {
    pub generated_at: String,
    pub items: Vec<FeedItem>,
    /// Matching items that did not fit under `limit`.
    pub more: usize,
    /// True if a core source (cvelist, kev) is stale: the feed may be missing news.
    pub stale: bool,
    pub health: BTreeMap<String, SourceHealth>,
}
