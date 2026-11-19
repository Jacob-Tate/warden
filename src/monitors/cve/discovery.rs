//! Product discovery: turn a plain name ("FortiClient EMS") into candidate
//! `TrackedProduct` definitions an agent can confirm. Algorithm: see
//! docs/research/product-discovery.md section 2.
//!
//! 1. NVD CPE Products API keyword search with name variants (token form,
//!    squashed form, and single tokens only to harvest noise for keyword-only).
//! 2. Aggregate versioned CPE rows into distinct `(part, vendor, product)` with
//!    live / deprecated counts, then score and penalize (hardware, deprecated-only,
//!    third-party "... for X" plugins, suffix variants).
//! 3. Probe the top candidates with the NVD CVE API (`virtualMatchString`) to confirm
//!    CVE linkage (candidates with zero CVEs are dropped) and collect sample CVE ids.
//! 4. Fetch a few sample CVE records from cveawg.mitre.org to learn the CNA's real
//!    vendor/product strings (placeholders such as `n/a` skipped).
//! 5. Look up KEV names locally (token containment, list splitting, initialisms).
//! 6. If nothing is linked to a CVE, propose a keyword-only product with suggested
//!    keywords and `exclude_keywords`.
//!
//! Discovery never saves anything; see [`to_tracked_product`].
//!
//! Network access goes through the [`Net`] trait so tests (and a later cache) can
//! substitute it; [`HttpNet`] is the real implementation with polite rate limiting.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::normalize::{
    is_unknown, is_unknown_product, norm, normalize_vendor, parse_cpe, slugify, split_product_list,
    squash, strip_vendor_prefix, tokens,
};
use crate::db::{Db, DbResult};
use crate::model::{CnaName, CpeRef, KevName, MatchMode, TrackedProduct, now_rfc3339};

pub const NVD_BASE: &str = "https://services.nvd.nist.gov/rest/json";
pub const CVEAWG_BASE: &str = "https://cveawg.mitre.org/api/cve";

/// `warden/<version> (+repo url)`; no personal information.
pub fn user_agent() -> String {
    format!(
        "warden/{} (+https://github.com/Jacob-Tate/warden)",
        env!("CARGO_PKG_VERSION")
    )
}

/// Shared HTTP client with the warden user agent.
pub fn build_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(user_agent())
        .timeout(Duration::from_secs(60))
        .build()?)
}

// ---- result types -----------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CpeCounts {
    pub total: u32,
    pub live: u32,
    pub deprecated: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KevHit {
    pub vendor_project: String,
    pub product: String,
    pub count: u32,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Evidence {
    pub cpe_counts: CpeCounts,
    /// Total CVEs NVD links to the CPE (`None` if not probed).
    pub cve_total: Option<u64>,
    pub sample_cves: Vec<String>,
    pub kev_hits: Vec<KevHit>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    /// Proposed definition, ready for confirmation.
    pub product: TrackedProduct,
    pub score: f64,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryResult {
    pub query: String,
    pub candidates: Vec<Candidate>,
    pub warnings: Vec<String>,
}

impl DiscoveryResult {
    /// Compact JSON for the agent.
    pub fn to_compact_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

/// A distinct KEV `(vendorProject, product)` with its entry count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevRow {
    pub vendor_project: String,
    pub product: String,
    pub count: u32,
}

/// Distinct KEV names from the local `kev` table.
pub fn load_kev_rows(conn: &rusqlite::Connection) -> DbResult<Vec<KevRow>> {
    let mut st = conn.prepare(
        "SELECT COALESCE(vendor_project, ''), COALESCE(product, ''), COUNT(*) \
         FROM kev GROUP BY 1, 2",
    )?;
    let rows = st.query_map([], |r| {
        Ok(KevRow {
            vendor_project: r.get(0)?,
            product: r.get(1)?,
            count: r.get(2)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// What the agent may change when confirming a candidate. `None` keeps the proposal.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Overrides {
    pub id: Option<String>,
    pub name: Option<String>,
    pub cpes: Option<Vec<CpeRef>>,
    pub cna_names: Option<Vec<CnaName>>,
    pub kev_names: Option<Vec<KevName>>,
    pub aliases: Option<Vec<String>>,
    pub keywords: Option<Vec<String>>,
    pub exclude_keywords: Option<Vec<String>>,
    pub match_mode: Option<MatchMode>,
    pub confirmed_by: Option<String>,
}

/// Turn a confirmed candidate (plus the agent's edits) into a product to save.
pub fn to_tracked_product(candidate: &Candidate, o: Overrides) -> TrackedProduct {
    let mut p = candidate.product.clone();
    if let Some(v) = o.id {
        p.id = v;
    }
    if let Some(v) = o.name {
        p.name = v;
    }
    if let Some(v) = o.cpes {
        p.cpes = v;
    }
    if let Some(v) = o.cna_names {
        p.cna_names = v;
    }
    if let Some(v) = o.kev_names {
        p.kev_names = v;
    }
    if let Some(v) = o.aliases {
        p.aliases = v;
    }
    if let Some(v) = o.keywords {
        p.keywords = v;
    }
    if let Some(v) = o.exclude_keywords {
        p.exclude_keywords = v;
    }
    if let Some(v) = o.match_mode {
        p.match_mode = v;
    }
    p.confirmed_by = o.confirmed_by.unwrap_or_else(|| "agent".to_owned());
    let now = now_rfc3339();
    p.created_at = now.clone();
    p.updated_at = now;
    p
}

// ---- network layer ------------------------------------------------------------

/// The three upstream lookups discovery needs. Implemented by [`HttpNet`] and by
/// test mocks.
#[allow(async_fn_in_trait)] // concrete types only
pub trait Net {
    /// NVD CPE Products API 2.0, `keywordSearch`, up to 10000 rows.
    async fn cpe_search(&self, keyword: &str) -> Result<Value>;
    /// NVD CVE API 2.0 with `virtualMatchString=<cpe prefix>&resultsPerPage=5`.
    async fn cve_probe(&self, cpe_prefix: &str) -> Result<Value>;
    /// One CVE record 5.x from cveawg.mitre.org.
    async fn cve_record(&self, cve_id: &str) -> Result<Value>;
}

/// Real HTTP implementation. NVD requests are spaced out (6.2 s without an API
/// key, 0.7 s with one) and retried with backoff on 403/429/503.
pub struct HttpNet {
    client: reqwest::Client,
    nvd_base: String,
    cve_base: String,
    api_key: Option<String>,
    nvd_interval: Duration,
    next_slot: Mutex<Instant>,
}

/// Days of recent CVEs sampled when learning CNA names (NVD's maximum range is 120).
const RECENT_DAYS: i64 = 120;
/// Sample CVEs kept per probed candidate.
const SAMPLE_PAGE: u64 = 5;

/// `pubStartDate` / `pubEndDate` values (UTC, NVD extended ISO format) for the last `days`.
fn recent_window(now: chrono::DateTime<chrono::Utc>, days: i64) -> (String, String) {
    let f = |t: chrono::DateTime<chrono::Utc>| t.format("%Y-%m-%dT%H:%M:%S%.3f").to_string();
    (f(now - chrono::Duration::days(days)), f(now))
}

fn vulnerabilities(page: &Value) -> Vec<Value> {
    page.get("vulnerabilities")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Order NVD `vulnerabilities` entries by `cve.published` descending (id as tie
/// break); entries without a date go last.
fn sort_newest_first(v: &mut [Value]) {
    let key = |x: &Value| {
        (
            x.pointer("/cve/published")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            x.pointer("/cve/id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
        )
    };
    v.sort_by_key(|b| std::cmp::Reverse(key(b)));
}

fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl HttpNet {
    pub fn new(client: reqwest::Client, nvd_api_key: Option<String>) -> Self {
        Self::with_bases(client, nvd_api_key, NVD_BASE, CVEAWG_BASE)
    }

    pub fn with_bases(
        client: reqwest::Client,
        nvd_api_key: Option<String>,
        nvd_base: &str,
        cve_base: &str,
    ) -> Self {
        let interval = if nvd_api_key.is_some() {
            Duration::from_millis(700)
        } else {
            Duration::from_millis(6200)
        };
        Self {
            client,
            nvd_base: nvd_base.trim_end_matches('/').to_owned(),
            cve_base: cve_base.trim_end_matches('/').to_owned(),
            api_key: nvd_api_key,
            nvd_interval: interval,
            next_slot: Mutex::new(Instant::now()),
        }
    }

    /// Override the NVD spacing (tests against a local server use zero).
    pub fn with_interval(mut self, d: Duration) -> Self {
        self.nvd_interval = d;
        self
    }

    async fn wait_slot(&self) {
        let at = {
            let mut next = self.next_slot.lock().unwrap_or_else(|e| e.into_inner());
            let at = (*next).max(Instant::now());
            *next = at + self.nvd_interval;
            at
        };
        tokio::time::sleep_until(at.into()).await;
    }

    async fn get(&self, url: &str, nvd: bool) -> Result<Value> {
        let mut backoff = Duration::from_secs(10);
        for attempt in 0..3 {
            if nvd {
                self.wait_slot().await;
            }
            let mut req = self.client.get(url);
            if nvd && let Some(k) = &self.api_key {
                req = req.header("apiKey", k);
            }
            let resp = req.send().await.with_context(|| format!("GET {url}"))?;
            let status = resp.status();
            if matches!(status.as_u16(), 403 | 429 | 503) && attempt < 2 {
                tracing::warn!(%status, "rate limited, backing off {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff *= 3;
                continue;
            }
            if !status.is_success() {
                let msg = resp
                    .headers()
                    .get("message")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                bail!("GET {url}: HTTP {status} {msg}");
            }
            return resp
                .json::<Value>()
                .await
                .with_context(|| format!("decoding {url}"));
        }
        bail!("GET {url}: gave up after retries")
    }
}

impl Net for HttpNet {
    async fn cpe_search(&self, keyword: &str) -> Result<Value> {
        let url = format!(
            "{}/cpes/2.0?keywordSearch={}&resultsPerPage=10000",
            self.nvd_base,
            pct(keyword)
        );
        self.get(&url, true).await
    }

    async fn cve_probe(&self, cpe_prefix: &str) -> Result<Value> {
        let base = format!(
            "{}/cves/2.0?virtualMatchString={}",
            self.nvd_base,
            pct(cpe_prefix)
        );
        // 1. Total count only.
        let head = self.get(&format!("{base}&resultsPerPage=1"), true).await?;
        let total = head
            .get("totalResults")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if total == 0 {
            return Ok(head);
        }
        // 2. Recently published CVEs (NVD caps a date range at 120 days). The oldest
        // records of a CPE say "n/a" for vendor/product, so they teach nothing.
        let (start, end) = recent_window(chrono::Utc::now(), RECENT_DAYS);
        let mut vulns = match self
            .get(
                &format!("{base}&pubStartDate={start}&pubEndDate={end}&resultsPerPage=20"),
                true,
            )
            .await
        {
            Ok(v) => vulnerabilities(&v),
            Err(e) => {
                tracing::debug!("recent CVE window query failed: {e:#}");
                vec![]
            }
        };
        // 3. Nothing recent: the last page of the unfiltered list.
        if vulns.is_empty() {
            let from = total.saturating_sub(SAMPLE_PAGE);
            let page = self
                .get(
                    &format!("{base}&startIndex={from}&resultsPerPage={SAMPLE_PAGE}"),
                    true,
                )
                .await?;
            vulns = vulnerabilities(&page);
        }
        sort_newest_first(&mut vulns);
        vulns.truncate(SAMPLE_PAGE as usize);
        Ok(serde_json::json!({
            "totalResults": total,
            "vulnerabilities": vulns,
        }))
    }

    async fn cve_record(&self, cve_id: &str) -> Result<Value> {
        // cveawg has no published strict limit; stay polite anyway.
        tokio::time::sleep(Duration::from_millis(250)).await;
        self.get(&format!("{}/{}", self.cve_base, pct(cve_id)), false)
            .await
    }
}

// ---- aggregation & scoring (pure) ---------------------------------------------

/// Distinct `(part, vendor, product)` aggregated from versioned CPE rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpeAgg {
    pub part: String,
    pub vendor: String,
    pub product: String,
    pub counts: CpeCounts,
    pub title: Option<String>,
    /// Other CPE parts the same vendor:product also appears under (merged in).
    pub other_parts: Vec<String>,
}

fn strip_version_from_title(t: &str) -> String {
    let mut parts: Vec<&str> = t.split_whitespace().collect();
    while parts.len() > 1
        && parts
            .last()
            .is_some_and(|l| *l == "-" || l.chars().next().is_some_and(|c| c.is_ascii_digit()))
    {
        parts.pop();
    }
    parts.join(" ")
}

/// Aggregate pages of NVD CPE API output (rows seen twice, e.g. in two query
/// variants, are counted once).
pub fn aggregate_cpes(pages: &[Value]) -> Vec<CpeAgg> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut map: BTreeMap<(String, String, String), CpeAgg> = BTreeMap::new();
    for page in pages {
        let Some(rows) = page.get("products").and_then(Value::as_array) else {
            continue;
        };
        for row in rows {
            let Some(cpe) = row.get("cpe") else { continue };
            let Some(name) = cpe.get("cpeName").and_then(Value::as_str) else {
                continue;
            };
            if !seen.insert(name) {
                continue;
            }
            let Some(parsed) = parse_cpe(name) else {
                continue;
            };
            let deprecated = cpe
                .get("deprecated")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let key = (
                parsed.part.clone(),
                parsed.vendor.clone(),
                parsed.product.clone(),
            );
            let e = map.entry(key).or_insert_with(|| CpeAgg {
                part: parsed.part.clone(),
                vendor: parsed.vendor.clone(),
                product: parsed.product.clone(),
                counts: CpeCounts::default(),
                title: None,
                other_parts: vec![],
            });
            e.counts.total += 1;
            if deprecated {
                e.counts.deprecated += 1;
            } else {
                e.counts.live += 1;
                e.title = None.or(e.title.take()).or_else(|| first_title(cpe));
            }
            if e.title.is_none() {
                e.title = first_title(cpe);
            }
        }
    }
    merge_parts(map.into_values().collect())
}

/// Merge entries that share `vendor:product` but differ in CPE part (`a`/`o`/`h`):
/// matching keys on vendor:product only, so one candidate is enough. The part
/// with the most live rows (then `a` over `o` over `h`) is kept as `part`; the
/// rest are listed in `other_parts` and counts are summed.
fn merge_parts(aggs: Vec<CpeAgg>) -> Vec<CpeAgg> {
    let mut groups: BTreeMap<(String, String), Vec<CpeAgg>> = BTreeMap::new();
    for a in aggs {
        groups
            .entry((a.vendor.clone(), a.product.clone()))
            .or_default()
            .push(a);
    }
    groups
        .into_values()
        .map(|mut g| {
            let rank = |p: &str| match p {
                "a" => 0,
                "o" => 1,
                _ => 2,
            };
            g.sort_by(|x, y| {
                y.counts
                    .live
                    .cmp(&x.counts.live)
                    .then(rank(&x.part).cmp(&rank(&y.part)))
            });
            let mut it = g.into_iter();
            let mut main = it.next().expect("non-empty group");
            for o in it {
                main.counts.total += o.counts.total;
                main.counts.live += o.counts.live;
                main.counts.deprecated += o.counts.deprecated;
                if main.title.is_none() {
                    main.title = o.title.clone();
                }
                if !main.other_parts.contains(&o.part) {
                    main.other_parts.push(o.part);
                }
            }
            main
        })
        .collect()
}

fn first_title(cpe: &Value) -> Option<String> {
    cpe.get("titles")?
        .as_array()?
        .iter()
        .find(|t| t.get("lang").and_then(Value::as_str) == Some("en"))
        .or_else(|| cpe.get("titles")?.as_array()?.first())?
        .get("title")?
        .as_str()
        .map(strip_version_from_title)
}

/// Query in the comparison forms the scorer uses.
#[derive(Debug, Clone)]
pub struct QueryForms {
    pub norm: String,
    pub tokens: Vec<String>,
    pub squash: String,
}

impl QueryForms {
    pub fn new(q: &str) -> Self {
        Self {
            norm: norm(q),
            tokens: tokens(q),
            squash: squash(q),
        }
    }
}

/// Score one aggregated CPE product against the query; returns the score and the
/// human-readable reasons (used as evidence notes).
pub fn score_cpe(agg: &CpeAgg, q: &QueryForms) -> (f64, Vec<String>) {
    let mut score = 0.0;
    let mut notes = Vec::new();
    let pnorm = norm(&agg.product);
    let psq = squash(&agg.product);
    let vnorm = normalize_vendor(&agg.vendor);
    let vsq = squash(&vnorm);
    let ptoks = tokens(&agg.product);
    let vtoks = tokens(&vnorm);
    let in_q = |t: &String| q.tokens.contains(t);
    let product_in_q = !ptoks.is_empty() && ptoks.iter().all(in_q);
    let vendor_in_q = !vtoks.is_empty() && vtoks.iter().all(in_q);

    let exact = psq == q.squash;
    if exact {
        score += 10.0;
        notes.push("product name equals query".into());
    } else if format!("{vsq}{psq}") == q.squash || (product_in_q && vendor_in_q) {
        score += 8.0;
        notes.push("query contains vendor and product".into());
    } else if product_in_q {
        score += 5.0;
        notes.push("product words are a subset of the query".into());
    }
    if let Some(title) = &agg.title {
        let tn = norm(title);
        if q.tokens.iter().all(|t| tn.split(' ').any(|w| w == t)) || squash(&tn).contains(&q.squash)
        {
            score += 3.0;
        }
    }
    score += f64::from(agg.counts.live + 1).log2();

    if agg.part == "h" {
        score -= 5.0;
        notes.push(
            "hardware CPE (per-model entries); software is usually a separate 'o'/'a' product"
                .into(),
        );
    }
    if !exact && !q.squash.is_empty() && psq.starts_with(&q.squash) {
        score -= 4.0;
        notes.push("suffix variant of the query (sibling product)".into());
    }
    if agg.counts.live == 0 {
        // Always rank below any live product, however well the name matches.
        score = score.min(0.0) - 8.0;
        notes.push("deprecated-only: every CPE row is deprecated".into());
    }
    let words: Vec<&str> = pnorm.split(' ').collect();
    let title_norm = agg.title.as_deref().map(norm).unwrap_or_default();
    let for_q = |hay: &str| {
        let w: Vec<&str> = hay.split(' ').collect();
        w.iter().enumerate().any(|(i, x)| {
            *x == "for"
                && w[i + 1..]
                    .iter()
                    .take(3)
                    .any(|t| q.tokens.iter().any(|qt| qt == t))
        })
    };
    if (words.len() > 1 && for_q(&pnorm)) || for_q(&title_norm) {
        score -= 6.0;
        notes.push("looks like a third-party plugin 'for <query>'".into());
    }
    (score, notes)
}

// ---- sampling CNA strings & KEV ---------------------------------------------------

fn product_relates(product: &str, cand_vendor: &str, cand_product: &str) -> bool {
    let target = squash(cand_product);
    let vnorm = normalize_vendor(cand_vendor);
    let mut segs = vec![norm(product)];
    segs.extend(split_product_list(product).iter().map(|s| norm(s)));
    segs.iter()
        .any(|s| squash(s) == target || squash(&strip_vendor_prefix(&vnorm, s)) == target)
}

/// Pull `(vendor, product, assigner)` strings that refer to `cand` out of one
/// CVE record 5.x. ADP entries only count when their CPE names the candidate.
pub fn learn_cna_names(record: &Value, cand: &CpeAgg) -> Vec<CnaName> {
    let assigner = record
        .pointer("/cveMetadata/assignerShortName")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut out = Vec::new();
    let mut scan = |affected: Option<&Value>, trust_names: bool| {
        for e in affected.and_then(Value::as_array).into_iter().flatten() {
            let vendor = e.get("vendor").and_then(Value::as_str).unwrap_or("");
            let product = e
                .get("product")
                .and_then(Value::as_str)
                .or_else(|| e.get("packageName").and_then(Value::as_str))
                .unwrap_or("");
            if is_unknown_product(product) {
                continue;
            }
            let cpe_hit = e
                .get("cpes")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter_map(parse_cpe)
                .any(|c| c.vendor == cand.vendor && c.product == cand.product);
            if cpe_hit || (trust_names && product_relates(product, &cand.vendor, &cand.product)) {
                out.push(CnaName {
                    vendor: if is_unknown(vendor) {
                        String::new()
                    } else {
                        vendor.to_owned()
                    },
                    product: product.to_owned(),
                    source_cna: assigner.clone(),
                });
            }
        }
    };
    scan(record.pointer("/containers/cna/affected"), true);
    for adp in record
        .pointer("/containers/adp")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        scan(adp.get("affected"), false);
    }
    out
}

/// KEV rows that belong to a CPE candidate: vendor agrees (cpe vendor or any learned
/// CNA vendor) and some list segment of the KEV product equals the candidate's
/// product, a learned CNA product, or its initialism (`Extensible Operating System`
/// ~ `eos`).
pub fn kev_hits_for_cpe(kev: &[KevRow], cand: &CpeAgg, cna: &[CnaName]) -> Vec<KevHit> {
    let mut vendors: HashSet<String> = HashSet::new();
    vendors.insert(squash(&normalize_vendor(&cand.vendor)));
    for c in cna.iter().filter(|c| !c.vendor.is_empty()) {
        vendors.insert(squash(&normalize_vendor(&c.vendor)));
    }
    let vnorm = normalize_vendor(&cand.vendor);
    let mut targets: HashSet<String> = HashSet::new();
    targets.insert(squash(&cand.product));
    for c in cna {
        targets.insert(squash(&strip_vendor_prefix(&vnorm, &norm(&c.product))));
        targets.insert(squash(&c.product));
    }
    let mut hits = Vec::new();
    for row in kev {
        if is_unknown_product(&row.product) {
            continue;
        }
        let rv = squash(&normalize_vendor(&row.vendor_project));
        if !vendors.contains(&rv) {
            continue;
        }
        let mut segs = vec![norm(&row.product)];
        segs.extend(split_product_list(&row.product).iter().map(|s| norm(s)));
        let ok = segs.iter().any(|s| {
            let stripped = strip_vendor_prefix(&normalize_vendor(&row.vendor_project), s);
            let toks: Vec<&str> = stripped.split(' ').collect();
            let initials: String = toks.iter().filter_map(|t| t.chars().next()).collect();
            targets.contains(&squash(s))
                || targets.contains(&squash(&stripped))
                || (toks.len() >= 3 && targets.contains(&initials))
        });
        if ok {
            hits.push(KevHit {
                vendor_project: row.vendor_project.clone(),
                product: row.product.clone(),
                count: row.count,
            });
        }
    }
    hits.sort_by(|a, b| b.count.cmp(&a.count).then(a.product.cmp(&b.product)));
    hits
}

/// KEV rows for a keyword-only product: all query tokens occur in vendor+product.
fn kev_hits_for_query(kev: &[KevRow], q: &QueryForms) -> Vec<KevHit> {
    if q.tokens.is_empty() {
        return Vec::new();
    }
    kev.iter()
        .filter(|r| {
            let hay = norm(&format!("{} {}", r.vendor_project, r.product));
            let words: Vec<&str> = hay.split(' ').collect();
            q.tokens.iter().all(|t| words.contains(&t.as_str())) || squash(&hay).contains(&q.squash)
        })
        .map(|r| KevHit {
            vendor_project: r.vendor_project.clone(),
            product: r.product.clone(),
            count: r.count,
        })
        .collect()
}

// ---- orchestration -----------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DiscoverOptions {
    /// Candidates returned at most.
    pub max_candidates: usize,
    /// How many top candidates are probed against the CVE API.
    pub probe_top: usize,
    /// Sample CVE records fetched per probed candidate.
    pub sample_cves: usize,
}

impl Default for DiscoverOptions {
    fn default() -> Self {
        Self {
            max_candidates: 5,
            probe_top: 3,
            sample_cves: 3,
        }
    }
}

fn cpe_prefix(c: &CpeAgg) -> String {
    let esc = |s: &str| s.replace('\\', "\\\\").replace(':', "\\:");
    format!("cpe:2.3:{}:{}:{}", c.part, esc(&c.vendor), esc(&c.product))
}

fn blank_product(id: String, name: String) -> TrackedProduct {
    TrackedProduct {
        id,
        name,
        cpes: vec![],
        cna_names: vec![],
        kev_names: vec![],
        aliases: vec![],
        keywords: vec![],
        exclude_keywords: vec![],
        match_mode: MatchMode::CpeNames,
        confirmed_by: "discovery".into(),
        created_at: String::new(),
        updated_at: String::new(),
    }
}

fn title_case(s: &str) -> String {
    s.split(['_', ' '])
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut c = w.chars();
            c.next()
                .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Distinct vendors in noisy CPE rows, as exclusion-keyword suggestions.
fn noise_vendors(aggs: &[CpeAgg], q: &QueryForms) -> Vec<String> {
    let mut count: HashMap<String, u32> = HashMap::new();
    for a in aggs {
        let v = normalize_vendor(&a.vendor);
        if v.contains(' ') || v.len() < 3 || q.tokens.contains(&v) {
            continue;
        }
        *count.entry(v).or_default() += a.counts.total;
    }
    let mut v: Vec<(String, u32)> = count.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.into_iter().take(6).map(|x| x.0).collect()
}

/// Run discovery for `query`. `kev` is the local KEV name table ([`load_kev_rows`]).
pub async fn discover_with<N: Net>(
    net: &N,
    kev: &[KevRow],
    query: &str,
    opts: &DiscoverOptions,
) -> Result<DiscoveryResult> {
    let query = query.trim();
    if query.is_empty() {
        bail!("empty product name");
    }
    let q = QueryForms::new(query);
    if q.tokens.is_empty() {
        bail!("product name has no letters or digits");
    }
    let mut warnings: Vec<String> = Vec::new();

    // 1. CPE dictionary search: token form, then squashed form.
    let mut pages: Vec<Value> = Vec::new();
    let mut variants = vec![q.norm.clone()];
    if q.tokens.len() > 1 {
        variants.push(q.squash.clone());
    }
    for v in &variants {
        match net.cpe_search(v).await {
            Ok(page) => {
                if page
                    .get("totalResults")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    > 10_000
                {
                    warnings.push(format!(
                        "CPE search '{v}' has more than 10000 rows; results truncated"
                    ));
                }
                pages.push(page);
            }
            Err(e) => warnings.push(format!("CPE search '{v}' failed: {e:#}")),
        }
    }
    let mut aggs = aggregate_cpes(&pages);
    if pages.is_empty() {
        bail!(
            "NVD CPE search failed: {}",
            warnings.last().cloned().unwrap_or_default()
        );
    }

    // Noise harvest for the keyword-only path: single tokens, only when nothing found.
    let mut noise: Vec<CpeAgg> = Vec::new();
    if aggs.is_empty() {
        let mut toks: Vec<&String> = q.tokens.iter().filter(|t| t.len() >= 3).collect();
        toks.sort_by_key(|t| std::cmp::Reverse(t.len()));
        for t in toks.into_iter().take(2) {
            match net.cpe_search(t).await {
                Ok(page) => noise.extend(aggregate_cpes(&[page])),
                Err(e) => warnings.push(format!("noise search '{t}' failed: {e:#}")),
            }
        }
    }

    // 2. Score.
    let mut scored: Vec<(CpeAgg, f64, Vec<String>)> = aggs
        .drain(..)
        .map(|a| {
            let (s, n) = score_cpe(&a, &q);
            (a, s, n)
        })
        .collect();
    let by_score = |a: &(CpeAgg, f64, Vec<String>), b: &(CpeAgg, f64, Vec<String>)| {
        b.1.total_cmp(&a.1)
            .then(b.0.counts.live.cmp(&a.0.counts.live))
            .then(a.0.product.cmp(&b.0.product))
    };
    scored.sort_by(by_score);

    // 3-4. Probe the top candidates, then sample CNA strings.
    let mut kept: Vec<(CpeAgg, f64, Evidence, Vec<CnaName>)> = Vec::new();
    for (i, (agg, score, notes)) in scored.into_iter().enumerate() {
        let mut ev = Evidence {
            cpe_counts: agg.counts.clone(),
            notes,
            ..Default::default()
        };
        if let Some(t) = &agg.title {
            ev.notes.push(format!("CPE title: {t}"));
        }
        if !agg.other_parts.is_empty() {
            ev.notes.push(format!(
                "also listed under CPE part(s): {} (merged)",
                agg.other_parts.join(", ")
            ));
        }
        let mut score = score;
        let mut cna: Vec<CnaName> = Vec::new();
        if i < opts.probe_top {
            match net.cve_probe(&cpe_prefix(&agg)).await {
                Ok(v) => {
                    let total = v.get("totalResults").and_then(Value::as_u64).unwrap_or(0);
                    if total == 0 {
                        warnings.push(format!(
                            "dropped {}:{} ({}): no CVE references this CPE",
                            agg.vendor, agg.product, agg.part
                        ));
                        continue;
                    }
                    ev.cve_total = Some(total);
                    score += ((total + 1) as f64).log2().min(10.0) / 2.0;
                    ev.sample_cves = v
                        .get("vulnerabilities")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|x| x.pointer("/cve/id").and_then(Value::as_str))
                        .map(str::to_owned)
                        .take(opts.sample_cves)
                        .collect();
                }
                Err(e) => warnings.push(format!(
                    "CVE probe for {}:{} failed: {e:#}",
                    agg.vendor, agg.product
                )),
            }
            let mut learned: BTreeMap<(String, String), (CnaName, u32)> = BTreeMap::new();
            for id in &ev.sample_cves {
                match net.cve_record(id).await {
                    Ok(rec) => {
                        for n in learn_cna_names(&rec, &agg) {
                            let key = (n.vendor.to_lowercase(), squash(&n.product));
                            learned.entry(key).or_insert((n, 0)).1 += 1;
                        }
                    }
                    Err(e) => warnings.push(format!("fetching {id} failed: {e:#}")),
                }
            }
            let mut l: Vec<(CnaName, u32)> = learned.into_values().collect();
            l.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.product.cmp(&b.0.product)));
            cna = l.into_iter().map(|x| x.0).take(5).collect();
        } else {
            ev.notes.push("not probed against the CVE API".into());
        }
        kept.push((agg, score, ev, cna));
    }
    kept.sort_by(|a, b| b.1.total_cmp(&a.1));

    // 5. Assemble candidates (+ KEV) or fall back to keywords.
    let mut candidates: Vec<Candidate> = Vec::new();
    let extra = kept.len().saturating_sub(opts.max_candidates);
    for (agg, score, mut ev, cna) in kept.into_iter().take(opts.max_candidates) {
        let exact = squash(&agg.product) == q.squash
            || format!(
                "{}{}",
                squash(&normalize_vendor(&agg.vendor)),
                squash(&agg.product)
            ) == q.squash;
        let name = if exact {
            query.to_owned()
        } else {
            agg.title
                .clone()
                .unwrap_or_else(|| title_case(&agg.product))
        };
        let mut p = blank_product(slugify(&name), name);
        p.cpes = vec![CpeRef {
            part: agg.part.clone(),
            vendor: agg.vendor.clone(),
            product: agg.product.clone(),
            note: Some(format!(
                "NVD, {} entries ({} live)",
                agg.counts.total, agg.counts.live
            )),
        }];
        ev.kev_hits = kev_hits_for_cpe(kev, &agg, &cna);
        p.kev_names = ev
            .kev_hits
            .iter()
            .map(|h| KevName {
                vendor_project: h.vendor_project.clone(),
                product: h.product.clone(),
            })
            .collect();
        if ev.cve_total.is_some() && cna.is_empty() {
            ev.notes
                .push("no CNA strings learned from the sample CVEs (CPE/KEV matching only)".into());
        }
        p.cna_names = cna;
        if exact && q.norm != norm(&agg.product) && q.norm != squash(&agg.product) {
            p.aliases.push(q.norm.clone());
        }
        candidates.push(Candidate {
            product: p,
            score: (score * 100.0).round() / 100.0,
            evidence: ev,
        });
    }
    if extra > 0 {
        warnings.push(format!("{extra} lower-ranked candidates omitted"));
    }
    // Disambiguate ids.
    let mut seen: HashMap<String, usize> = HashMap::new();
    for c in &mut candidates {
        let n = seen.entry(c.product.id.clone()).or_default();
        *n += 1;
        if *n > 1 {
            c.product.id = format!("{}-{}", c.product.id, slugify(&c.product.cpes[0].product));
        }
    }

    if candidates.is_empty() {
        candidates.push(keyword_candidate(query, &q, kev, &noise));
        warnings.push(
            "no CPE linked to any CVE was found; proposing a keyword-only product (matching \
             by description text). Review keywords/exclude_keywords before saving."
                .into(),
        );
    } else if candidates.len() > 1 && candidates[0].score - candidates[1].score < 2.0 {
        warnings.push("top candidates score closely: ambiguous, ask the user which one".into());
    }

    Ok(DiscoveryResult {
        query: query.to_owned(),
        candidates,
        warnings,
    })
}

fn keyword_candidate(query: &str, q: &QueryForms, kev: &[KevRow], noise: &[CpeAgg]) -> Candidate {
    let mut p = blank_product(slugify(query), query.to_owned());
    p.match_mode = MatchMode::Keyword;
    let mut kw = vec![query.to_lowercase()];
    if q.squash != squash(&query.to_lowercase()) || q.tokens.len() > 1 {
        kw.push(q.squash.clone());
    }
    kw.dedup();
    p.keywords = kw;
    p.exclude_keywords = noise_vendors(noise, q);
    let hits = kev_hits_for_query(kev, q);
    p.kev_names = hits
        .iter()
        .map(|h| KevName {
            vendor_project: h.vendor_project.clone(),
            product: h.product.clone(),
        })
        .collect();
    let mut notes = vec![
        "no CPE with CVE linkage: matching by whole-word keywords in CVE descriptions".into(),
        "exclude_keywords are vendors of unrelated CPE products found by a trial search".into(),
    ];
    if q.tokens.len() == 1 && q.squash.len() < 5 {
        notes.push("short single-word keyword: expect false positives".into());
    }
    Candidate {
        product: p,
        score: 1.0,
        evidence: Evidence {
            kev_hits: hits,
            notes,
            ..Default::default()
        },
    }
}

/// Discover using the real network and the local KEV table.
pub async fn discover(
    db: &Db,
    client: reqwest::Client,
    nvd_api_key: Option<String>,
    query: &str,
) -> Result<DiscoveryResult> {
    let kev = db.call(|c| load_kev_rows(c)).await?;
    let net = HttpNet::new(client, nvd_api_key);
    discover_with(&net, &kev, query, &DiscoverOptions::default()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORTICLIENT: &str =
        include_str!("../../../tests/fixtures/discovery/cpes_forticlientems.json");
    const GRAFANA: &str = include_str!("../../../tests/fixtures/discovery/cpes_grafana.json");
    const NGINX: &str = include_str!("../../../tests/fixtures/discovery/cpes_nginx.json");
    const FORTIGATE: &str = include_str!("../../../tests/fixtures/discovery/cpes_fortigate.json");
    const PROBE: &str =
        include_str!("../../../tests/fixtures/discovery/cves_probe_forticlientems.json");
    const RECORD: &str =
        include_str!("../../../tests/fixtures/discovery/cveawg_CVE-2026-21643.json");

    fn j(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    fn ranked(fixture: &str, query: &str) -> Vec<(String, f64)> {
        let q = QueryForms::new(query);
        let mut v: Vec<(String, f64)> = aggregate_cpes(&[j(fixture)])
            .iter()
            .map(|a| {
                (
                    format!("{}:{}:{}", a.part, a.vendor, a.product),
                    score_cpe(a, &q).0,
                )
            })
            .collect();
        v.sort_by(|a, b| b.1.total_cmp(&a.1));
        v
    }

    #[test]
    fn aggregates_counts_and_dedupes_rows() {
        let page = j(FORTICLIENT);
        let aggs = aggregate_cpes(&[page.clone(), page]);
        assert_eq!(aggs.len(), 2);
        let ems = aggs.iter().find(|a| a.product == "forticlientems").unwrap();
        assert_eq!(
            ems.counts,
            CpeCounts {
                total: 3,
                live: 3,
                deprecated: 0
            }
        );
        assert_eq!(ems.title.as_deref(), Some("Fortinet FortiClientEMS"));

        let n = aggregate_cpes(&[j(NGINX)]);
        let dep = n.iter().find(|a| a.vendor == "nginx").unwrap();
        assert_eq!((dep.counts.live, dep.counts.deprecated), (0, 2));
    }

    #[test]
    fn forticlient_ems_prefers_exact_over_cloud_sibling() {
        let r = ranked(FORTICLIENT, "FortiClient EMS");
        assert_eq!(r[0].0, "a:fortinet:forticlientems");
        assert!(r[0].1 - r[1].1 > 3.0, "{r:?}");
    }

    #[test]
    fn grafana_prefers_core_product_over_siblings() {
        let r = ranked(GRAFANA, "Grafana");
        assert_eq!(r[0].0, "a:grafana:grafana");
        assert!(r.iter().skip(1).all(|x| x.1 < r[0].1), "{r:?}");
    }

    #[test]
    fn nginx_penalizes_deprecated_only_and_suffix_variants() {
        let r = ranked(NGINX, "nginx");
        assert_eq!(r[0].0, "a:f5:nginx");
        let score = |k: &str| r.iter().find(|x| x.0 == k).unwrap().1;
        assert!(
            score("a:nginx:nginx") < score("a:f5:nginx_open_source"),
            "{r:?}"
        );
        assert!(score("a:f5:nginx_open_source") < score("a:f5:nginx"));
    }

    #[test]
    fn hardware_is_penalized() {
        let q = QueryForms::new("fortigate");
        let a = &aggregate_cpes(&[j(FORTIGATE)])[0];
        let (_, notes) = score_cpe(a, &q);
        assert!(notes.iter().any(|n| n.contains("hardware")));
    }

    #[test]
    fn third_party_plugin_is_penalized() {
        let q = QueryForms::new("docker");
        let mk = |vendor: &str, product: &str, title: &str| CpeAgg {
            part: "a".into(),
            vendor: vendor.into(),
            product: product.into(),
            counts: CpeCounts {
                total: 10,
                live: 10,
                deprecated: 0,
            },
            title: Some(title.into()),
            other_parts: vec![],
        };
        let real = score_cpe(&mk("docker", "docker", "Docker"), &q).0;
        let plugin = score_cpe(&mk("amirraminfar", "dozzle", "Dozzle for Docker"), &q);
        assert!(plugin.1.iter().any(|n| n.contains("third-party")));
        assert!(plugin.0 < real - 8.0);
    }

    #[test]
    fn learns_cna_strings_and_skips_na() {
        let aggs = aggregate_cpes(&[j(FORTICLIENT)]);
        let cand = aggs.iter().find(|a| a.product == "forticlientems").unwrap();
        let names = learn_cna_names(&j(RECORD), cand);
        assert_eq!(
            names,
            vec![CnaName {
                vendor: "Fortinet".into(),
                product: "FortiClientEMS".into(),
                source_cna: Some("fortinet".into()),
            }]
        );
        let rec = serde_json::json!({"cveMetadata":{"assignerShortName":"cisco"},
            "containers":{"cna":{"affected":[
              {"vendor":"n/a","product":"Cisco IOS and IOS XE"},
              {"vendor":"n/a","product":"n/a"}]}}});
        let ios = CpeAgg {
            part: "o".into(),
            vendor: "cisco".into(),
            product: "ios_xe".into(),
            counts: CpeCounts::default(),
            title: None,
            other_parts: vec![],
        };
        let names = learn_cna_names(&rec, &ios);
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].vendor, "");
        assert_eq!(names[0].product, "Cisco IOS and IOS XE");
    }

    fn kev_rows() -> Vec<KevRow> {
        let k = |v: &str, p: &str, c| KevRow {
            vendor_project: v.into(),
            product: p.into(),
            count: c,
        };
        vec![
            k("Fortinet", "FortiClient EMS", 3),
            k("Fortinet", "FortiOS", 9),
            k("Fortinet", "FortiOS and FortiProxy", 4),
            k("Fortinet", "Multiple Products", 7),
            k("Arista", "Extensible Operating System", 1),
            k("Arista", "VeloCloud Orchestrator", 3),
            k("Grafana Labs", "Grafana", 2),
        ]
    }

    #[test]
    fn kev_hits_use_containment_lists_and_initialisms() {
        let mk = |part: &str, v: &str, p: &str| CpeAgg {
            part: part.into(),
            vendor: v.into(),
            product: p.into(),
            counts: CpeCounts::default(),
            title: None,
            other_parts: vec![],
        };
        let ems = kev_hits_for_cpe(&kev_rows(), &mk("a", "fortinet", "forticlientems"), &[]);
        assert_eq!(ems.len(), 1);
        assert_eq!(ems[0].product, "FortiClient EMS");
        let os = kev_hits_for_cpe(&kev_rows(), &mk("o", "fortinet", "fortios"), &[]);
        let names: Vec<&str> = os.iter().map(|h| h.product.as_str()).collect();
        assert_eq!(names, ["FortiOS", "FortiOS and FortiProxy"]);
        let eos = kev_hits_for_cpe(&kev_rows(), &mk("o", "arista", "eos"), &[]);
        assert_eq!(eos.len(), 1);
        assert_eq!(eos[0].product, "Extensible Operating System");
        let g = kev_hits_for_cpe(&kev_rows(), &mk("a", "grafana", "grafana"), &[]);
        assert_eq!(g[0].vendor_project, "Grafana Labs");
    }

    struct MockNet {
        cpe: HashMap<String, Value>,
        probe: Value,
        record: Value,
        calls: Mutex<Vec<String>>,
    }
    impl Net for MockNet {
        async fn cpe_search(&self, k: &str) -> Result<Value> {
            self.calls.lock().unwrap().push(format!("cpe:{k}"));
            Ok(self
                .cpe
                .get(k)
                .cloned()
                .unwrap_or_else(|| serde_json::json!({"totalResults":0,"products":[]})))
        }
        async fn cve_probe(&self, p: &str) -> Result<Value> {
            self.calls.lock().unwrap().push(format!("probe:{p}"));
            if p.ends_with("forticlientems") {
                Ok(self.probe.clone())
            } else {
                Ok(serde_json::json!({"totalResults":0,"vulnerabilities":[]}))
            }
        }
        async fn cve_record(&self, id: &str) -> Result<Value> {
            self.calls.lock().unwrap().push(format!("record:{id}"));
            Ok(self.record.clone())
        }
    }

    fn mock() -> MockNet {
        MockNet {
            cpe: HashMap::from([
                ("forticlientems".to_owned(), j(FORTICLIENT)),
                (
                    "xcp".to_owned(),
                    serde_json::json!({"totalResults":2,"products":[
                        {"cpe":{"deprecated":false,"cpeName":"cpe:2.3:h:fujitsu:m10-1_xcp:*:*:*:*:*:*:*:*","titles":[{"title":"Fujitsu M10-1 XCP","lang":"en"}]}},
                        {"cpe":{"deprecated":false,"cpeName":"cpe:2.3:a:emc:documentum_xcp:1.0:*:*:*:*:*:*:*","titles":[{"title":"EMC Documentum xCP 1.0","lang":"en"}]}}
                    ]}),
                ),
            ]),
            probe: j(PROBE),
            record: j(RECORD),
            calls: Mutex::new(vec![]),
        }
    }

    #[tokio::test]
    async fn end_to_end_with_mock_network() {
        let net = mock();
        let r = discover_with(
            &net,
            &kev_rows(),
            "FortiClient EMS",
            &DiscoverOptions::default(),
        )
        .await
        .unwrap();
        let top = &r.candidates[0];
        assert_eq!(top.product.cpes[0].product, "forticlientems");
        assert_eq!(top.product.name, "FortiClient EMS");
        assert_eq!(top.product.id, "forticlient-ems");
        assert_eq!(top.product.match_mode, MatchMode::CpeNames);
        assert_eq!(top.evidence.cve_total, Some(9));
        assert_eq!(top.evidence.sample_cves.len(), 3);
        assert_eq!(top.product.cna_names[0].product, "FortiClientEMS");
        assert_eq!(top.product.kev_names.len(), 1);
        assert_eq!(top.product.kev_names[0].product, "FortiClient EMS");
        // cloud sibling had 0 probe hits and was dropped
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("forticlientems_cloud"))
        );
        // both query variants were searched
        let calls = net.calls.lock().unwrap().clone();
        assert!(calls.contains(&"cpe:forticlient ems".to_owned()));
        assert!(calls.contains(&"cpe:forticlientems".to_owned()));

        let json = r.to_compact_json().unwrap();
        assert!(!json.contains('\n') && json.contains("\"sample_cves\""));

        let tp = to_tracked_product(
            top,
            Overrides {
                keywords: Some(vec!["forticlient ems".into()]),
                ..Default::default()
            },
        );
        assert_eq!(tp.keywords, ["forticlient ems"]);
        assert_eq!(tp.confirmed_by, "agent");
        assert!(!tp.created_at.is_empty());
    }

    #[tokio::test]
    async fn keyword_only_fallback_with_noise_excludes() {
        let net = mock();
        let r = discover_with(&net, &kev_rows(), "XCP-ng", &DiscoverOptions::default())
            .await
            .unwrap();
        assert_eq!(r.candidates.len(), 1);
        let c = &r.candidates[0];
        assert_eq!(c.product.match_mode, MatchMode::Keyword);
        assert!(c.product.keywords.contains(&"xcp-ng".to_owned()));
        assert!(c.product.keywords.contains(&"xcpng".to_owned()));
        assert!(c.product.exclude_keywords.contains(&"fujitsu".to_owned()));
        assert!(c.product.exclude_keywords.contains(&"emc".to_owned()));
        assert!(r.warnings.iter().any(|w| w.contains("keyword-only")));
    }

    #[test]
    fn merges_same_vendor_product_across_parts() {
        let page = serde_json::json!({"products": [
            {"cpe": {"cpeName": "cpe:2.3:a:grafana:grafana:9.0.0:*:*:*:*:*:*:*", "deprecated": false,
                     "titles": [{"lang": "en", "title": "Grafana 9.0.0"}]}},
            {"cpe": {"cpeName": "cpe:2.3:a:grafana:grafana:9.1.0:*:*:*:*:*:*:*", "deprecated": false}},
            {"cpe": {"cpeName": "cpe:2.3:o:grafana:grafana:1.0:*:*:*:*:*:*:*", "deprecated": false}},
        ]});
        let aggs = aggregate_cpes(&[page]);
        assert_eq!(aggs.len(), 1, "{aggs:?}");
        assert_eq!(aggs[0].part, "a");
        assert_eq!(aggs[0].other_parts, ["o"]);
        assert_eq!(aggs[0].counts.total, 3);
        assert_eq!(aggs[0].counts.live, 3);
    }

    #[test]
    fn recent_window_is_120_days_back() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-19T12:30:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let (a, b) = recent_window(now, 120);
        assert_eq!(b, "2026-11-19T12:30:00.000");
        assert_eq!(a, "2026-07-22T12:30:00.000");
    }

    #[test]
    fn samples_newest_cves_first() {
        let mut v = vec![
            serde_json::json!({"cve": {"id": "CVE-2010-0001", "published": "2010-01-01T00:00:00.000"}}),
            serde_json::json!({"cve": {"id": "CVE-2026-0002", "published": "2026-10-01T00:00:00.000"}}),
            serde_json::json!({"cve": {"id": "CVE-2026-0003", "published": "2026-11-01T00:00:00.000"}}),
            serde_json::json!({"cve": {"id": "CVE-1999-0001"}}),
        ];
        sort_newest_first(&mut v);
        let ids: Vec<&str> = v.iter().map(|x| x["cve"]["id"].as_str().unwrap()).collect();
        assert_eq!(
            ids,
            [
                "CVE-2026-0003",
                "CVE-2026-0002",
                "CVE-2010-0001",
                "CVE-1999-0001"
            ]
        );
    }

    /// Serve canned JSON bodies in order on a local port; returns the base URL and
    /// the request lines seen.
    async fn canned_server(bodies: Vec<String>) -> (String, std::sync::Arc<Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            for body in bodies {
                let (mut s, _) = l.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                seen2
                    .lock()
                    .unwrap()
                    .push(req.lines().next().unwrap_or("").to_owned());
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                s.write_all(resp.as_bytes()).await.unwrap();
            }
        });
        (base, seen)
    }

    #[tokio::test]
    async fn http_probe_prefers_recent_window_then_last_page() {
        let head = r#"{"totalResults":40,"vulnerabilities":[]}"#.to_owned();
        let recent = r#"{"totalResults":2,"vulnerabilities":[
            {"cve":{"id":"CVE-2026-1","published":"2026-09-01T00:00:00.000"}},
            {"cve":{"id":"CVE-2026-2","published":"2026-10-01T00:00:00.000"}}]}"#
            .to_owned();
        let (base, seen) = canned_server(vec![head.clone(), recent]).await;
        let net = HttpNet::with_bases(reqwest::Client::new(), None, &base, &base)
            .with_interval(Duration::ZERO);
        let v = net.cve_probe("cpe:2.3:a:x:y").await.unwrap();
        assert_eq!(v["totalResults"], 40);
        assert_eq!(v["vulnerabilities"][0]["cve"]["id"], "CVE-2026-2");
        let lines = seen.lock().unwrap().clone();
        assert!(lines[0].contains("resultsPerPage=1 "), "{lines:?}");
        assert!(lines[1].contains("pubStartDate=") && lines[1].contains("pubEndDate="));

        // Empty window: falls back to the last page (startIndex = total - 5).
        let last = r#"{"totalResults":40,"vulnerabilities":[
            {"cve":{"id":"CVE-2012-9","published":"2012-01-01T00:00:00.000"}}]}"#
            .to_owned();
        let empty = r#"{"totalResults":0,"vulnerabilities":[]}"#.to_owned();
        let (base, seen) = canned_server(vec![head, empty, last]).await;
        let net = HttpNet::with_bases(reqwest::Client::new(), None, &base, &base)
            .with_interval(Duration::ZERO);
        let v = net.cve_probe("cpe:2.3:a:x:y").await.unwrap();
        assert_eq!(v["vulnerabilities"][0]["cve"]["id"], "CVE-2012-9");
        assert!(seen.lock().unwrap()[2].contains("startIndex=35"));
    }

    #[test]
    fn percent_encoding() {
        assert_eq!(pct("cpe:2.3:a:x y"), "cpe%3A2.3%3Aa%3Ax%20y");
    }

    /// Live network test: `cargo test live_discovery -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "hits NVD / cveawg / CISA over the network and takes about a minute"]
    async fn live_discovery() {
        let client = build_client().unwrap();
        // KEV catalog straight from CISA (the sync sources are not used here).
        let kev_json: Value = client
            .get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let mut counts: BTreeMap<(String, String), u32> = BTreeMap::new();
        for v in kev_json["vulnerabilities"].as_array().unwrap() {
            let k = (
                v["vendorProject"].as_str().unwrap_or("").to_owned(),
                v["product"].as_str().unwrap_or("").to_owned(),
            );
            *counts.entry(k).or_default() += 1;
        }
        let kev: Vec<KevRow> = counts
            .into_iter()
            .map(|((vendor_project, product), count)| KevRow {
                vendor_project,
                product,
                count,
            })
            .collect();
        let net = HttpNet::new(client, std::env::var("NVD_API_KEY").ok());
        for name in ["Grafana", "FortiClient EMS"] {
            let t = Instant::now();
            let r = discover_with(&net, &kev, name, &DiscoverOptions::default())
                .await
                .unwrap();
            println!("== {name}: {:.1}s", t.elapsed().as_secs_f32());
            println!("{}", serde_json::to_string_pretty(&r).unwrap());
            assert!(!r.candidates.is_empty());
        }
    }
}
