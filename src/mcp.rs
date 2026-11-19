//! MCP server: rmcp 3.11 stateless streamable HTTP (JSON responses), mounted at
//! `/mcp` by `http::router`. One `Warden` handler is built per request by the
//! service factory; shared state lives behind `Arc`s.
//!
//! User mistakes (bad ids, unknown products, rate limits) come back as tool
//! results with `isError: true` and a message the model can act on, never as
//! protocol errors.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use chrono::Utc;
use regex::Regex;
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, tool::Extension, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::never::NeverSessionManager,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::{
    auth::Principal,
    config::Config,
    db::Db,
    model::{CnaName, CpeRef, KevName, MatchMode, TrackedProduct},
    monitors::cve::{
        discovery::{
            self, Candidate, DiscoverOptions, DiscoveryResult, Evidence, HttpNet, Overrides,
        },
        feed::{self, FeedOptions},
        sync::Syncer,
        tracked::{self, UserError},
    },
};

/// Discovery can take ~25 s without an NVD key (rate-limited requests); cap it.
pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(60);
/// A cached discovery result is reused by `add_tracked` for this long.
const DISCOVERY_TTL: Duration = Duration::from_secs(15 * 60);
/// `trigger_sync` refuses when a pass started less than this long ago.
pub const SYNC_COOLDOWN: Duration = Duration::from_secs(5 * 60);
/// NVD lookups for a single CVE id.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_ACK_IDS: usize = 500;
/// Discovery results kept in memory (oldest evicted first).
const MAX_DISCOVERY_CACHE: usize = 32;

const INSTRUCTIONS: &str = "\
warden is a CVE feed for the software the user runs. Typical loop: call get_new_cves, summarize \
the items for the user (KEV and high CVSS first; `change` says why an item is listed again), then \
call ack with the cve_ids you handled so they are not repeated. Fetching never consumes; only ack \
does. Use cve_detail for the full record of one CVE. To track new software: call discover_product \
first, review the candidates (and warnings), then add_tracked with the chosen candidate_index and \
any overrides; discovery can take up to a minute. list_tracked shows what is tracked, \
update_tracked/remove_tracked change it. sync_status shows data freshness; trigger_sync starts a \
background refresh (at most once per 5 minutes).";

type DiscoveryCache = HashMap<String, (Instant, Arc<DiscoveryResult>)>;

/// Shared dependencies of every tool call.
#[derive(Clone)]
pub struct McpDeps {
    pub db: Db,
    pub syncer: Arc<Syncer>,
    pub config: Arc<Config>,
    net: Arc<HttpNet>,
    discoveries: Arc<Mutex<DiscoveryCache>>,
    last_trigger: Arc<Mutex<Option<Instant>>>,
}

impl McpDeps {
    pub fn new(db: Db, syncer: Arc<Syncer>, config: Arc<Config>) -> anyhow::Result<Self> {
        let net = HttpNet::new(discovery::build_client()?, config.nvd_api_key.clone());
        Ok(Self {
            db,
            syncer,
            config,
            net: Arc::new(net),
            discoveries: Default::default(),
            last_trigger: Default::default(),
        })
    }
}

/// Hosts and origins accepted on `/mcp`, derived from `WARDEN_PUBLIC_URL`.
pub fn allowed_hosts_and_origins(public_url: &str) -> (Vec<String>, Vec<String>) {
    let mut hosts: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    let mut origins: Vec<String> = vec![
        "https://claude.ai:443".into(),
        "http://localhost:*".into(),
        "http://127.0.0.1:*".into(),
    ];
    if let Ok(uri) = public_url.parse::<axum::http::Uri>()
        && let Some(auth) = uri.authority()
    {
        // Host without a port matches any port; keep the port out so a proxy that
        // forwards `Host: name:443` or plain `name` both work.
        hosts.push(auth.host().to_owned());
        let scheme = uri.scheme_str().unwrap_or("https");
        let port = auth
            .port_u16()
            .unwrap_or(if scheme == "http" { 80 } else { 443 });
        origins.push(format!("{scheme}://{}:{port}", auth.host()));
    }
    (hosts, origins)
}

/// The streamable-HTTP tower service for `/mcp`.
pub fn service(
    deps: McpDeps,
    ct: CancellationToken,
) -> StreamableHttpService<Warden, NeverSessionManager> {
    let (hosts, origins) = allowed_hosts_and_origins(&deps.config.public_url);
    let cfg = StreamableHttpServerConfig::default()
        .with_allowed_hosts(hosts)
        .with_allowed_origins(origins)
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_max_request_body_bytes(1024 * 1024)
        .with_cancellation_token(ct);
    StreamableHttpService::new(
        move || Ok(Warden::new(deps.clone())),
        NeverSessionManager::default().into(),
        cfg,
    )
}

// ---- parameter types ------------------------------------------------------------------

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct GetNewCvesParams {
    /// Reader identity with its own ack cursor. Omit to use the name of the API key in use.
    consumer: Option<String>,
    /// Maximum items to return (default 50, max 200).
    limit: Option<usize>,
    /// Only this tracked product (id or name).
    product: Option<String>,
    /// Only items with a CVSS score at or above this (0-10).
    min_cvss: Option<f64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct AckParams {
    /// Reader identity (omit to use the API key's name; must match what get_new_cves used).
    consumer: Option<String>,
    /// CVE ids to mark as seen, e.g. ["CVE-2026-1234"].
    cve_ids: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CveDetailParams {
    /// A CVE id such as CVE-2026-21643.
    cve_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DiscoverParams {
    /// Product name as the user says it, e.g. "FortiClient EMS" or "nginx".
    name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CpeIn {
    /// CPE part: "a" (application), "o" (OS) or "h" (hardware).
    part: String,
    vendor: String,
    product: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CnaIn {
    vendor: String,
    product: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct KevIn {
    vendor_project: String,
    product: String,
}

#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
enum MatchModeIn {
    /// Structured matching (CPE, CNA and KEV names), plus keywords if given.
    #[serde(rename = "cpe+names")]
    CpeNames,
    /// Match whole-word keywords in CVE descriptions only.
    #[serde(rename = "keyword")]
    Keyword,
}

/// Edits applied on top of a discovery candidate (or the existing product). Omitted
/// fields keep their current value; a given list replaces the whole list.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
struct OverridesIn {
    /// Display name.
    name: Option<String>,
    cpes: Option<Vec<CpeIn>>,
    /// Vendor/product strings as CNAs write them in CVE records.
    cna_names: Option<Vec<CnaIn>>,
    /// CISA KEV vendorProject/product names.
    kev_names: Option<Vec<KevIn>>,
    aliases: Option<Vec<String>>,
    /// Whole-word phrases matched in CVE descriptions.
    keywords: Option<Vec<String>>,
    /// Phrases that veto a keyword match.
    exclude_keywords: Option<Vec<String>>,
    match_mode: Option<MatchModeIn>,
}

impl OverridesIn {
    fn into_overrides(self, confirmed_by: &str) -> Overrides {
        Overrides {
            id: None,
            name: self.name,
            cpes: self.cpes.map(|v| {
                v.into_iter()
                    .map(|c| CpeRef {
                        part: c.part,
                        vendor: c.vendor,
                        product: c.product,
                        note: None,
                    })
                    .collect()
            }),
            cna_names: self.cna_names.map(|v| {
                v.into_iter()
                    .map(|c| CnaName {
                        vendor: c.vendor,
                        product: c.product,
                        source_cna: None,
                    })
                    .collect()
            }),
            kev_names: self.kev_names.map(|v| {
                v.into_iter()
                    .map(|k| KevName {
                        vendor_project: k.vendor_project,
                        product: k.product,
                    })
                    .collect()
            }),
            aliases: self.aliases,
            keywords: self.keywords,
            exclude_keywords: self.exclude_keywords,
            match_mode: self.match_mode.map(|m| match m {
                MatchModeIn::CpeNames => MatchMode::CpeNames,
                MatchModeIn::Keyword => MatchMode::Keyword,
            }),
            confirmed_by: Some(confirmed_by.to_owned()),
        }
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct AddTrackedParams {
    /// Product name, the same text given to discover_product.
    name: String,
    /// Which discovery candidate to save (0-based, default 0).
    candidate_index: Option<usize>,
    /// Edits to the chosen candidate. For a fully manual add (discovery found nothing
    /// usable) give cpes and/or keywords here.
    overrides: Option<OverridesIn>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct UpdateTrackedParams {
    /// Tracked product id (see list_tracked).
    id: String,
    #[serde(flatten)]
    fields: OverridesIn,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RemoveTrackedParams {
    /// Tracked product id (see list_tracked).
    id: String,
}

// ---- helpers ------------------------------------------------------------------------------

fn cve_id_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^CVE-\d{4}-\d{4,}$").expect("valid regex"))
}

/// Normalize and validate a CVE id (trim, upper-case).
fn parse_cve_id(s: &str) -> Result<String, String> {
    let id = s.trim().to_uppercase();
    if cve_id_re().is_match(&id) {
        Ok(id)
    } else {
        Err(format!(
            "`{s}` is not a CVE id; expected the form CVE-YYYY-NNNN (e.g. CVE-2026-21643)"
        ))
    }
}

fn ok_json<T: Serialize>(v: &T) -> Result<CallToolResult, McpError> {
    match serde_json::to_string(v) {
        Ok(s) => Ok(CallToolResult::success(vec![ContentBlock::text(s)])),
        Err(e) => Err(McpError::internal_error(
            format!("serializing result: {e}"),
            None,
        )),
    }
}

fn user_err(msg: impl Into<String>) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::error(vec![ContentBlock::text(msg.into())]))
}

/// Short random reference shown to the caller and written to the log with the full error.
fn error_id() -> String {
    let mut b = [0u8; 4];
    if getrandom::fill(&mut b).is_err() {
        b = std::process::id().to_le_bytes();
    }
    crate::auth::hex(&b)
}

/// An internal failure: the caller gets a generic message plus a reference id, the log
/// gets the full cause chain under the same id. Input mistakes ([`UserError`]) keep their
/// specific message.
fn internal_err(what: &str, e: &anyhow::Error) -> Result<CallToolResult, McpError> {
    if let Some(u) = e.downcast_ref::<UserError>() {
        return user_err(u.0.clone());
    }
    let id = error_id();
    tracing::error!(error_id = %id, "{what}: {e:#}");
    user_err(format!(
        "{what} failed because of an internal error (ref {id}); the details are in the server log. Try again shortly."
    ))
}

fn principal_name(parts: &axum::http::request::Parts) -> Option<String> {
    parts.extensions.get::<Principal>().map(|p| p.name.clone())
}

/// `^[a-zA-Z0-9._:-]{1,64}$`: what a consumer (ack cursor) name may look like.
fn valid_consumer(c: &str) -> bool {
    (1..=64).contains(&c.len())
        && c.chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':' | '-'))
}

/// The consumer (ack cursor) for a call: the explicit name, else the authenticated
/// principal (`<api key name>` or `oauth:<label>`), else `default`.
///
/// An explicit name is accepted as given, so any authenticated caller can read or move
/// another consumer's cursor. That is deliberate for a single-user server (all callers are
/// the owner); it is not a security boundary.
fn resolve_consumer(explicit: Option<String>, principal: Option<String>) -> Result<String, String> {
    let c = explicit
        .map(|c| c.trim().to_owned())
        .filter(|c| !c.is_empty())
        .or(principal)
        .unwrap_or_else(|| "default".to_owned());
    if !valid_consumer(&c) {
        return Err("consumer must be 1-64 characters from letters, digits and . _ : -".into());
    }
    Ok(c)
}

// ---- the server --------------------------------------------------------------------------------

#[derive(Clone)]
pub struct Warden {
    deps: McpDeps,
    tool_router: ToolRouter<Warden>,
}

impl Warden {
    pub fn new(deps: McpDeps) -> Self {
        Self {
            deps,
            tool_router: Self::tool_router(),
        }
    }

    /// Discovery with a ~15 minute in-memory cache and an overall timeout.
    async fn discover_cached(&self, name: &str) -> anyhow::Result<Arc<DiscoveryResult>> {
        let key = name.trim().to_lowercase();
        {
            let mut c = self
                .deps
                .discoveries
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            c.retain(|_, (t, _)| t.elapsed() < DISCOVERY_TTL);
            if let Some((_, r)) = c.get(&key) {
                return Ok(r.clone());
            }
        }
        let kev = self.deps.db.call(|c| discovery::load_kev_rows(c)).await?;
        let opts = DiscoverOptions::default();
        let run = discovery::discover_with(self.deps.net.as_ref(), &kev, name, &opts);
        let r = tokio::time::timeout(DISCOVERY_TIMEOUT, run)
            .await
            .map_err(|_| {
                anyhow::Error::new(UserError(format!(
                    "discovery timed out after {}s (NVD is slow or rate limiting); try again shortly",
                    DISCOVERY_TIMEOUT.as_secs()
                )))
            })??;
        let r = Arc::new(r);
        {
            let mut c = self
                .deps
                .discoveries
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            cache_insert(&mut c, key, r.clone());
        }
        Ok(r)
    }
}

/// Insert into the discovery cache, evicting the oldest entries beyond [`MAX_DISCOVERY_CACHE`].
fn cache_insert(c: &mut DiscoveryCache, key: String, r: Arc<DiscoveryResult>) {
    c.insert(key, (Instant::now(), r));
    while c.len() > MAX_DISCOVERY_CACHE {
        let Some(oldest) = c
            .iter()
            .min_by_key(|(_, (t, _))| *t)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        c.remove(&oldest);
    }
}

#[derive(Serialize)]
struct DiscoveryOut<'a> {
    query: &'a str,
    candidates: Vec<IndexedCandidate<'a>>,
    warnings: &'a [String],
}

#[derive(Serialize)]
struct IndexedCandidate<'a> {
    index: usize,
    #[serde(flatten)]
    candidate: &'a Candidate,
}

#[tool_router]
impl Warden {
    #[tool(
        description = "List CVEs that are new or changed for this consumer and not yet acknowledged, ranked KEV first then by CVSS. Returns {items, more, stale, health}. Each item has cve, product, cvss, severity, kev, epss, change (new|backfill|kev_added|cvss_changed|rejected), summary, fixed_versions. Does not consume anything (it only remembers what it showed, so the ack covers exactly that): call ack afterwards.",
        annotations(read_only_hint = false, idempotent_hint = true)
    )]
    async fn get_new_cves(
        &self,
        Extension(parts): Extension<axum::http::request::Parts>,
        Parameters(p): Parameters<GetNewCvesParams>,
    ) -> Result<CallToolResult, McpError> {
        let consumer = match resolve_consumer(p.consumer, principal_name(&parts)) {
            Ok(c) => c,
            Err(m) => return user_err(m),
        };
        if p.min_cvss.is_some_and(|m| !(0.0..=10.0).contains(&m)) {
            return user_err("min_cvss must be between 0 and 10");
        }
        let opts = FeedOptions {
            limit: p.limit.unwrap_or(feed::DEFAULT_LIMIT),
            product: p.product,
            min_cvss: p.min_cvss,
            include_acked: false,
            backfill_days: self.deps.config.backfill_days,
        };
        match feed::get_new(&self.deps.db, &consumer, &opts).await {
            Ok(env) => ok_json(&env),
            Err(e) => internal_err("reading the feed", &e),
        }
    }

    #[tool(
        description = "Mark CVEs as seen so get_new_cves stops returning them (they come back only if they enter CISA KEV, their CVSS changes materially, or they are rejected). Call after you have summarized the items."
    )]
    async fn ack(
        &self,
        Extension(parts): Extension<axum::http::request::Parts>,
        Parameters(p): Parameters<AckParams>,
    ) -> Result<CallToolResult, McpError> {
        let consumer = match resolve_consumer(p.consumer, principal_name(&parts)) {
            Ok(c) => c,
            Err(m) => return user_err(m),
        };
        if p.cve_ids.is_empty() {
            return user_err("cve_ids is empty");
        }
        if p.cve_ids.len() > MAX_ACK_IDS {
            return user_err(format!("at most {MAX_ACK_IDS} ids per call"));
        }
        let mut ids = Vec::with_capacity(p.cve_ids.len());
        for s in &p.cve_ids {
            match parse_cve_id(s) {
                Ok(id) => ids.push(id),
                Err(m) => return user_err(m),
            }
        }
        match feed::ack(&self.deps.db, &consumer, &ids).await {
            Ok(n) => ok_json(&json!({"acked": n, "consumer": consumer})),
            Err(e) => internal_err("ack", &e),
        }
    }

    #[tool(
        description = "Full record of one CVE: all CVSS scores with sources, affected products, KEV and EPSS data, SSVC, references and which tracked products it matches. Unknown ids are looked up in NVD.",
        annotations(read_only_hint = true)
    )]
    async fn cve_detail(
        &self,
        Parameters(p): Parameters<CveDetailParams>,
    ) -> Result<CallToolResult, McpError> {
        let id = match parse_cve_id(&p.cve_id) {
            Ok(id) => id,
            Err(m) => return user_err(m),
        };
        let fut = feed::cve_detail(&self.deps.syncer.ctx, &self.deps.syncer.nvd_api.api, &id);
        match tokio::time::timeout(LOOKUP_TIMEOUT, fut).await {
            Err(_) => user_err(format!("looking up {id} timed out; try again shortly")),
            Ok(Ok(Some(v))) => ok_json(&v),
            Ok(Ok(None)) => user_err(format!("{id} is not known locally or to NVD")),
            Ok(Err(e)) => internal_err("cve_detail", &e),
        }
    }

    #[tool(
        description = "List tracked products with id, name, matching definition (cpes, cna_names, kev_names, keywords...) and how many CVEs currently match each.",
        annotations(read_only_hint = true)
    )]
    async fn list_tracked(&self) -> Result<CallToolResult, McpError> {
        match tracked::list(&self.deps.db).await {
            Ok(v) => ok_json(&v),
            Err(e) => internal_err("list_tracked", &e),
        }
    }

    #[tool(
        description = "Look a product name up in NVD's CPE dictionary, CISA KEV and sample CVEs and propose tracking definitions. Returns candidates (each with an index, score, evidence and a ready definition) and warnings. Read them with the user when ambiguous, then call add_tracked. Slow: up to about a minute without an NVD key.",
        annotations(read_only_hint = true)
    )]
    async fn discover_product(
        &self,
        Parameters(p): Parameters<DiscoverParams>,
    ) -> Result<CallToolResult, McpError> {
        if let Err(m) = check_name(&p.name) {
            return user_err(m);
        }
        match self.discover_cached(&p.name).await {
            Ok(r) => ok_json(&DiscoveryOut {
                query: &r.query,
                candidates: r
                    .candidates
                    .iter()
                    .enumerate()
                    .map(|(index, candidate)| IndexedCandidate { index, candidate })
                    .collect(),
                warnings: &r.warnings,
            }),
            Err(e) => internal_err("discovery", &e),
        }
    }

    #[tool(
        description = "Start tracking a product. Runs discovery for `name` (or reuses a result from the last 15 minutes), saves candidate `candidate_index` (default 0) with your `overrides`, and matches it against stored CVEs. Returns the saved product and the initial match count. If discovery finds nothing usable, give overrides.cpes and/or overrides.keywords for a manual add. Old CVEs are not flooded into the feed: only the last backfill window counts as new."
    )]
    async fn add_tracked(
        &self,
        Extension(parts): Extension<axum::http::request::Parts>,
        Parameters(p): Parameters<AddTrackedParams>,
    ) -> Result<CallToolResult, McpError> {
        let name = p.name.trim().to_owned();
        if let Err(m) = check_name(&name) {
            return user_err(m);
        }
        let who = principal_name(&parts).unwrap_or_else(|| "agent".into());
        let ov = p.overrides.unwrap_or_default();
        let manual_input = ov.cpes.as_ref().is_some_and(|c| !c.is_empty())
            || ov.keywords.as_ref().is_some_and(|k| !k.is_empty());
        let overrides = ov.into_overrides(&who);
        if let Err(e) = tracked::validate_overrides(&overrides) {
            return user_err(e.0);
        }
        let (candidate, note) = match self.discover_cached(&name).await {
            Ok(r) => match r.candidates.get(p.candidate_index.unwrap_or(0)) {
                Some(c) => (c.clone(), None),
                None => {
                    return user_err(format!(
                        "candidate_index {} is out of range ({} candidates)",
                        p.candidate_index.unwrap_or(0),
                        r.candidates.len()
                    ));
                }
            },
            Err(e) if manual_input => {
                let id = error_id();
                tracing::warn!(error_id = %id, "add_tracked: discovery failed, saving manually: {e:#}");
                (
                    blank_candidate(&name, overrides.cpes.is_some()),
                    Some(format!("discovery failed (ref {id}); saved manually")),
                )
            }
            Err(e) => {
                if e.downcast_ref::<UserError>().is_some() {
                    return user_err(format!(
                        "{e}. Retry later, or pass overrides.cpes / overrides.keywords to add the product manually."
                    ));
                }
                return internal_err(
                    "discovery (retry later, or pass overrides.cpes / overrides.keywords to add the product manually)",
                    &e,
                );
            }
        };
        let res = tracked::add_candidate(
            &self.deps.syncer.ctx,
            Some(&self.deps.syncer.nvd_api.api),
            &candidate,
            overrides,
            self.deps.config.backfill_days,
        )
        .await;
        match res {
            Ok(r) => {
                let mut v = serde_json::to_value(&r).unwrap_or_default();
                if let Some(n) = note {
                    v["note"] = json!(n);
                }
                ok_json(&v)
            }
            Err(e) => internal_err("saving the product", &e),
        }
    }

    #[tool(
        description = "Change a tracked product's definition. Only the fields you pass change; a list replaces the whole list. The product is re-matched against stored CVEs. Use list_tracked for ids."
    )]
    async fn update_tracked(
        &self,
        Extension(parts): Extension<axum::http::request::Parts>,
        Parameters(p): Parameters<UpdateTrackedParams>,
    ) -> Result<CallToolResult, McpError> {
        let who = principal_name(&parts).unwrap_or_else(|| "agent".into());
        let overrides = p.fields.into_overrides(&who);
        if let Err(e) = tracked::validate_overrides(&overrides) {
            return user_err(e.0);
        }
        let res = tracked::update(
            &self.deps.syncer.ctx,
            Some(&self.deps.syncer.nvd_api.api),
            &p.id,
            overrides,
            self.deps.config.backfill_days,
        )
        .await;
        match res {
            Ok(Some(r)) => ok_json(&r),
            Ok(None) => user_err(format!(
                "no tracked product with id `{}`; call list_tracked for the ids",
                p.id
            )),
            Err(e) => internal_err("updating the product", &e),
        }
    }

    #[tool(
        description = "Stop tracking a product and delete its matches and acknowledgements. Irreversible.",
        annotations(destructive_hint = true)
    )]
    async fn remove_tracked(
        &self,
        Parameters(p): Parameters<RemoveTrackedParams>,
    ) -> Result<CallToolResult, McpError> {
        match tracked::remove(&self.deps.db, &p.id).await {
            Ok(true) => ok_json(&json!({"removed": p.id})),
            Ok(false) => user_err(format!(
                "no tracked product with id `{}`; call list_tracked for the ids",
                p.id
            )),
            Err(e) => internal_err("remove_tracked", &e),
        }
    }

    #[tool(
        description = "Data freshness: per-source last success/error and staleness (cvelist, nvd_feed, kev, epss), whether a sync is running now, and the last sync run's summary line.",
        annotations(read_only_hint = true)
    )]
    async fn sync_status(&self) -> Result<CallToolResult, McpError> {
        let now = Utc::now();
        let health = self
            .deps
            .db
            .call(move |c| feed::source_health(c, now))
            .await;
        let health = match health {
            Ok(h) => h,
            Err(e) => return internal_err("sync_status", &e.into()),
        };
        let stale = ["cvelist", "kev"]
            .iter()
            .any(|s| health.get(*s).is_none_or(|h| h.stale));
        let s = &self.deps.syncer;
        ok_json(&json!({
            "stale": stale,
            "running": s.is_running(),
            "last_run": s.last_run().map(|r| json!({
                "started_at": r.started_at.to_rfc3339(),
                "finished_at": r.finished_at.to_rfc3339(),
                "ok": r.ok,
                "summary": r.line,
            })),
            "sources": health,
        }))
    }

    #[tool(
        description = "Start a full data sync in the background and return immediately; poll sync_status. Refused if a sync started less than 5 minutes ago (the scheduler already syncs periodically)."
    )]
    async fn trigger_sync(&self) -> Result<CallToolResult, McpError> {
        let s = &self.deps.syncer;
        if s.is_running() {
            return user_err("a sync is already running; check sync_status");
        }
        {
            let mut last = self
                .deps
                .last_trigger
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let recent_manual = last.is_some_and(|t| t.elapsed() < SYNC_COOLDOWN);
            let recent_any = s.last_started().is_some_and(|t| {
                Utc::now() - t < chrono::Duration::from_std(SYNC_COOLDOWN).unwrap_or_default()
            });
            if recent_manual || recent_any {
                return user_err(
                    "a sync ran less than 5 minutes ago; data is as fresh as it gets. See sync_status.",
                );
            }
            *last = Some(Instant::now());
        }
        let syncer = s.clone();
        tokio::spawn(async move {
            syncer.trigger_sync().await;
        });
        ok_json(&json!({"started": true, "hint": "poll sync_status for the result"}))
    }
}

fn check_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("name is empty".into());
    }
    if name.chars().count() > tracked::MAX_NAME_CHARS {
        return Err(format!(
            "name is too long (max {} characters)",
            tracked::MAX_NAME_CHARS
        ));
    }
    Ok(())
}

fn blank_candidate(name: &str, has_cpes: bool) -> Candidate {
    use crate::monitors::cve::normalize::slugify;
    Candidate {
        product: TrackedProduct {
            id: slugify(name),
            name: name.to_owned(),
            cpes: vec![],
            cna_names: vec![],
            kev_names: vec![],
            aliases: vec![],
            keywords: vec![],
            exclude_keywords: vec![],
            match_mode: if has_cpes {
                MatchMode::CpeNames
            } else {
                MatchMode::Keyword
            },
            confirmed_by: "manual".into(),
            created_at: String::new(),
            updated_at: String::new(),
        },
        score: 0.0,
        evidence: Evidence::default(),
    }
}

#[tool_handler]
impl ServerHandler for Warden {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("warden", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cve_id_validation() {
        assert_eq!(parse_cve_id(" cve-2026-21643 ").unwrap(), "CVE-2026-21643");
        assert!(parse_cve_id("CVE-26-1").is_err());
        assert!(parse_cve_id("CVE-2026-123").is_err());
        assert!(parse_cve_id("CVE-2026-1234; DROP").is_err());
        assert!(parse_cve_id("../etc").is_err());
    }

    #[test]
    fn consumer_defaults_to_principal() {
        assert_eq!(resolve_consumer(None, Some("key".into())).unwrap(), "key");
        assert_eq!(
            resolve_consumer(Some("x".into()), Some("key".into())).unwrap(),
            "x"
        );
        assert_eq!(
            resolve_consumer(Some("  ".into()), None).unwrap(),
            "default"
        );
        assert!(resolve_consumer(Some("a".repeat(65)), None).is_err());
        // charset: letters, digits and . _ : -
        for ok in ["claude-ai", "oauth:routine.1", "k_2", "A"] {
            assert_eq!(resolve_consumer(Some(ok.into()), None).unwrap(), ok);
        }
        for bad in ["a b", "x\u{7}", "a/b", "caf\u{e9}", "<x>", "a;b", "a\nb"] {
            assert!(resolve_consumer(Some(bad.into()), None).is_err(), "{bad:?}");
        }
        // a derived principal is checked too
        assert!(resolve_consumer(None, Some("bad name".into())).is_err());
    }

    #[test]
    fn internal_errors_are_generic_but_user_errors_are_specific() {
        let text = |r: Result<CallToolResult, McpError>| {
            serde_json::to_string(&r.unwrap().content).unwrap()
        };
        let secret = anyhow::anyhow!("open /srv/warden/data/warden.db: disk I/O error")
            .context("sql: SELECT secret FROM t");
        let out = text(internal_err("reading the feed", &secret));
        assert!(
            out.contains("ref ") && out.contains("internal error"),
            "{out}"
        );
        assert!(!out.contains("/srv") && !out.contains("SELECT"), "{out}");
        let u = anyhow::Error::new(UserError("candidate 3 is out of range".into()));
        assert!(text(internal_err("x", &u)).contains("candidate 3 is out of range"));
    }

    #[test]
    fn discovery_cache_is_bounded_oldest_first() {
        let mut c = DiscoveryCache::new();
        let r = || {
            Arc::new(DiscoveryResult {
                query: String::new(),
                candidates: vec![],
                warnings: vec![],
            })
        };
        for i in 0..(MAX_DISCOVERY_CACHE + 10) {
            cache_insert(&mut c, format!("k{i}"), r());
        }
        assert_eq!(c.len(), MAX_DISCOVERY_CACHE);
        assert!(!c.contains_key("k0") && c.contains_key(&format!("k{}", MAX_DISCOVERY_CACHE + 9)));
    }

    #[test]
    fn hosts_and_origins_from_public_url() {
        let (h, o) = allowed_hosts_and_origins("https://warden.example.com");
        assert!(
            h.contains(&"warden.example.com".to_owned()) && h.contains(&"localhost".to_owned())
        );
        assert!(o.contains(&"https://warden.example.com:443".to_owned()));
        let (h, o) = allowed_hosts_and_origins("http://localhost:8080");
        assert!(h.iter().any(|x| x == "localhost"));
        assert!(o.contains(&"http://localhost:8080".to_owned()));
    }
}
