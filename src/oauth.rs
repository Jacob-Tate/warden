//! Minimal single-user OAuth 2.1 authorization server for `/mcp`.
//!
//! Exists so claude.ai custom connectors (and scheduled routines, which reuse them)
//! can authenticate: they only speak OAuth (discovery + dynamic client registration +
//! PKCE S256). There is exactly one human, the owner, who proves it with a passphrase
//! on the consent page (argon2id hash in `WARDEN_OWNER_PASSPHRASE_HASH`).
//!
//! Endpoints: RFC 9728 protected-resource metadata, RFC 8414 authorization-server
//! metadata (also served as `openid-configuration`), RFC 7591 `POST /register`,
//! `GET|POST /authorize`, `POST /token`, RFC 7009 `POST /revoke`.
//!
//! Design notes
//! - Codes, access tokens and refresh tokens are 32 random bytes; only SHA-256 hashes are stored.
//! - Every time comparison is done by SQLite (`strftime('now')`), never the Rust clock.
//! - Refresh tokens rotate on every use. Each code/refresh chain shares a `family_id`;
//!   replaying a used code or a rotated refresh token revokes the whole family.
//! - All tokens are bound to the resource `<public_url>/mcp` (RFC 8707) and to a
//!   consumer label chosen by the owner on the consent page.
//! - Redirect URIs must pass an operator allowlist at registration *and* match the
//!   registered value at `/authorize`; failures there never redirect.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use axum::{
    Extension, Form, Json, Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;

use crate::{
    auth::{ClientIp, Principal, TokenValidator, ValidateFuture, generate_key, hash_key},
    db::{Db, DbResult},
};

/// Authorization-code lifetime.
const CODE_TTL_SECS: i64 = 60;
/// Access-token lifetime.
pub const ACCESS_TTL_SECS: i64 = 3600;
/// Registered clients kept at most (see [`register_client`] for the eviction policy).
const MAX_CLIENTS: i64 = 50;
/// Clients that never got a token, or are unused for this long, are pruned.
const CLIENT_STALE_DAYS: i64 = 30;
const NOW: &str = "strftime('%Y-%m-%dT%H:%M:%SZ','now')";

// ---- configuration & state ---------------------------------------------------------

pub struct OAuthConfig {
    /// `https://host` (no trailing slash); also the issuer.
    pub issuer: String,
    /// The protected resource: `<issuer>/mcp`. Tokens are bound to it.
    pub resource: String,
    pub passphrase_hash: String,
    pub redirect_allow: Vec<String>,
    pub refresh_ttl_secs: i64,
    pub secure_cookie: bool,
}

#[derive(Clone)]
pub struct OAuthState {
    pub db: Db,
    pub cfg: Arc<OAuthConfig>,
    passphrases: Arc<PassphraseLimiter>,
    registrations: Arc<RegistrationLimiter>,
}

impl OAuthState {
    pub fn new(db: Db, cfg: OAuthConfig) -> Self {
        Self {
            db,
            cfg: Arc::new(cfg),
            passphrases: Arc::default(),
            registrations: Arc::default(),
        }
    }

    pub fn validator(&self) -> OAuthValidator {
        OAuthValidator {
            db: self.db.clone(),
            resource: self.cfg.resource.clone(),
        }
    }
}

/// Check that `hash` parses as an argon2 PHC string (startup validation).
pub fn check_hash(hash: &str) -> Result<()> {
    // Verifying a dummy password distinguishes "malformed hash" from "wrong password".
    match Argon2::default().verify_password(b"", hash) {
        Ok(()) => Ok(()),
        Err(argon2::password_hash::Error::PasswordInvalid) => Ok(()),
        Err(e) => bail!("WARDEN_OWNER_PASSPHRASE_HASH is not a valid argon2 hash: {e}"),
    }
}

fn verify_passphrase(hash: &str, pw: &str) -> bool {
    pw.len() <= 1024
        && Argon2::default()
            .verify_password(pw.as_bytes(), hash)
            .is_ok()
}

/// `warden hash-passphrase`: read a passphrase (hidden prompt on a terminal, one line from
/// stdin otherwise) and return the config line.
pub fn hash_passphrase_command() -> Result<String> {
    use std::io::{IsTerminal, Read};
    let pw = if std::io::stdin().is_terminal() {
        let a = rpassword::prompt_password("Owner passphrase (input hidden): ")?;
        let b = rpassword::prompt_password("Repeat: ")?;
        if a != b {
            bail!("the two entries differ");
        }
        a
    } else {
        let mut s = String::new();
        std::io::stdin().take(4096).read_to_string(&mut s)?;
        s.lines().next().unwrap_or("").to_owned()
    };
    if pw.chars().count() < 12 {
        bail!("use a passphrase of at least 12 characters (a few random words is fine)");
    }
    let hash = Argon2::default()
        .hash_password(pw.as_bytes())
        .map_err(|e| anyhow::anyhow!("hashing failed: {e}"))?
        .to_string();
    Ok(format!(
        "Add this to the environment (single-quote it in a shell; double every `$` as `$$` in a\n\
         docker compose file or .env read by compose):\n\n  WARDEN_OWNER_PASSPHRASE_HASH='{hash}'\n"
    ))
}

// ---- rate limiters -------------------------------------------------------------------

const PW_WINDOW: Duration = Duration::from_secs(900);
/// Failures per address before backoff starts.
const PW_FREE: u32 = 3;
/// Failures from all addresses within the window that lock the consent page entirely.
const PW_GLOBAL_MAX: usize = 30;

struct IpFails {
    count: u32,
    last: Instant,
}

#[derive(Default)]
struct PwState {
    per_ip: HashMap<IpAddr, IpFails>,
    global: Vec<Instant>,
}

/// Wrong-passphrase limiter: per address, the third failure locks that address for
/// 10 s, doubling with each further failure (cap 15 min); 30 failures from anywhere in
/// 15 minutes lock everyone out until the window drains.
#[derive(Default)]
pub struct PassphraseLimiter {
    st: Mutex<PwState>,
}

impl PassphraseLimiter {
    fn lock(&self) -> std::sync::MutexGuard<'_, PwState> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `Err(wait)` if the attempt must be refused now.
    pub fn check(&self, ip: IpAddr) -> Result<(), Duration> {
        let mut s = self.lock();
        let now = Instant::now();
        s.global.retain(|t| now.duration_since(*t) < PW_WINDOW);
        if s.global.len() >= PW_GLOBAL_MAX {
            let oldest = s.global.first().copied().unwrap_or(now);
            return Err(PW_WINDOW.saturating_sub(now.duration_since(oldest)));
        }
        if let Some(e) = s.per_ip.get(&ip) {
            if now.duration_since(e.last) >= PW_WINDOW {
                s.per_ip.remove(&ip);
            } else if e.count >= PW_FREE {
                let exp = (e.count - PW_FREE).min(7);
                let lock = Duration::from_secs((10u64 << exp).min(900));
                let since = now.duration_since(e.last);
                if since < lock {
                    return Err(lock - since);
                }
            }
        }
        Ok(())
    }

    pub fn failure(&self, ip: IpAddr) {
        let mut s = self.lock();
        let now = Instant::now();
        if s.per_ip.len() > 10_000 {
            s.per_ip
                .retain(|_, e| now.duration_since(e.last) < PW_WINDOW);
        }
        s.global.push(now);
        let e = s.per_ip.entry(ip).or_insert(IpFails {
            count: 0,
            last: now,
        });
        e.count += 1;
        e.last = now;
    }

    pub fn success(&self, ip: IpAddr) {
        self.lock().per_ip.remove(&ip);
    }
}

const REG_WINDOW: Duration = Duration::from_secs(3600);
const REG_PER_IP: usize = 10;
const REG_GLOBAL: usize = 100;

#[derive(Default)]
struct RegState {
    per_ip: HashMap<IpAddr, Vec<Instant>>,
    global: Vec<Instant>,
}

#[derive(Default)]
struct RegistrationLimiter {
    st: Mutex<RegState>,
}

impl RegistrationLimiter {
    /// Record an attempt; false if over the per-address or global hourly budget.
    fn hit(&self, ip: IpAddr) -> bool {
        let mut g = self.st.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let RegState { per_ip, global } = &mut *g;
        global.retain(|t| now.duration_since(*t) < REG_WINDOW);
        if per_ip.len() > 10_000 {
            per_ip.retain(|_, v| {
                v.last()
                    .is_some_and(|t| now.duration_since(*t) < REG_WINDOW)
            });
        }
        let v = per_ip.entry(ip).or_default();
        v.retain(|t| now.duration_since(*t) < REG_WINDOW);
        if v.len() >= REG_PER_IP || global.len() >= REG_GLOBAL {
            return false;
        }
        v.push(now);
        global.push(now);
        true
    }
}

// ---- small helpers -------------------------------------------------------------------

fn no_store(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    r
}

fn json_response(status: StatusCode, v: Value) -> Response {
    no_store((status, Json(v)).into_response())
}

fn oauth_error(status: StatusCode, code: &str, desc: &str) -> Response {
    json_response(status, json!({"error": code, "error_description": desc}))
}

fn internal_error() -> Response {
    oauth_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "internal error",
    )
}

fn is_loopback_host(h: &str) -> bool {
    matches!(h, "localhost" | "127.0.0.1" | "[::1]")
}

/// Validate a redirect URI for registration: well-formed, no fragment or userinfo,
/// https (or http on loopback only) and matching the operator allowlist.
fn redirect_uri_allowed(uri: &str, allow: &[String]) -> bool {
    if uri.len() > 512 {
        return false;
    }
    let Ok(u) = Url::parse(uri) else { return false };
    if u.fragment().is_some() || !u.username().is_empty() || u.password().is_some() {
        return false;
    }
    let Some(host) = u.host_str() else {
        return false;
    };
    match u.scheme() {
        "https" => {}
        "http" if is_loopback_host(host) => {}
        _ => return false,
    }
    allow.iter().any(|a| {
        if let Some(base) = a.strip_suffix(":*") {
            // `scheme://host:*`: any port and path on exactly that scheme and host
            Url::parse(base).is_ok_and(|b| {
                b.scheme() == u.scheme() && b.host_str() == u.host_str() && b.path() == "/"
            })
        } else {
            a == uri
        }
    })
}

/// Does `requested` match one of the registered URIs? Exact, or (loopback only, RFC 8252
/// section 7.3) equal except for the port.
fn redirect_matches(registered: &[String], requested: &str) -> bool {
    if registered.iter().any(|r| r == requested) {
        return true;
    }
    let Ok(req) = Url::parse(requested) else {
        return false;
    };
    let Some(host) = req.host_str().filter(|h| is_loopback_host(h)) else {
        return false;
    };
    registered.iter().any(|r| {
        Url::parse(r).is_ok_and(|r| {
            r.scheme() == req.scheme()
                && r.host_str() == Some(host)
                && r.path() == req.path()
                && r.query() == req.query()
        })
    })
}

fn valid_label(s: &str) -> bool {
    (1..=48).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn sanitize_label(s: &str) -> String {
    let t: String = s
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect();
    t.trim_matches('-').chars().take(32).collect()
}

/// Suggested consumer label: `claude-ai` for Anthropic callbacks, else the client name.
fn default_label(client_id: &str, name: Option<&str>, redirect: &Url) -> String {
    let host = redirect.host_str().unwrap_or("");
    if host == "claude.ai" || host == "claude.com" {
        return "claude-ai".into();
    }
    let s = name.map(sanitize_label).unwrap_or_default();
    if s.is_empty() {
        format!("client-{}", &client_id[..client_id.len().min(8)])
    } else {
        s
    }
}

fn valid_challenge(c: &str) -> bool {
    c.len() == 43
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn valid_verifier(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

fn pkce_ok(verifier: &str, challenge: &str) -> bool {
    if !valid_verifier(verifier) {
        return false;
    }
    let calc = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    bool::from(calc.as_bytes().ct_eq(challenge.as_bytes()))
}

fn escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c if c.is_control() => {}
            c => o.push(c),
        }
    }
    o
}

// ---- router -------------------------------------------------------------------------

pub fn routes(state: OAuthState) -> Router {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server),
        )
        .route(
            "/.well-known/openid-configuration",
            get(authorization_server),
        )
        .route("/register", post(register))
        .route("/authorize", get(authorize_get).post(authorize_post))
        .route("/token", post(token))
        .route("/revoke", post(revoke))
        .with_state(state)
}

async fn protected_resource(State(s): State<OAuthState>) -> Response {
    Json(json!({
        "resource": s.cfg.resource,
        "authorization_servers": [s.cfg.issuer],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["warden"],
    }))
    .into_response()
}

async fn authorization_server(State(s): State<OAuthState>) -> Response {
    let i = &s.cfg.issuer;
    // `client_id_metadata_document_supported` is deliberately absent: advertising it
    // makes Claude use CIMD, which would require fetching client-supplied URLs.
    Json(json!({
        "issuer": i,
        "authorization_endpoint": format!("{i}/authorize"),
        "token_endpoint": format!("{i}/token"),
        "registration_endpoint": format!("{i}/register"),
        "revocation_endpoint": format!("{i}/revoke"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["warden", "offline_access"],
        "authorization_response_iss_parameter_supported": true,
    }))
    .into_response()
}

// ---- dynamic client registration (RFC 7591) ----------------------------------------------

async fn register(
    State(s): State<OAuthState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    Json(body): Json<Value>,
) -> Response {
    let reg_err = |code: &str, desc: &str| oauth_error(StatusCode::BAD_REQUEST, code, desc);
    if !s.registrations.hit(ip) {
        let mut r = oauth_error(
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            "too many registrations, try again later",
        );
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(600));
        return r;
    }
    let Some(uris) = body.get("redirect_uris").and_then(Value::as_array) else {
        return reg_err("invalid_redirect_uri", "redirect_uris is required");
    };
    if uris.is_empty() || uris.len() > 5 {
        return reg_err("invalid_redirect_uri", "give between 1 and 5 redirect_uris");
    }
    let mut redirects = Vec::new();
    for u in uris {
        match u.as_str() {
            Some(u) if redirect_uri_allowed(u, &s.cfg.redirect_allow) => {
                redirects.push(u.to_owned())
            }
            _ => {
                return reg_err(
                    "invalid_redirect_uri",
                    "a redirect_uri is not allowed by this server",
                );
            }
        }
    }
    let name: Option<String> = body
        .get("client_name")
        .and_then(Value::as_str)
        .map(|n| {
            n.chars()
                .filter(|c| !c.is_control())
                .take(100)
                .collect::<String>()
        })
        .filter(|n| !n.trim().is_empty());
    let client_id = match generate_key() {
        Ok(k) => k[..32].to_owned(),
        Err(_) => return internal_error(),
    };
    let (cid, cname, uris_json) = (
        client_id.clone(),
        name.clone(),
        json!(redirects).to_string(),
    );
    match s
        .db
        .call(move |c| register_client(c, &cid, cname.as_deref(), &uris_json))
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "client registry is full",
            );
        }
        Err(e) => {
            tracing::error!("oauth register: {e}");
            return internal_error();
        }
    }
    tracing::info!(client = %client_id, name = ?name, "oauth client registered");
    json_response(
        StatusCode::CREATED,
        json!({
            "client_id": client_id,
            "client_name": name,
            "redirect_uris": redirects,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }),
    )
}

/// Insert a client, pruning first. Returns false when the registry is full of clients
/// that hold tokens (clients that never completed a flow are evicted oldest-first, so
/// an anonymous registration flood cannot displace the owner's connections).
fn register_client(
    c: &mut rusqlite::Connection,
    client_id: &str,
    name: Option<&str>,
    uris_json: &str,
) -> DbResult<bool> {
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    prune_clients(&tx)?;
    loop {
        let n: i64 = tx.query_row("SELECT COUNT(*) FROM oauth_clients", [], |r| r.get(0))?;
        if n < MAX_CLIENTS {
            break;
        }
        let gone = tx.execute(
            "DELETE FROM oauth_clients WHERE client_id = (\
               SELECT client_id FROM oauth_clients c \
               WHERE NOT EXISTS (SELECT 1 FROM oauth_tokens t WHERE t.client_id = c.client_id) \
               ORDER BY created_at, rowid LIMIT 1)",
            [],
        )?;
        if gone == 0 {
            return Ok(false);
        }
    }
    tx.execute(
        &format!(
            "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, created_at) \
             VALUES (?1, ?2, ?3, {NOW})"
        ),
        params![client_id, name, uris_json],
    )?;
    tx.commit()?;
    Ok(true)
}

fn prune_clients(c: &rusqlite::Connection) -> DbResult<usize> {
    Ok(c.execute(
        &format!(
            "DELETE FROM oauth_clients WHERE \
               COALESCE(last_used_at, created_at) < strftime('%Y-%m-%dT%H:%M:%SZ','now','-{CLIENT_STALE_DAYS} days') \
               AND NOT EXISTS (SELECT 1 FROM oauth_tokens t WHERE t.client_id = oauth_clients.client_id \
                               AND t.revoked_at IS NULL AND t.expires_at > {NOW})"
        ),
        [],
    )?)
}

/// Daily maintenance: drop expired codes/tokens (kept one extra day so replay and
/// rotation-reuse of recently expired material is still recognised) and stale clients.
pub fn cleanup(c: &rusqlite::Connection) -> DbResult<usize> {
    let grace = "strftime('%Y-%m-%dT%H:%M:%SZ','now','-1 day')";
    let a = c.execute(
        &format!("DELETE FROM oauth_codes WHERE expires_at < {grace}"),
        [],
    )?;
    let b = c.execute(
        &format!("DELETE FROM oauth_tokens WHERE expires_at < {grace}"),
        [],
    )?;
    Ok(a + b + prune_clients(c)?)
}

// ---- /authorize ------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct AuthParams {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    response_type: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
    // consent form only
    csrf: Option<String>,
    passphrase: Option<String>,
    label: Option<String>,
    deny: Option<String>,
}

struct Validated {
    client_id: String,
    client_name: Option<String>,
    redirect: Url,
    state: Option<String>,
    challenge: String,
    scope: String,
    resource: String,
    default_label: String,
}

enum AuthzError {
    /// Show an error page; the client or redirect URI is not trustworthy.
    Page(&'static str),
    /// Redirect back to the (validated) client with an OAuth error.
    Redirect {
        to: Url,
        state: Option<String>,
        code: &'static str,
        desc: &'static str,
    },
}

impl AuthzError {
    fn into_response(self, s: &OAuthState) -> Response {
        match self {
            AuthzError::Page(m) => page(StatusCode::BAD_REQUEST, &error_html(m), None),
            AuthzError::Redirect {
                to,
                state,
                code,
                desc,
            } => redirect_back(
                s,
                to,
                state.as_deref(),
                &[("error", code), ("error_description", desc)],
            ),
        }
    }
}

fn redirect_back(
    s: &OAuthState,
    mut to: Url,
    state: Option<&str>,
    extra: &[(&str, &str)],
) -> Response {
    {
        let mut q = to.query_pairs_mut();
        for (k, v) in extra {
            q.append_pair(k, v);
        }
        if let Some(st) = state {
            q.append_pair("state", st);
        }
        q.append_pair("iss", &s.cfg.issuer);
    }
    let mut r = no_store(StatusCode::FOUND.into_response());
    match HeaderValue::from_str(to.as_str()) {
        Ok(v) => {
            r.headers_mut().insert(header::LOCATION, v);
        }
        Err(_) => return internal_error(),
    }
    // the CSRF cookie has served its purpose
    r.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "warden_csrf=; Path=/authorize; Max-Age=0; HttpOnly; SameSite=Strict",
        ),
    );
    r
}

async fn validate_authorize(s: &OAuthState, p: &AuthParams) -> Result<Validated, AuthzError> {
    let Some(client_id) = p
        .client_id
        .clone()
        .filter(|c| !c.is_empty() && c.len() <= 128)
    else {
        return Err(AuthzError::Page("Missing or invalid client_id."));
    };
    let cid = client_id.clone();
    let row =
        s.db.call(move |c| {
            Ok(c.query_row(
                "SELECT client_name, redirect_uris FROM oauth_clients WHERE client_id = ?1",
                [&cid],
                |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?)
        })
        .await
        .map_err(|_| AuthzError::Page("Internal error."))?;
    let Some((client_name, uris)) = row else {
        return Err(AuthzError::Page(
            "Unknown client. Remove and re-add the connector.",
        ));
    };
    let registered: Vec<String> = serde_json::from_str(&uris).unwrap_or_default();
    let Some(redirect_str) = p.redirect_uri.as_deref() else {
        return Err(AuthzError::Page("Missing redirect_uri."));
    };
    // Registered URIs already passed the allowlist; re-check in case config tightened.
    if !redirect_matches(&registered, redirect_str)
        || !redirect_uri_allowed(redirect_str, &s.cfg.redirect_allow)
    {
        return Err(AuthzError::Page(
            "redirect_uri does not match this client's registration.",
        ));
    }
    let Ok(redirect) = Url::parse(redirect_str) else {
        return Err(AuthzError::Page("Invalid redirect_uri."));
    };
    let fail = |code, desc| AuthzError::Redirect {
        to: redirect.clone(),
        state: p.state.clone().filter(|s| s.len() <= 512),
        code,
        desc,
    };
    if p.response_type.as_deref() != Some("code") {
        return Err(fail(
            "unsupported_response_type",
            "response_type must be code",
        ));
    }
    if p.code_challenge_method.as_deref() != Some("S256") {
        return Err(fail(
            "invalid_request",
            "PKCE with code_challenge_method=S256 is required",
        ));
    }
    let challenge = p.code_challenge.clone().unwrap_or_default();
    if !valid_challenge(&challenge) {
        return Err(fail(
            "invalid_request",
            "code_challenge is missing or malformed",
        ));
    }
    if p.state.as_ref().is_some_and(|s| s.len() > 512) {
        return Err(fail("invalid_request", "state is too long"));
    }
    if p.resource.as_deref().is_some_and(|r| r != s.cfg.resource) {
        return Err(fail(
            "invalid_target",
            "resource must be this server's /mcp URL",
        ));
    }
    let scope = if p
        .scope
        .as_deref()
        .is_some_and(|s| s.split(' ').any(|t| t == "offline_access"))
    {
        "warden offline_access"
    } else {
        "warden"
    };
    let default_label = default_label(&client_id, client_name.as_deref(), &redirect);
    Ok(Validated {
        client_id,
        client_name,
        redirect,
        state: p.state.clone(),
        challenge,
        scope: scope.to_owned(),
        resource: s.cfg.resource.clone(),
        default_label,
    })
}

fn page(status: StatusCode, html: &str, cookie: Option<String>) -> Response {
    let mut r = (status, html.to_owned()).into_response();
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    if let Some(c) = cookie.and_then(|c| HeaderValue::from_str(&c).ok()) {
        h.insert(header::SET_COOKIE, c);
    }
    r
}

const STYLE: &str = "body{font:16px system-ui,sans-serif;max-width:30rem;margin:3rem auto;padding:0 1rem;color:#1b1b1b;background:#fafafa}\
h1{font-size:1.3rem}dl{background:#fff;border:1px solid #ddd;border-radius:6px;padding:.8rem 1rem}dt{font-size:.8rem;color:#666}dd{margin:0 0 .6rem;word-break:break-all}\
input[type=password],input[type=text]{width:100%;box-sizing:border-box;padding:.5rem;margin:.2rem 0 .8rem;font:inherit}\
button{font:inherit;padding:.5rem 1rem;margin-right:.5rem;cursor:pointer}.err{color:#a00020}.warn{color:#8a5a00}small{color:#666}";

fn error_html(msg: &str) -> String {
    format!(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>warden: error</title><style>{STYLE}</style><h1>Cannot continue</h1><p class=err>{}</p>",
        escape(msg)
    )
}

fn consent_html(
    v: &Validated,
    p: &AuthParams,
    csrf: &str,
    label: &str,
    error: Option<&str>,
) -> String {
    let host = match (v.redirect.host_str(), v.redirect.port()) {
        (Some(h), Some(port)) => format!("{h}:{port}"),
        (Some(h), None) => h.to_owned(),
        _ => String::new(),
    };
    let loopback = v.redirect.host_str().is_some_and(is_loopback_host);
    let hidden = |name: &str, val: &str| {
        format!(
            "<input type=hidden name=\"{name}\" value=\"{}\">",
            escape(val)
        )
    };
    let mut hid = String::new();
    for (n, val) in [
        ("client_id", v.client_id.as_str()),
        ("redirect_uri", v.redirect.as_str()),
        ("response_type", "code"),
        ("code_challenge", &v.challenge),
        ("code_challenge_method", "S256"),
        ("scope", p.scope.as_deref().unwrap_or("")),
        ("resource", p.resource.as_deref().unwrap_or("")),
        ("csrf", csrf),
    ] {
        hid.push_str(&hidden(n, val));
    }
    if let Some(st) = &v.state {
        hid.push_str(&hidden("state", st));
    }
    format!(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>warden: authorize</title><style>{STYLE}</style>\
         <h1>Authorize access to warden</h1>\
         <p>An application is asking to read your CVE feed and manage tracked products.</p>\
         <dl><dt>Application</dt><dd>{name}</dd><dt>Will return you to</dt><dd><b>{host}</b></dd></dl>\
         {warn}{err}\
         <form method=post action=\"/authorize\">{hid}\
         <label>Owner passphrase<input type=password name=passphrase autocomplete=current-password required autofocus></label>\
         <label>Connection name <small>(its own unread-CVE cursor; letters, digits, . _ -)</small>\
         <input type=text name=label value=\"{label}\" maxlength=48 pattern=\"[A-Za-z0-9._\\-]{{1,48}}\"></label>\
         <button type=submit>Authorize</button><button type=submit name=deny value=1 formnovalidate>Deny</button></form>",
        name = escape(v.client_name.as_deref().unwrap_or("(unnamed client)")),
        host = escape(&host),
        warn = if loopback {
            "<p class=warn>This returns to an address on the machine running the application. Only continue if you started this sign-in yourself.</p>"
        } else {
            ""
        },
        err = error
            .map(|e| format!("<p class=err>{}</p>", escape(e)))
            .unwrap_or_default(),
        label = escape(label),
    )
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find_map(|(k, v)| (k == name).then_some(v))
}

fn csrf_cookie(s: &OAuthState, token: &str) -> String {
    format!(
        "warden_csrf={token}; Path=/authorize; Max-Age=900; HttpOnly; SameSite=Strict{}",
        if s.cfg.secure_cookie { "; Secure" } else { "" }
    )
}

async fn authorize_get(State(s): State<OAuthState>, Query(p): Query<AuthParams>) -> Response {
    let v = match validate_authorize(&s, &p).await {
        Ok(v) => v,
        Err(e) => return e.into_response(&s),
    };
    let Ok(csrf) = generate_key() else {
        return internal_error();
    };
    page(
        StatusCode::OK,
        &consent_html(&v, &p, &csrf, &v.default_label, None),
        Some(csrf_cookie(&s, &csrf)),
    )
}

async fn authorize_post(
    State(s): State<OAuthState>,
    Extension(ClientIp(ip)): Extension<ClientIp>,
    headers: HeaderMap,
    Form(p): Form<AuthParams>,
) -> Response {
    // CSRF first: double-submit cookie. Failures do not count against the passphrase limiter.
    let form_tok = p.csrf.as_deref().unwrap_or("");
    let ok = cookie_value(&headers, "warden_csrf")
        .is_some_and(|c| !c.is_empty() && bool::from(c.as_bytes().ct_eq(form_tok.as_bytes())));
    if !ok {
        return page(
            StatusCode::FORBIDDEN,
            &error_html(
                "This form has expired or did not come from warden. Go back to the application and start again.",
            ),
            None,
        );
    }
    let v = match validate_authorize(&s, &p).await {
        Ok(v) => v,
        Err(e) => return e.into_response(&s),
    };
    if p.deny.is_some() {
        return redirect_back(
            &s,
            v.redirect,
            v.state.as_deref(),
            &[
                ("error", "access_denied"),
                ("error_description", "the owner denied the request"),
            ],
        );
    }
    if let Err(wait) = s.passphrases.check(ip) {
        let mut r = page(
            StatusCode::TOO_MANY_REQUESTS,
            &error_html("Too many failed attempts. Wait a while and try again."),
            None,
        );
        r.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from(wait.as_secs().max(1)),
        );
        return r;
    }
    let (hash, pw) = (
        s.cfg.passphrase_hash.clone(),
        p.passphrase.clone().unwrap_or_default(),
    );
    let ok = tokio::task::spawn_blocking(move || verify_passphrase(&hash, &pw))
        .await
        .unwrap_or(false);
    let label_in = p.label.as_deref().map(str::trim).filter(|l| !l.is_empty());
    if !ok {
        s.passphrases.failure(ip);
        tracing::warn!(%ip, client = %v.client_id, "oauth consent: wrong passphrase");
        return page(
            StatusCode::UNAUTHORIZED,
            &consent_html(
                &v,
                &p,
                form_tok,
                label_in.unwrap_or(&v.default_label),
                Some("Wrong passphrase."),
            ),
            None,
        );
    }
    let label = match label_in {
        Some(l) if valid_label(l) => l.to_owned(),
        Some(_) => {
            return page(
                StatusCode::BAD_REQUEST,
                &consent_html(
                    &v,
                    &p,
                    form_tok,
                    &v.default_label,
                    Some("The connection name may only use letters, digits, . _ - (max 48)."),
                ),
                None,
            );
        }
        None => v.default_label.clone(),
    };
    s.passphrases.success(ip);
    let (code, family) = match (generate_key(), generate_key()) {
        (Ok(c), Ok(f)) => (c, f),
        _ => return internal_error(),
    };
    let (ch, cid, ru, chal, res, scope, lab) = (
        hash_key(&code),
        v.client_id.clone(),
        v.redirect.to_string(),
        v.challenge.clone(),
        v.resource.clone(),
        v.scope.clone(),
        label.clone(),
    );
    let stored = s
        .db
        .call(move |c| {
            Ok(c.execute(
                &format!(
                    "INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, code_challenge, \
                     resource, consumer, scope, family_id, expires_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, strftime('%Y-%m-%dT%H:%M:%SZ','now','+{CODE_TTL_SECS} seconds'))"
                ),
                params![ch, cid, ru, chal, res, lab, scope, &family[..22]],
            )?)
        })
        .await;
    if let Err(e) = stored {
        tracing::error!("oauth store code: {e}");
        return internal_error();
    }
    tracing::info!(client = %v.client_id, %label, %ip, "oauth consent granted");
    redirect_back(&s, v.redirect, v.state.as_deref(), &[("code", &code)])
}

// ---- /token ------------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct TokenParams {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    resource: Option<String>,
    token: Option<String>,
}

type Reject = (&'static str, &'static str);

struct Issued {
    access: String,
    refresh: String,
    scope: String,
}

fn revoke_family(tx: &rusqlite::Connection, family: &str) -> DbResult<()> {
    tx.execute(
        &format!(
            "UPDATE oauth_tokens SET revoked_at = {NOW} WHERE family_id = ?1 AND revoked_at IS NULL"
        ),
        [family],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn issue_pair(
    tx: &rusqlite::Connection,
    client_id: &str,
    family: &str,
    resource: &str,
    consumer: &str,
    scope: &str,
    refresh_ttl: i64,
) -> DbResult<Issued> {
    let (access, refresh) = (
        generate_key().map_err(|e| std::io::Error::other(e.to_string()))?,
        generate_key().map_err(|e| std::io::Error::other(e.to_string()))?,
    );
    for (kind, tok, ttl) in [
        ("access", &access, ACCESS_TTL_SECS),
        ("refresh", &refresh, refresh_ttl),
    ] {
        tx.execute(
            &format!(
                "INSERT INTO oauth_tokens (token_hash, kind, client_id, family_id, resource, consumer, \
                 scope, expires_at, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, strftime('%Y-%m-%dT%H:%M:%SZ','now',?8), {NOW})"
            ),
            params![hash_key(tok), kind, client_id, family, resource, consumer, scope, format!("+{ttl} seconds")],
        )?;
    }
    tx.execute(
        &format!("UPDATE oauth_clients SET last_used_at = {NOW} WHERE client_id = ?1"),
        [client_id],
    )?;
    Ok(Issued {
        access,
        refresh,
        scope: scope.to_owned(),
    })
}

fn exchange_code(
    c: &mut rusqlite::Connection,
    p: &TokenParams,
    resource: &str,
    refresh_ttl: i64,
) -> DbResult<Result<Issued, Reject>> {
    let (Some(code), Some(client_id), Some(redirect_uri), Some(verifier)) = (
        p.code.as_deref(),
        p.client_id.as_deref(),
        p.redirect_uri.as_deref(),
        p.code_verifier.as_deref(),
    ) else {
        return Ok(Err((
            "invalid_request",
            "code, client_id, redirect_uri and code_verifier are required",
        )));
    };
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let known: bool = tx
        .query_row(
            "SELECT 1 FROM oauth_clients WHERE client_id = ?1",
            [client_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !known {
        return Ok(Err(("invalid_client", "unknown client_id")));
    }
    type CodeRow = (
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        bool,
        bool,
    );
    let row: Option<CodeRow> = tx
        .query_row(
            &format!(
                "SELECT client_id, redirect_uri, code_challenge, resource, consumer, scope, family_id, \
                 used_at IS NOT NULL, expires_at <= {NOW} FROM oauth_codes WHERE code_hash = ?1"
            ),
            [hash_key(code)],
            |r| {
                Ok((
                    r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?,
                    r.get(7)?, r.get(8)?,
                ))
            },
        )
        .optional()?;
    let Some((cid, ruri, chal, res, consumer, scope, family, used, expired)) = row else {
        return Ok(Err((
            "invalid_grant",
            "unknown or expired authorization code",
        )));
    };
    if used {
        // Replay: whatever was issued from this code is now suspect.
        revoke_family(&tx, &family)?;
        tx.commit()?;
        tracing::warn!(client = %client_id, "oauth authorization code replayed; token family revoked");
        return Ok(Err(("invalid_grant", "authorization code already used")));
    }
    // Single use: burn the code on any attempt, successful or not.
    tx.execute(
        &format!("UPDATE oauth_codes SET used_at = {NOW} WHERE code_hash = ?1"),
        [hash_key(code)],
    )?;
    let reject = if expired {
        Some("authorization code expired")
    } else if cid != client_id || ruri != redirect_uri {
        Some("client_id or redirect_uri does not match the authorization request")
    } else if !pkce_ok(verifier, &chal) {
        Some("PKCE verification failed")
    } else if p.resource.as_deref().is_some_and(|r| r != res) {
        Some("resource does not match the authorization request")
    } else {
        None
    };
    if let Some(msg) = reject {
        tx.commit()?;
        return Ok(Err(("invalid_grant", msg)));
    }
    let issued = issue_pair(
        &tx,
        client_id,
        &family,
        resource,
        &consumer,
        scope.as_deref().unwrap_or("warden"),
        refresh_ttl,
    )?;
    tx.commit()?;
    Ok(Ok(issued))
}

fn exchange_refresh(
    c: &mut rusqlite::Connection,
    p: &TokenParams,
    resource: &str,
    refresh_ttl: i64,
) -> DbResult<Result<Issued, Reject>> {
    let (Some(rt), Some(client_id)) = (p.refresh_token.as_deref(), p.client_id.as_deref()) else {
        return Ok(Err((
            "invalid_request",
            "refresh_token and client_id are required",
        )));
    };
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    type Row = (String, String, String, Option<String>, bool, bool, bool);
    let row: Option<Row> = tx
        .query_row(
            &format!(
                "SELECT client_id, family_id, consumer, scope, rotated_at IS NOT NULL, \
                 revoked_at IS NOT NULL, expires_at <= {NOW} \
                 FROM oauth_tokens WHERE token_hash = ?1 AND kind = 'refresh'"
            ),
            [hash_key(rt)],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some((cid, family, consumer, scope, rotated, revoked, expired)) = row else {
        return Ok(Err(("invalid_grant", "unknown refresh token")));
    };
    if cid != client_id {
        return Ok(Err((
            "invalid_grant",
            "refresh token was not issued to this client",
        )));
    }
    if rotated {
        // An already-exchanged token came back: either the client lost the rotation
        // response or the token was stolen. Cut the whole family either way.
        revoke_family(&tx, &family)?;
        tx.commit()?;
        tracing::warn!(client = %client_id, "oauth refresh token reuse detected; token family revoked");
        return Ok(Err(("invalid_grant", "refresh token already used")));
    }
    if revoked || expired {
        return Ok(Err(("invalid_grant", "refresh token expired or revoked")));
    }
    tx.execute(
        &format!(
            "UPDATE oauth_tokens SET rotated_at = {NOW}, revoked_at = {NOW} WHERE token_hash = ?1"
        ),
        [hash_key(rt)],
    )?;
    // Old access tokens of this family die with the rotation.
    tx.execute(
        &format!("UPDATE oauth_tokens SET revoked_at = {NOW} WHERE family_id = ?1 AND kind = 'access' AND revoked_at IS NULL"),
        [&family],
    )?;
    let issued = issue_pair(
        &tx,
        client_id,
        &family,
        resource,
        &consumer,
        scope.as_deref().unwrap_or("warden"),
        refresh_ttl,
    )?;
    tx.commit()?;
    Ok(Ok(issued))
}

async fn token(State(s): State<OAuthState>, Form(p): Form<TokenParams>) -> Response {
    if p.resource.as_deref().is_some_and(|r| r != s.cfg.resource) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "resource must be this server's /mcp URL",
        );
    }
    let (resource, ttl) = (s.cfg.resource.clone(), s.cfg.refresh_ttl_secs);
    let grant = p.grant_type.clone().unwrap_or_default();
    let result = match grant.as_str() {
        "authorization_code" => {
            s.db.call(move |c| exchange_code(c, &p, &resource, ttl))
                .await
        }
        "refresh_token" => {
            s.db.call(move |c| exchange_refresh(c, &p, &resource, ttl))
                .await
        }
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "use authorization_code or refresh_token",
            );
        }
    };
    match result {
        Ok(Ok(t)) => json_response(
            StatusCode::OK,
            json!({
                "access_token": t.access,
                "token_type": "Bearer",
                "expires_in": ACCESS_TTL_SECS,
                "refresh_token": t.refresh,
                "scope": t.scope,
            }),
        ),
        Ok(Err((code, desc))) => oauth_error(StatusCode::BAD_REQUEST, code, desc),
        Err(e) => {
            tracing::error!("oauth token: {e}");
            internal_error()
        }
    }
}

/// RFC 7009: revoke the presented token's whole family. Always 200 (no oracle).
async fn revoke(State(s): State<OAuthState>, Form(p): Form<TokenParams>) -> Response {
    if let Some(t) = p.token {
        let h = hash_key(&t);
        let r =
            s.db.call(move |c| {
                let fam: Option<String> = c
                    .query_row(
                        "SELECT family_id FROM oauth_tokens WHERE token_hash = ?1",
                        [&h],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(f) = fam {
                    revoke_family(c, &f)?;
                }
                Ok(())
            })
            .await;
        if let Err(e) = r {
            tracing::error!("oauth revoke: {e}");
            return internal_error();
        }
    }
    json_response(StatusCode::OK, json!({}))
}

// ---- bearer validation ----------------------------------------------------------------------

/// Accepts live OAuth access tokens bound to this server's `/mcp` resource.
pub struct OAuthValidator {
    db: Db,
    resource: String,
}

impl TokenValidator for OAuthValidator {
    fn validate<'a>(&'a self, token: &'a str) -> ValidateFuture<'a> {
        Box::pin(async move {
            // Cheap shape check: tokens are 32 random bytes, base64url.
            if token.len() != 43 {
                return None;
            }
            let (h, res) = (hash_key(token), self.resource.clone());
            let consumer: Option<String> = self
                .db
                .call(move |c| {
                    Ok(c.query_row(
                        &format!(
                            "SELECT consumer FROM oauth_tokens WHERE token_hash = ?1 AND kind = 'access' \
                             AND revoked_at IS NULL AND expires_at > {NOW} AND resource = ?2"
                        ),
                        params![h, res],
                        |r| r.get(0),
                    )
                    .optional()?)
                })
                .await
                .ok()
                .flatten();
            consumer.map(|c| Principal {
                name: format!("oauth:{c}"),
            })
        })
    }
}

/// Build the authorization server from config; `None` (OAuth disabled) without a passphrase hash.
pub fn from_config(db: Db, config: &crate::config::Config) -> Result<Option<OAuthState>> {
    let Some(hash) = &config.owner_passphrase_hash else {
        return Ok(None);
    };
    check_hash(hash)?;
    Ok(Some(OAuthState::new(
        db,
        OAuthConfig {
            issuer: config.public_url.clone(),
            resource: format!("{}/mcp", config.public_url),
            passphrase_hash: hash.clone(),
            redirect_allow: config.oauth_redirect_allow.clone(),
            refresh_ttl_secs: config.oauth_refresh_days * 86_400,
            secure_cookie: config.public_url.starts_with("https://"),
        },
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{ApiKeyValidator, hash_key as hk},
        config::Config,
        http,
    };
    use axum::{body::Body, extract::ConnectInfo, http::Request};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    const PASS: &str = "correct horse battery staple";
    const CB: &str = "https://claude.ai/api/mcp/auth_callback";
    const RES: &str = "http://localhost:8080/mcp";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    fn challenge(v: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()))
    }

    struct T {
        app: Router,
        db: Db,
    }

    fn setup_with(cfg: Config) -> T {
        let hash = Argon2::default()
            .hash_password(PASS.as_bytes())
            .unwrap()
            .to_string();
        let mut st = http::tests::test_state();
        st.config = Arc::new(cfg);
        let o = OAuthState::new(
            st.db.clone(),
            OAuthConfig {
                issuer: "http://localhost:8080".into(),
                resource: RES.into(),
                passphrase_hash: hash,
                redirect_allow: crate::config::DEFAULT_REDIRECT_ALLOW
                    .iter()
                    .map(|s| (*s).into())
                    .collect(),
                refresh_ttl_secs: 30 * 86_400,
                secure_cookie: false,
            },
        );
        st.validators = vec![
            Arc::new(ApiKeyValidator::parse(&[format!("k:{}", hk("static-key"))]).unwrap()),
            Arc::new(o.validator()),
        ];
        st.oauth = Some(o);
        let db = st.db.clone();
        T {
            app: http::router(st),
            db,
        }
    }

    fn setup() -> T {
        setup_with(Config::from_lookup(|_| None).unwrap())
    }

    fn req(method: &str, uri: &str) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "localhost:8080")
    }

    async fn send(t: &T, mut r: Request<Body>, ip: &str) -> (StatusCode, HeaderMap, String) {
        let addr: SocketAddr = format!("{ip}:4000").parse().unwrap();
        r.extensions_mut().insert(ConnectInfo(addr));
        let res = t.app.clone().oneshot(r).await.unwrap();
        let (st, h) = (res.status(), res.headers().clone());
        let b = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        (st, h, String::from_utf8_lossy(&b).into_owned())
    }

    fn form(pairs: &[(&str, &str)]) -> String {
        let mut s = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in pairs {
            s.append_pair(k, v);
        }
        s.finish()
    }

    async fn register_cb(t: &T, uris: Value) -> (StatusCode, Value) {
        let r = req("POST", "/register")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"client_name": "Claude", "redirect_uris": uris}).to_string(),
            ))
            .unwrap();
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (st, _, b) = send(t, r, &format!("203.0.{}.{}", n / 250, n % 250)).await;
        (st, serde_json::from_str(&b).unwrap_or(Value::Null))
    }

    async fn client(t: &T) -> String {
        let (st, v) = register_cb(t, json!([CB])).await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        v["client_id"].as_str().unwrap().to_owned()
    }

    fn authorize_query(cid: &str, redirect: &str, chal: &str, extra: &[(&str, &str)]) -> String {
        let mut p = vec![
            ("client_id", cid),
            ("redirect_uri", redirect),
            ("response_type", "code"),
            ("code_challenge", chal),
            ("code_challenge_method", "S256"),
            ("state", "xyz"),
        ];
        p.extend_from_slice(extra);
        form(&p)
    }

    async fn get_authorize(t: &T, q: &str) -> (StatusCode, HeaderMap, String) {
        send(
            t,
            req("GET", &format!("/authorize?{q}"))
                .body(Body::empty())
                .unwrap(),
            "203.0.113.2",
        )
        .await
    }

    /// GET the consent page; returns the CSRF token (also checked against the form).
    async fn consent(t: &T, q: &str) -> (String, HeaderMap, String) {
        let (st, h, body) = get_authorize(t, q).await;
        assert_eq!(st, StatusCode::OK, "{body}");
        let cookie = h[header::SET_COOKIE].to_str().unwrap();
        let tok = cookie
            .strip_prefix("warden_csrf=")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert!(body.contains(&tok), "csrf token in form");
        (tok, h, body)
    }

    #[allow(clippy::too_many_arguments)]
    async fn post_consent(
        t: &T,
        cid: &str,
        chal: &str,
        csrf: Option<&str>,
        pass: &str,
        label: &str,
        ip: &str,
    ) -> (StatusCode, HeaderMap, String) {
        let body = form(&[
            ("client_id", cid),
            ("redirect_uri", CB),
            ("response_type", "code"),
            ("code_challenge", chal),
            ("code_challenge_method", "S256"),
            ("state", "xyz"),
            ("resource", RES),
            ("csrf", csrf.unwrap_or("")),
            ("passphrase", pass),
            ("label", label),
        ]);
        let mut b =
            req("POST", "/authorize").header("content-type", "application/x-www-form-urlencoded");
        if let Some(c) = csrf {
            b = b.header("cookie", format!("warden_csrf={c}"));
        }
        send(t, b.body(Body::from(body)).unwrap(), ip).await
    }

    /// Full consent; returns the authorization code.
    async fn get_code(t: &T, cid: &str, label: &str) -> String {
        let chal = challenge(VERIFIER);
        let (csrf, ..) = consent(t, &authorize_query(cid, CB, &chal, &[("resource", RES)])).await;
        let (st, h, body) =
            post_consent(t, cid, &chal, Some(&csrf), PASS, label, "203.0.113.2").await;
        assert_eq!(st, StatusCode::FOUND, "{body}");
        let loc = Url::parse(h[header::LOCATION].to_str().unwrap()).unwrap();
        assert!(loc.as_str().starts_with(CB));
        let q: HashMap<_, _> = loc.query_pairs().into_owned().collect();
        assert_eq!(q["state"], "xyz");
        assert_eq!(q["iss"], "http://localhost:8080");
        q["code"].clone()
    }

    async fn token_req(t: &T, pairs: &[(&str, &str)]) -> (StatusCode, HeaderMap, Value) {
        let r = req("POST", "/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form(pairs)))
            .unwrap();
        let (st, h, b) = send(t, r, "203.0.113.3").await;
        (st, h, serde_json::from_str(&b).unwrap_or(Value::Null))
    }

    async fn code_exchange(t: &T, cid: &str, code: &str, verifier: &str) -> (StatusCode, Value) {
        let (st, h, v) = token_req(
            t,
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", cid),
                ("redirect_uri", CB),
                ("code_verifier", verifier),
            ],
        )
        .await;
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
        (st, v)
    }

    async fn refresh(t: &T, cid: &str, rt: &str) -> (StatusCode, Value) {
        let (st, _, v) = token_req(
            t,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", rt),
                ("client_id", cid),
            ],
        )
        .await;
        (st, v)
    }

    async fn mcp_call(t: &T, tok: &str, ip: &str) -> (StatusCode, HeaderMap, String) {
        let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}).to_string();
        let r = Request::post("/mcp")
            .header("host", "localhost:8080")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("authorization", format!("Bearer {tok}"))
            .body(Body::from(body))
            .unwrap();
        send(t, r, ip).await
    }

    async fn mcp_status(t: &T, tok: &str) -> StatusCode {
        mcp_call(t, tok, "203.0.113.5").await.0
    }

    async fn authed(t: &T) -> (String, Value) {
        let cid = client(t).await;
        let code = get_code(t, &cid, "").await;
        let (st, v) = code_exchange(t, &cid, &code, VERIFIER).await;
        assert_eq!(st, StatusCode::OK, "{v}");
        (cid, v)
    }

    fn sql(t: &T, q: &'static str) -> usize {
        t.db.with_conn(|c| Ok(c.execute(q, [])?)).unwrap()
    }

    fn count(t: &T, q: &'static str) -> i64 {
        t.db.with_conn(|c| Ok(c.query_row(q, [], |r| r.get(0))?))
            .unwrap()
    }

    fn s(v: &Value, k: &str) -> String {
        v[k].as_str().unwrap().to_owned()
    }

    #[tokio::test]
    async fn metadata_documents() {
        let t = setup();
        let get = async |p: &str| {
            let (st, _, b) = send(
                &t,
                req("GET", p).body(Body::empty()).unwrap(),
                "203.0.113.1",
            )
            .await;
            assert_eq!(st, StatusCode::OK, "{p}");
            serde_json::from_str::<Value>(&b).unwrap()
        };
        for p in [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        ] {
            let v = get(p).await;
            assert_eq!(v["resource"], RES);
            assert_eq!(v["authorization_servers"], json!(["http://localhost:8080"]));
        }
        for p in [
            "/.well-known/oauth-authorization-server",
            "/.well-known/openid-configuration",
        ] {
            let v = get(p).await;
            assert_eq!(v["issuer"], "http://localhost:8080");
            assert_eq!(
                v["authorization_endpoint"],
                "http://localhost:8080/authorize"
            );
            assert_eq!(v["token_endpoint"], "http://localhost:8080/token");
            assert_eq!(v["registration_endpoint"], "http://localhost:8080/register");
            assert_eq!(v["code_challenge_methods_supported"], json!(["S256"]));
            assert_eq!(v["token_endpoint_auth_methods_supported"], json!(["none"]));
            assert!(v.get("client_id_metadata_document_supported").is_none());
        }
    }

    #[tokio::test]
    async fn disabled_without_passphrase() {
        let app = http::router(http::tests::test_state());
        for p in [
            "/.well-known/oauth-authorization-server",
            "/authorize",
            "/register",
        ] {
            let res = app
                .clone()
                .oneshot(Request::get(p).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::NOT_FOUND, "{p}");
        }
    }

    #[tokio::test]
    async fn dcr_allowlist_and_cap() {
        let t = setup();
        for ok in [
            json!([CB]),
            json!(["http://localhost:53682/callback"]),
            json!(["http://127.0.0.1:1/cb"]),
        ] {
            assert_eq!(
                register_cb(&t, ok.clone()).await.0,
                StatusCode::CREATED,
                "{ok}"
            );
        }
        for bad in [
            json!(["https://evil.example/cb"]),
            json!(["https://claude.com/api/mcp/auth_callback"]),
            json!(["http://claude.ai/api/mcp/auth_callback"]),
            json!(["https://claude.ai/other"]),
            json!(["http://localhost.evil.example/cb"]),
            json!(["https://claude.ai/api/mcp/auth_callback#frag"]),
            json!([CB, "https://evil.example/cb"]),
            json!([]),
            json!("x"),
        ] {
            let (st, v) = register_cb(&t, bad.clone()).await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "{bad}");
            assert_eq!(v["error"], "invalid_redirect_uri");
        }
        // Registry cap: never-authorized clients are evicted oldest first, and a client
        // that holds tokens survives a registration flood.
        let (cid, _) = authed(&t).await;
        for i in 0..60 {
            let r = req("POST", "/register")
                .header("content-type", "application/json")
                .body(Body::from(json!({"redirect_uris": [CB]}).to_string()))
                .unwrap();
            let (st, ..) = send(&t, r, &format!("198.51.100.{}", i % 250)).await;
            assert_eq!(st, StatusCode::CREATED);
        }
        assert!(count(&t, "SELECT COUNT(*) FROM oauth_clients") <= MAX_CLIENTS);
        let kept: i64 =
            t.db.with_conn(|c| {
                Ok(c.query_row(
                    "SELECT COUNT(*) FROM oauth_clients WHERE client_id = ?1",
                    [&cid],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(kept, 1);
    }

    #[tokio::test]
    async fn registration_is_rate_limited() {
        let t = setup();
        let mut last = StatusCode::OK;
        for _ in 0..=REG_PER_IP {
            let r = req("POST", "/register")
                .header("content-type", "application/json")
                .body(Body::from(json!({"redirect_uris": [CB]}).to_string()))
                .unwrap();
            last = send(&t, r, "192.0.2.44").await.0;
        }
        assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn full_flow_reaches_mcp() {
        let t = setup();
        let (_, v) = authed(&t).await;
        assert_eq!(v["token_type"], "Bearer");
        assert_eq!(v["expires_in"], 3600);
        let access = s(&v, "access_token");
        let (st, _, body) = mcp_call(&t, &access, "203.0.113.5").await;
        assert_eq!(st, StatusCode::OK, "{body}");
        assert!(body.contains("get_new_cves"));
        // default consumer for Anthropic callbacks; only hashes are stored
        let name: String =
            t.db.with_conn(|c| {
                Ok(
                    c.query_row("SELECT consumer FROM oauth_tokens LIMIT 1", [], |r| {
                        r.get(0)
                    })?,
                )
            })
            .unwrap();
        assert_eq!(name, "claude-ai");
        let raw: i64 =
            t.db.with_conn(|c| {
                Ok(c.query_row(
                    "SELECT COUNT(*) FROM oauth_tokens WHERE token_hash = ?1",
                    [&access],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(raw, 0);
        // the owner-chosen label becomes the consumer name
        let cid2 = client(&t).await;
        let code = get_code(&t, &cid2, "routine-nightly").await;
        let (_, v) = code_exchange(&t, &cid2, &code, VERIFIER).await;
        let validator = OAuthValidator {
            db: t.db.clone(),
            resource: RES.into(),
        };
        let p = validator.validate(&s(&v, "access_token")).await.unwrap();
        assert_eq!(p.name, "oauth:routine-nightly");
    }

    #[tokio::test]
    async fn pkce_wrong_verifier_fails_and_burns_code() {
        let t = setup();
        let cid = client(&t).await;
        let code = get_code(&t, &cid, "").await;
        let (st, v) = code_exchange(&t, &cid, &code, &"A".repeat(43)).await;
        assert_eq!(
            (st, v["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_grant"))
        );
        // the right verifier no longer works: the failed attempt consumed the code
        let (st, v) = code_exchange(&t, &cid, &code, VERIFIER).await;
        assert_eq!(
            (st, v["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_grant"))
        );
        let code = get_code(&t, &cid, "").await;
        assert_eq!(
            code_exchange(&t, &cid, &code, "short").await.0,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn code_replay_revokes_issued_tokens() {
        let t = setup();
        let cid = client(&t).await;
        let code = get_code(&t, &cid, "").await;
        let (st, v) = code_exchange(&t, &cid, &code, VERIFIER).await;
        assert_eq!(st, StatusCode::OK);
        let (access, rt) = (s(&v, "access_token"), s(&v, "refresh_token"));
        assert_eq!(mcp_status(&t, &access).await, StatusCode::OK);
        assert_eq!(
            code_exchange(&t, &cid, &code, VERIFIER).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(mcp_status(&t, &access).await, StatusCode::UNAUTHORIZED);
        assert_eq!(refresh(&t, &cid, &rt).await.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn code_bound_to_client_redirect_and_resource() {
        let t = setup();
        let cid = client(&t).await;
        let other = client(&t).await;
        let code = get_code(&t, &cid, "").await;
        assert_eq!(
            code_exchange(&t, &other, &code, VERIFIER).await.1["error"],
            "invalid_grant"
        );
        let code = get_code(&t, &cid, "").await;
        let (st, _, v) = token_req(
            &t,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", &cid),
                ("redirect_uri", "https://claude.ai/api/mcp/other"),
                ("code_verifier", VERIFIER),
            ],
        )
        .await;
        assert_eq!(
            (st, v["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_grant"))
        );
        let code = get_code(&t, &cid, "").await;
        let (_, _, v) = token_req(
            &t,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", &cid),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
                ("resource", "https://evil.example/mcp"),
            ],
        )
        .await;
        assert_eq!(v["error"], "invalid_target");
        let (_, _, v) = token_req(&t, &[("grant_type", "password")]).await;
        assert_eq!(v["error"], "unsupported_grant_type");
        assert_eq!(
            code_exchange(&t, "nope", "x", VERIFIER).await.1["error"],
            "invalid_client"
        );
    }

    #[tokio::test]
    async fn refresh_rotation_and_reuse_detection() {
        let t = setup();
        let (cid, v) = authed(&t).await;
        let (a1, r1) = (s(&v, "access_token"), s(&v, "refresh_token"));
        let (st, v2) = refresh(&t, &cid, &r1).await;
        assert_eq!(st, StatusCode::OK, "{v2}");
        let (a2, r2) = (s(&v2, "access_token"), s(&v2, "refresh_token"));
        assert!(r1 != r2 && a1 != a2);
        assert_eq!(mcp_status(&t, &a2).await, StatusCode::OK);
        // another client cannot use it (and that does not kill the family)
        let other = client(&t).await;
        assert_eq!(refresh(&t, &other, &r2).await.1["error"], "invalid_grant");
        let (st, v3) = refresh(&t, &cid, &r2).await;
        assert_eq!(st, StatusCode::OK);
        let (a3, r3) = (s(&v3, "access_token"), s(&v3, "refresh_token"));
        // reuse of a rotated token: invalid_grant, and the whole family dies
        assert_eq!(refresh(&t, &cid, &r1).await.1["error"], "invalid_grant");
        assert_eq!(mcp_status(&t, &a3).await, StatusCode::UNAUTHORIZED);
        assert_eq!(refresh(&t, &cid, &r3).await.1["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn expired_revoked_and_unbound_tokens_are_rejected() {
        let t = setup();
        let (cid, v) = authed(&t).await;
        let (a, r) = (s(&v, "access_token"), s(&v, "refresh_token"));
        assert_eq!(mcp_status(&t, &a).await, StatusCode::OK);
        sql(
            &t,
            "UPDATE oauth_tokens SET expires_at = '2000-01-01T00:00:00Z' WHERE kind = 'access'",
        );
        let (st, h, _) = mcp_call(&t, &a, "203.0.113.5").await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        let www = h[header::WWW_AUTHENTICATE].to_str().unwrap();
        assert!(
            www.contains("error=\"invalid_token\"") && www.contains("resource_metadata="),
            "{www}"
        );
        sql(
            &t,
            "UPDATE oauth_tokens SET expires_at = '2000-01-01T00:00:00Z' WHERE kind = 'refresh'",
        );
        assert_eq!(refresh(&t, &cid, &r).await.1["error"], "invalid_grant");
        // cleanup removes the long-expired rows
        assert!(t.db.with_conn(|c| cleanup(c)).unwrap() > 0);
        assert_eq!(count(&t, "SELECT COUNT(*) FROM oauth_tokens"), 0);

        // revocation kills the family
        let (_, v) = authed(&t).await;
        let a = s(&v, "access_token");
        let rq = req("POST", "/revoke")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form(&[("token", &s(&v, "refresh_token"))])))
            .unwrap();
        assert_eq!(send(&t, rq, "203.0.113.3").await.0, StatusCode::OK);
        assert_eq!(mcp_status(&t, &a).await, StatusCode::UNAUTHORIZED);

        // a token bound to another resource is not accepted
        let (_, v) = authed(&t).await;
        let a = s(&v, "access_token");
        assert_eq!(mcp_status(&t, &a).await, StatusCode::OK);
        sql(
            &t,
            "UPDATE oauth_tokens SET resource = 'https://other.example/mcp'",
        );
        assert_eq!(mcp_status(&t, &a).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_code_is_rejected() {
        let t = setup();
        let cid = client(&t).await;
        let code = get_code(&t, &cid, "").await;
        sql(
            &t,
            "UPDATE oauth_codes SET expires_at = '2000-01-01T00:00:00Z'",
        );
        assert_eq!(
            code_exchange(&t, &cid, &code, VERIFIER).await.1["error"],
            "invalid_grant"
        );
    }

    #[tokio::test]
    async fn authorize_request_validation() {
        let t = setup();
        let cid = client(&t).await;
        let chal = challenge(VERIFIER);
        // untrusted redirect_uri / client: error page, never a redirect
        for q in [
            authorize_query(&cid, "https://evil.example/cb", &chal, &[]),
            authorize_query(
                &cid,
                "https://claude.ai/api/mcp/auth_callback?x=1",
                &chal,
                &[],
            ),
            authorize_query("unknown", CB, &chal, &[]),
        ] {
            let (st, h, _) = get_authorize(&t, &q).await;
            assert_eq!(st, StatusCode::BAD_REQUEST);
            assert!(h.get(header::LOCATION).is_none());
        }
        // problems after the redirect_uri is trusted redirect back with an error
        let cases = [
            (
                authorize_query(&cid, CB, &chal, &[("resource", "https://evil.example/mcp")]),
                "invalid_target",
            ),
            (authorize_query(&cid, CB, "", &[]), "invalid_request"),
            (
                authorize_query(&cid, CB, &chal, &[])
                    .replace("response_type=code", "response_type=token"),
                "unsupported_response_type",
            ),
            (
                authorize_query(&cid, CB, &chal, &[]).replace("S256", "plain"),
                "invalid_request",
            ),
        ];
        for (q, err) in cases {
            let (st, h, _) = get_authorize(&t, &q).await;
            assert_eq!(st, StatusCode::FOUND, "{q}");
            let loc = Url::parse(h[header::LOCATION].to_str().unwrap()).unwrap();
            let q: HashMap<_, _> = loc.query_pairs().into_owned().collect();
            assert_eq!(q["error"], err);
            assert_eq!(q["state"], "xyz");
        }
        // the consent page itself
        let (_, h, body) =
            consent(&t, &authorize_query(&cid, CB, &chal, &[("resource", RES)])).await;
        assert_eq!(h["x-frame-options"], "DENY");
        assert!(
            h[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
        assert!(h[header::SET_COOKIE].to_str().unwrap().contains("HttpOnly"));
        assert!(body.contains("<b>claude.ai</b>") && body.contains("type=password"));
        assert!(!body.contains("src=") && !body.contains("<script"));
    }

    #[tokio::test]
    async fn loopback_redirect_ignores_port() {
        let t = setup();
        let (st, v) = register_cb(&t, json!(["http://127.0.0.1:1111/callback"])).await;
        assert_eq!(st, StatusCode::CREATED);
        let cid = s(&v, "client_id");
        let chal = challenge(VERIFIER);
        let q = authorize_query(&cid, "http://127.0.0.1:2222/callback", &chal, &[]);
        assert_eq!(get_authorize(&t, &q).await.0, StatusCode::OK);
        let q = authorize_query(&cid, "http://127.0.0.1:2222/other", &chal, &[]);
        assert_eq!(get_authorize(&t, &q).await.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn consent_post_needs_csrf() {
        let t = setup();
        let cid = client(&t).await;
        let chal = challenge(VERIFIER);
        let (csrf, ..) = consent(&t, &authorize_query(&cid, CB, &chal, &[])).await;
        // no cookie
        let (st, h, _) = post_consent(&t, &cid, &chal, None, PASS, "", "203.0.113.2").await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        assert!(h.get(header::LOCATION).is_none());
        // cookie present but the form token differs
        let mk = |tok: &str, extra: &[(&str, &str)]| {
            let mut p = vec![
                ("client_id", cid.as_str()),
                ("redirect_uri", CB),
                ("response_type", "code"),
                ("code_challenge", chal.as_str()),
                ("code_challenge_method", "S256"),
                ("csrf", tok),
                ("passphrase", PASS),
            ];
            p.extend_from_slice(extra);
            req("POST", "/authorize")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", format!("warden_csrf={csrf}"))
                .body(Body::from(form(&p)))
                .unwrap()
        };
        assert_eq!(
            send(&t, mk("other", &[]), "203.0.113.2").await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(count(&t, "SELECT COUNT(*) FROM oauth_codes"), 0);
        // deny redirects with access_denied
        let (st, h, _) = send(
            &t,
            mk(&csrf, &[("deny", "1"), ("state", "xyz")]),
            "203.0.113.2",
        )
        .await;
        assert_eq!(st, StatusCode::FOUND);
        assert!(
            h[header::LOCATION]
                .to_str()
                .unwrap()
                .contains("error=access_denied")
        );
    }

    #[tokio::test]
    async fn wrong_passphrase_is_rate_limited() {
        let t = setup();
        let cid = client(&t).await;
        let chal = challenge(VERIFIER);
        let (csrf, ..) = consent(&t, &authorize_query(&cid, CB, &chal, &[])).await;
        for _ in 0..PW_FREE {
            let (st, _, body) =
                post_consent(&t, &cid, &chal, Some(&csrf), "wrong", "", "198.51.100.77").await;
            assert_eq!(st, StatusCode::UNAUTHORIZED);
            assert!(body.contains("Wrong passphrase"));
        }
        // even the right passphrase is refused for this address now...
        let (st, h, _) =
            post_consent(&t, &cid, &chal, Some(&csrf), PASS, "", "198.51.100.77").await;
        assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
        assert!(h.contains_key(header::RETRY_AFTER));
        // ...another address is unaffected
        let (st, ..) = post_consent(&t, &cid, &chal, Some(&csrf), PASS, "", "198.51.100.78").await;
        assert_eq!(st, StatusCode::FOUND);
        // a bad label is a form error, not a redirect
        let (st, ..) = post_consent(
            &t,
            &cid,
            &chal,
            Some(&csrf),
            PASS,
            "bad label!",
            "198.51.100.79",
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn limiter_global_lockout_and_backoff() {
        let l = PassphraseLimiter::default();
        for i in 0..PW_GLOBAL_MAX {
            l.failure(format!("10.0.{}.{}", i / 200, i % 200 + 1).parse().unwrap());
        }
        assert!(l.check("192.0.2.1".parse().unwrap()).is_err());
        let l = PassphraseLimiter::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        l.failure(ip);
        l.failure(ip);
        assert!(l.check(ip).is_ok());
        l.failure(ip);
        assert!(l.check(ip).is_err());
        l.success(ip);
        assert!(l.check(ip).is_ok());
    }

    #[test]
    fn hash_check_and_verify() {
        let h = Argon2::default()
            .hash_password(b"pw-pw-pw-pw-pw")
            .unwrap()
            .to_string();
        assert!(h.starts_with("$argon2"));
        assert!(check_hash(&h).is_ok());
        assert!(check_hash("plaintext").is_err());
        assert!(verify_passphrase(&h, "pw-pw-pw-pw-pw"));
        assert!(!verify_passphrase(&h, "nope"));
    }

    #[tokio::test]
    async fn limiter_uses_forwarded_ip_and_spares_valid_tokens() {
        let t = setup_with(
            Config::from_lookup(|k| {
                (k == "WARDEN_TRUSTED_PROXIES").then(|| "10.0.0.0/8".to_owned())
            })
            .unwrap(),
        );
        let mk = |tok: &str, xff: &str| {
            let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}).to_string();
            Request::post("/mcp")
                .header("host", "localhost:8080")
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .header("authorization", format!("Bearer {tok}"))
                .header("x-forwarded-for", xff)
                .body(Body::from(body))
                .unwrap()
        };
        // attacker 198.51.100.50 behind the trusted proxy 10.0.0.1
        for _ in 0..crate::auth::MAX_FAILURES {
            assert_eq!(
                send(&t, mk("bad", "198.51.100.50"), "10.0.0.1").await.0,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            send(&t, mk("bad", "198.51.100.50"), "10.0.0.1").await.0,
            StatusCode::TOO_MANY_REQUESTS
        );
        // a spoofed left-most entry does not help the attacker
        assert_eq!(
            send(&t, mk("bad", "1.1.1.1, 198.51.100.50"), "10.0.0.1")
                .await
                .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        // another client behind the same proxy is unaffected
        assert_eq!(
            send(&t, mk("bad", "203.0.113.200"), "10.0.0.1").await.0,
            StatusCode::UNAUTHORIZED
        );
        // a valid credential works even from the blocked address
        assert_eq!(
            send(&t, mk("static-key", "198.51.100.50"), "10.0.0.1")
                .await
                .0,
            StatusCode::OK
        );
        // an untrusted peer cannot pick its identity with X-Forwarded-For
        for _ in 0..crate::auth::MAX_FAILURES {
            send(&t, mk("bad", "9.9.9.9"), "203.0.113.99").await;
        }
        assert_eq!(
            send(&t, mk("bad", "8.8.8.8"), "203.0.113.99").await.0,
            StatusCode::TOO_MANY_REQUESTS
        );
        // requests with no credentials are not counted as failures
        for _ in 0..20 {
            let r = Request::post("/mcp")
                .header("host", "localhost:8080")
                .header("x-forwarded-for", "203.0.113.150")
                .body(Body::empty())
                .unwrap();
            assert_eq!(send(&t, r, "10.0.0.1").await.0, StatusCode::UNAUTHORIZED);
        }
    }
}
