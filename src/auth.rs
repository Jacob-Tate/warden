//! Authentication for `/mcp`.
//!
//! Every request needs `Authorization: Bearer <token>`. The token is offered to each
//! configured [`TokenValidator`] in turn; the first that recognizes it yields a
//! [`Principal`], which is stored in the request extensions (the MCP tools read it
//! to default the `consumer`). Today the only validator is [`ApiKeyValidator`]
//! (static keys from `WARDEN_API_KEYS`, stored as SHA-256 hashes); Phase 2b adds an
//! OAuth access-token validator by pushing a second implementation onto the list.
//!
//! Failures answer `401` with a `WWW-Authenticate: Bearer resource_metadata=...`
//! challenge. A small in-memory per-IP limiter answers `429` after too many failures.

use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The authenticated caller. `name` is the API key's name (or, later, the OAuth client).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub name: String,
}

pub type ValidateFuture<'a> = Pin<Box<dyn Future<Output = Option<Principal>> + Send + 'a>>;

/// A way of turning a bearer token into a [`Principal`].
pub trait TokenValidator: Send + Sync {
    fn validate<'a>(&'a self, token: &'a str) -> ValidateFuture<'a>;
}

/// Static API keys: `name:sha256hex` entries; only hashes are held in memory.
pub struct ApiKeyValidator {
    keys: Vec<(String, [u8; 32])>,
}

impl ApiKeyValidator {
    /// Parse `WARDEN_API_KEYS` entries (`name:sha256hex`).
    pub fn parse(entries: &[String]) -> Result<Self> {
        let mut keys: Vec<(String, [u8; 32])> = Vec::new();
        for e in entries {
            let Some((name, hex_hash)) = e.split_once(':') else {
                bail!(
                    "WARDEN_API_KEYS entries must look like `name:sha256hex` (run `warden hash-key`)"
                );
            };
            let name = name.trim();
            if name.is_empty()
                || name.len() > 64
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            {
                bail!("API key name `{name}` must be 1-64 chars of [A-Za-z0-9._-]");
            }
            let hash = decode_hex32(hex_hash.trim())
                .ok_or_else(|| anyhow::anyhow!("API key `{name}`: hash is not 64 hex chars"))?;
            if keys.iter().any(|(n, _)| n == name) {
                bail!("API key name `{name}` is listed twice");
            }
            keys.push((name.to_owned(), hash));
        }
        Ok(Self { keys })
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn check(&self, token: &str) -> Option<Principal> {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        // Compare against every key without early exit.
        let mut found: Option<&str> = None;
        for (name, hash) in &self.keys {
            if bool::from(digest.ct_eq(hash)) {
                found = Some(name);
            }
        }
        found.map(|n| Principal { name: n.to_owned() })
    }
}

impl TokenValidator for ApiKeyValidator {
    fn validate<'a>(&'a self, token: &'a str) -> ValidateFuture<'a> {
        Box::pin(async move { self.check(token) })
    }
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of a key, lower-case hex.
pub fn hash_key(key: &str) -> String {
    hex(&Sha256::digest(key.as_bytes()))
}

/// A fresh random key (32 bytes, base64url without padding).
pub fn generate_key() -> Result<String> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("random number generator failed: {e}"))?;
    Ok(URL_SAFE_NO_PAD.encode(b))
}

/// `warden hash-key [name]`: print a new key once plus the config line to store.
pub fn hash_key_command(name: Option<&str>) -> Result<String> {
    let name = name.unwrap_or("default");
    // Validate the name by round-tripping through the parser.
    let key = generate_key()?;
    let entry = format!("{name}:{}", hash_key(&key));
    ApiKeyValidator::parse(std::slice::from_ref(&entry))?;
    Ok(format!(
        "API key (shown once, store it in your client; warden keeps only the hash):\n\n  {key}\n\n\
         Add this to WARDEN_API_KEYS (comma-separate several entries):\n\n  WARDEN_API_KEYS={entry}\n"
    ))
}

// ---- failed-auth limiter ----------------------------------------------------------

/// Failures allowed per window before an address is blocked.
pub const MAX_FAILURES: usize = 10;
pub const FAILURE_WINDOW: Duration = Duration::from_secs(300);

/// In-memory per-IP failure counter.
#[derive(Default)]
pub struct FailureLimiter {
    failures: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl FailureLimiter {
    pub fn blocked(&self, ip: IpAddr) -> bool {
        let mut m = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        match m.get_mut(&ip) {
            Some(v) => {
                v.retain(|t| now.duration_since(*t) < FAILURE_WINDOW);
                if v.is_empty() {
                    m.remove(&ip);
                    false
                } else {
                    v.len() >= MAX_FAILURES
                }
            }
            None => false,
        }
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let mut m = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if m.len() > 10_000 {
            m.retain(|_, v| {
                v.last()
                    .is_some_and(|t| now.duration_since(*t) < FAILURE_WINDOW)
            });
        }
        m.entry(ip).or_default().push(now);
    }
}

// ---- middleware ------------------------------------------------------------------------

#[derive(Clone)]
pub struct AuthState {
    validators: Arc<Vec<Arc<dyn TokenValidator>>>,
    limiter: Arc<FailureLimiter>,
    challenge: HeaderValue,
}

impl AuthState {
    pub fn new(validators: Vec<Arc<dyn TokenValidator>>, public_url: &str) -> Self {
        let challenge = format!(
            "Bearer resource_metadata=\"{public_url}/.well-known/oauth-protected-resource\""
        );
        Self {
            validators: Arc::new(validators),
            limiter: Arc::new(FailureLimiter::default()),
            challenge: HeaderValue::from_str(&challenge)
                .unwrap_or_else(|_| HeaderValue::from_static("Bearer")),
        }
    }

    fn unauthorized(&self) -> Response {
        let mut r = Response::new(Body::from("unauthorized"));
        *r.status_mut() = StatusCode::UNAUTHORIZED;
        r.headers_mut()
            .insert(header::WWW_AUTHENTICATE, self.challenge.clone());
        r
    }
}

fn bearer(req: &Request) -> Option<&str> {
    let v = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim())
        .filter(|t| !t.is_empty())
}

/// axum middleware (`from_fn_with_state`): authenticate or answer 401/429.
pub async fn require_auth(State(st): State<AuthState>, mut req: Request, next: Next) -> Response {
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|p| p.0.ip());
    if let Some(ip) = ip
        && st.limiter.blocked(ip)
    {
        let mut r = Response::new(Body::from("too many failed authentication attempts"));
        *r.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        r.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from(FAILURE_WINDOW.as_secs()),
        );
        return r;
    }
    let mut principal = None;
    if let Some(token) = bearer(&req) {
        for v in st.validators.iter() {
            if let Some(p) = v.validate(token).await {
                principal = Some(p);
                break;
            }
        }
    }
    match principal {
        Some(p) => {
            req.extensions_mut().insert(p);
            next.run(req).await
        }
        None => {
            if let Some(ip) = ip {
                st.limiter.record_failure(ip);
            }
            st.unauthorized()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_validate() {
        let key = generate_key().unwrap();
        assert_eq!(key.len(), 43);
        let v = ApiKeyValidator::parse(&[
            format!("claude-code:{}", hash_key(&key)),
            format!("routine:{}", hash_key("other")),
        ])
        .unwrap();
        assert_eq!(v.check(&key).unwrap().name, "claude-code");
        assert_eq!(v.check("other").unwrap().name, "routine");
        assert!(v.check("nope").is_none());
        assert!(v.check("").is_none());
    }

    #[test]
    fn rejects_bad_entries() {
        let h = hash_key("x");
        let p = |s: &str| ApiKeyValidator::parse(&[s.to_owned()]);
        assert!(p("plaintextkey").is_err());
        assert!(p(&format!(":{h}")).is_err());
        assert!(p("a:abcd").is_err());
        assert!(p(&format!("bad name:{h}")).is_err());
        assert!(ApiKeyValidator::parse(&[format!("a:{h}"), format!("a:{h}")]).is_err());
        assert!(p(&format!("ok_1:{h}")).is_ok());
    }

    #[test]
    fn limiter_blocks_after_ten_failures() {
        let l = FailureLimiter::default();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..MAX_FAILURES - 1 {
            l.record_failure(ip);
        }
        assert!(!l.blocked(ip));
        l.record_failure(ip);
        assert!(l.blocked(ip));
        assert!(!l.blocked("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn hash_key_command_output() {
        let out = hash_key_command(Some("laptop")).unwrap();
        assert!(out.contains("WARDEN_API_KEYS=laptop:"));
        assert!(hash_key_command(Some("bad name")).is_err());
    }
}
