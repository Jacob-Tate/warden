//! Runtime configuration, read from environment variables.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone)]
pub struct Config {
    pub db_path: PathBuf,
    pub bind: SocketAddr,
    /// Externally visible base URL (no trailing slash).
    pub public_url: String,
    /// Static API keys accepted as bearer tokens.
    pub api_keys: Vec<String>,
    /// Hash of the owner passphrase for the OAuth consent page (Phase 2).
    pub owner_passphrase_hash: Option<String>,
    /// Allowed OAuth redirect URIs: exact URLs, or `scheme://host:*` (any port and path).
    pub oauth_redirect_allow: Vec<String>,
    /// `WARDEN_OAUTH_REGISTRATION=open|closed`: closed disables dynamic client registration.
    pub oauth_registration_open: bool,
    /// Refresh-token lifetime in days (sliding: renewed on every rotation).
    pub oauth_refresh_days: i64,
    /// Reverse proxies whose `X-Forwarded-For` / `Forwarded` / `X-Real-IP` are believed.
    pub trusted_proxies: Vec<ipnet::IpNet>,
    pub nvd_api_key: Option<String>,
    pub sync_interval: Duration,
    /// Unmatched, undelivered CVEs older than this many days are pruned.
    pub retention_days: i64,
    /// Window (days) before a product's creation in which CVEs still count as news.
    pub backfill_days: i64,
}

/// Default OAuth redirect allowlist: Claude's hosted callbacks plus loopback (Claude Code, Inspector).
pub const DEFAULT_REDIRECT_ALLOW: &[&str] = &[
    "https://claude.ai/api/mcp/auth_callback",
    "http://localhost:*",
    "http://127.0.0.1:*",
    "http://[::1]:*",
];

/// Parse a comma-separated list of IPs and CIDRs (a bare IP is a /32 or /128).
pub fn parse_proxies(v: &str) -> Result<Vec<ipnet::IpNet>> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<ipnet::IpNet>()
                .or_else(|_| s.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                .with_context(|| format!("WARDEN_TRUSTED_PROXIES: not an IP or CIDR: {s}"))
        })
        .collect()
}

/// Parse `3600`, `90s`, `30m`, `6h` or `1d`.
fn parse_duration_secs(v: &str) -> Result<u64> {
    let v = v.trim();
    let (num, mult) = match v.chars().last() {
        Some('s') => (&v[..v.len() - 1], 1),
        Some('m') => (&v[..v.len() - 1], 60),
        Some('h') => (&v[..v.len() - 1], 3600),
        Some('d') => (&v[..v.len() - 1], 86_400),
        _ => (v, 1),
    };
    Ok(num
        .trim()
        .parse::<u64>()
        .with_context(|| format!("not a duration (use e.g. 3600, 30m, 1h): {v}"))?
        * mult)
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Build a config from an arbitrary key lookup (keeps tests off the real environment).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let nonempty = |k: &str| {
            get(k)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };

        let bind = nonempty("WARDEN_BIND").unwrap_or_else(|| "0.0.0.0:8080".into());
        let secs = match (
            nonempty("WARDEN_SYNC_INTERVAL"),
            nonempty("WARDEN_SYNC_INTERVAL_SECS"),
        ) {
            (Some(v), _) => parse_duration_secs(&v).context("WARDEN_SYNC_INTERVAL")?,
            (None, Some(v)) => v
                .parse::<u64>()
                .context("WARDEN_SYNC_INTERVAL_SECS must be an integer")?,
            (None, None) => 3600,
        };
        let days = |k: &str, default: i64| -> Result<i64> {
            match nonempty(k) {
                Some(v) => v
                    .parse::<i64>()
                    .ok()
                    .filter(|d| *d >= 0)
                    .with_context(|| format!("{k} must be a non-negative integer")),
                None => Ok(default),
            }
        };
        Ok(Self {
            db_path: nonempty("WARDEN_DB_PATH")
                .unwrap_or_else(|| "./data/warden.db".into())
                .into(),
            bind: bind
                .parse()
                .with_context(|| format!("WARDEN_BIND is not a socket address: {bind}"))?,
            public_url: nonempty("WARDEN_PUBLIC_URL")
                .unwrap_or_else(|| "http://localhost:8080".into())
                .trim_end_matches('/')
                .to_owned(),
            api_keys: nonempty("WARDEN_API_KEYS")
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_owned())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            owner_passphrase_hash: nonempty("WARDEN_OWNER_PASSPHRASE_HASH"),
            oauth_redirect_allow: match nonempty("WARDEN_OAUTH_REDIRECT_ALLOW") {
                Some(v) => v
                    .split(',')
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect(),
                None => DEFAULT_REDIRECT_ALLOW
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect(),
            },
            oauth_registration_open: match nonempty("WARDEN_OAUTH_REGISTRATION")
                .map(|v| v.to_ascii_lowercase())
                .as_deref()
            {
                None | Some("open") => true,
                Some("closed") => false,
                Some(o) => bail!("WARDEN_OAUTH_REGISTRATION must be `open` or `closed`, got `{o}`"),
            },
            oauth_refresh_days: match days("WARDEN_OAUTH_REFRESH_DAYS", 30)? {
                0 => bail!("WARDEN_OAUTH_REFRESH_DAYS must be at least 1"),
                d => d.min(365),
            },
            trusted_proxies: nonempty("WARDEN_TRUSTED_PROXIES")
                .map(|v| parse_proxies(&v))
                .transpose()?
                .unwrap_or_default(),
            nvd_api_key: nonempty("NVD_API_KEY"),
            sync_interval: Duration::from_secs(secs.max(60)),
            retention_days: days("WARDEN_RETENTION_DAYS", 180)?,
            backfill_days: days("WARDEN_BACKFILL_DAYS", 14)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(pairs: &[(&str, &str)]) -> Result<Config> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect();
        Config::from_lookup(|k| m.get(k).cloned())
    }

    #[test]
    fn defaults() {
        let c = cfg(&[]).unwrap();
        assert_eq!(c.bind.port(), 8080);
        assert!(c.api_keys.is_empty());
        assert_eq!(c.sync_interval, Duration::from_secs(3600));
        assert_eq!((c.retention_days, c.backfill_days), (180, 14));
    }

    #[test]
    fn durations_and_days() {
        let c = cfg(&[
            ("WARDEN_SYNC_INTERVAL", "2h"),
            ("WARDEN_RETENTION_DAYS", "30"),
            ("WARDEN_BACKFILL_DAYS", "0"),
        ])
        .unwrap();
        assert_eq!(c.sync_interval, Duration::from_secs(7200));
        assert_eq!((c.retention_days, c.backfill_days), (30, 0));
        assert!(cfg(&[("WARDEN_SYNC_INTERVAL", "soon")]).is_err());
        assert!(cfg(&[("WARDEN_RETENTION_DAYS", "-1")]).is_err());
    }

    #[test]
    fn parses_values() {
        let c = cfg(&[
            ("WARDEN_API_KEYS", "a, b,,c"),
            ("WARDEN_PUBLIC_URL", "https://x.example/"),
            ("WARDEN_BIND", "127.0.0.1:9000"),
        ])
        .unwrap();
        assert_eq!(c.api_keys, ["a", "b", "c"]);
        assert_eq!(c.public_url, "https://x.example");
        assert_eq!(c.bind.port(), 9000);
    }

    #[test]
    fn oauth_and_proxy_settings() {
        let c = cfg(&[]).unwrap();
        assert!(
            c.oauth_redirect_allow
                .iter()
                .any(|r| r.contains("claude.ai"))
        );
        assert!(c.trusted_proxies.is_empty() && c.oauth_refresh_days == 30);
        let c = cfg(&[
            ("WARDEN_TRUSTED_PROXIES", "10.0.0.0/8, 192.168.1.5,::1"),
            ("WARDEN_OAUTH_REDIRECT_ALLOW", "https://a.example/cb"),
        ])
        .unwrap();
        assert_eq!(c.trusted_proxies.len(), 3);
        assert_eq!(c.oauth_redirect_allow, ["https://a.example/cb"]);
        assert!(cfg(&[("WARDEN_TRUSTED_PROXIES", "nope")]).is_err());
        assert!(cfg(&[("WARDEN_OAUTH_REFRESH_DAYS", "0")]).is_err());
    }

    #[test]
    fn rejects_bad_bind() {
        assert!(cfg(&[("WARDEN_BIND", "nope")]).is_err());
    }
}
