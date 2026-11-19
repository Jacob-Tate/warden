//! Runtime configuration, read from environment variables.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};

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
    pub nvd_api_key: Option<String>,
    pub sync_interval: Duration,
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
        let secs = match nonempty("WARDEN_SYNC_INTERVAL_SECS") {
            Some(v) => v
                .parse::<u64>()
                .context("WARDEN_SYNC_INTERVAL_SECS must be an integer")?,
            None => 3600,
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
            nvd_api_key: nonempty("NVD_API_KEY"),
            sync_interval: Duration::from_secs(secs.max(60)),
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
    fn rejects_bad_bind() {
        assert!(cfg(&[("WARDEN_BIND", "nope")]).is_err());
    }
}
