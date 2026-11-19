//! warden: self-hosted monitoring service.
//!
//! `warden [serve]` runs the HTTP server plus the sync scheduler; the other
//! subcommands run one operation against the configured database and exit (see
//! `warden help`).

// Some model/db helpers are only used by tests.
#![allow(dead_code)]

mod auth;
mod config;
mod db;
mod http;
mod mcp;
mod model;
mod monitors;
mod oauth;

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tracing_subscriber::EnvFilter;

use monitors::cve::{
    discovery::{self, Overrides},
    feed::{self, FeedOptions},
    sources::{self, SourceContext},
    sync::{self, Syncer},
    tracked,
};

const HELP: &str = "\
warden: CVE feed service

USAGE:
  warden [serve]                     run the HTTP server and the sync scheduler
  warden sync-once                   run one full sync pass now
  warden discover <name>             look a product up and print candidate definitions
  warden track-add <name> [--pick N] discover, then track the Nth (default 1st) candidate
  warden tracked                     list tracked products with match counts
  warden rematch                     re-match every tracked product against stored CVEs
  warden feed [--consumer X] [--limit N] [--product P] [--min-cvss S] [--include-acked] [--ack]
                                     print what is new for a consumer (default `cli`); --ack consumes it
  warden cve <CVE-ID>                print the full record of one CVE
  warden hash-passphrase             hash the owner passphrase for the OAuth consent page (reads stdin)
  warden hash-key [name]             generate an API key (printed once) and its WARDEN_API_KEYS entry

Environment: see .env.example (WARDEN_DB_PATH, WARDEN_SYNC_INTERVAL, WARDEN_RETENTION_DAYS, ...).";

/// Minimal flag parsing: `--flag value` pairs and bare switches.
struct Args {
    positional: Vec<String>,
    flags: Vec<(String, Option<String>)>,
}

impl Args {
    fn parse(raw: &[String]) -> Self {
        const SWITCHES: &[&str] = &["--ack", "--include-acked"];
        let mut positional = Vec::new();
        let mut flags = Vec::new();
        let mut it = raw.iter();
        while let Some(a) = it.next() {
            if a.starts_with("--") {
                let v = if SWITCHES.contains(&a.as_str()) {
                    None
                } else {
                    it.next().cloned()
                };
                flags.push((a.clone(), v));
            } else {
                positional.push(a.clone());
            }
        }
        Self { positional, flags }
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.flags
            .iter()
            .find(|(k, _)| k == name)
            .and_then(|(_, v)| v.as_deref())
    }

    fn has(&self, name: &str) -> bool {
        self.flags.iter().any(|(k, _)| k == name)
    }

    fn number<T: std::str::FromStr>(&self, name: &str) -> Result<Option<T>> {
        self.value(name)
            .map(|v| {
                v.parse::<T>()
                    .map_err(|_| anyhow::anyhow!("{name} needs a number, got {v}"))
            })
            .transpose()
    }
}

fn print_json<T: serde::Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let raw: Vec<String> = std::env::args().skip(1).collect();
    let cmd = raw.first().map(String::as_str).unwrap_or("serve");
    if matches!(cmd, "help" | "--help" | "-h") {
        println!("{HELP}");
        return Ok(());
    }
    let args = Args::parse(raw.get(1..).unwrap_or_default());
    if cmd == "hash-key" {
        print!(
            "{}",
            auth::hash_key_command(args.positional.first().map(String::as_str))?
        );
        return Ok(());
    }

    if cmd == "hash-passphrase" {
        print!("{}", oauth::hash_passphrase_command()?);
        return Ok(());
    }

    let config = Arc::new(config::Config::from_env()?);
    let db = db::Db::open(&config.db_path)
        .with_context(|| format!("opening database {}", config.db_path.display()))?;
    tracing::info!(path = %config.db_path.display(), "database ready");
    let syncer = Arc::new(Syncer::new(
        SourceContext {
            db: db.clone(),
            http: sources::build_client()?,
        },
        config.nvd_api_key.clone(),
        config.retention_days,
        config.backfill_days,
    ));

    match cmd {
        "serve" => serve(config, db, syncer).await,
        "sync-once" => {
            let summary = syncer.trigger_sync().await;
            match summary {
                Some(s) => println!("{}", s.line()),
                None => bail!("a sync is already running"),
            }
            Ok(())
        }
        "discover" => {
            let name = args.positional.join(" ");
            let r = discovery::discover(
                &db,
                discovery::build_client()?,
                config.nvd_api_key.clone(),
                &name,
            )
            .await?;
            print_json(&r)
        }
        "track-add" => {
            let name = args.positional.join(" ");
            let pick: usize = args.number("--pick")?.unwrap_or(1);
            let r = discovery::discover(
                &db,
                discovery::build_client()?,
                config.nvd_api_key.clone(),
                &name,
            )
            .await?;
            for w in &r.warnings {
                eprintln!("warning: {w}");
            }
            let cand = pick
                .checked_sub(1)
                .and_then(|i| r.candidates.get(i))
                .with_context(|| format!("no candidate #{pick} ({} found)", r.candidates.len()))?;
            let res = tracked::add_candidate(
                &syncer.ctx,
                Some(&syncer.nvd_api.api),
                cand,
                Overrides::default(),
                config.backfill_days,
            )
            .await?;
            print_json(&res)
        }
        "tracked" => {
            for t in tracked::list(&db).await? {
                let p = &t.product;
                println!(
                    "{:<28} {:<26} matches={:<5} mode={} cpes={} cna={} kev={}",
                    p.id,
                    p.name,
                    t.matches,
                    p.match_mode.as_str(),
                    p.cpes.len(),
                    p.cna_names.len(),
                    p.kev_names.len()
                );
            }
            Ok(())
        }
        "rematch" => {
            for t in tracked::list(&db).await? {
                let id = t.product.id.clone();
                let st = db
                    .call(move |c| db::match_repo::rematch_product(c, &id))
                    .await?;
                if let Some(st) = st {
                    println!(
                        "{:<28} candidates={:<6} matched={}",
                        t.product.id, st.candidates, st.matched
                    );
                }
            }
            Ok(())
        }
        "feed" => {
            let consumer = args.value("--consumer").unwrap_or("cli").to_owned();
            let opts = FeedOptions {
                limit: args.number("--limit")?.unwrap_or(feed::DEFAULT_LIMIT),
                product: args.value("--product").map(str::to_owned),
                min_cvss: args.number("--min-cvss")?,
                include_acked: args.has("--include-acked"),
                backfill_days: config.backfill_days,
            };
            let env = feed::get_new(&db, &consumer, &opts).await?;
            print_json(&env)?;
            if args.has("--ack") {
                let n = feed::ack_items(&db, &consumer, &env.items).await?;
                eprintln!("acked {n} item(s) for consumer {consumer}");
            }
            Ok(())
        }
        "cve" => {
            let id = args
                .positional
                .first()
                .context("usage: warden cve <CVE-ID>")?;
            match feed::cve_detail(&syncer.ctx, &syncer.nvd_api.api, id).await? {
                Some(v) => print_json(&v),
                None => bail!("{id} is not known locally or to NVD"),
            }
        }
        other => bail!("unknown command `{other}`; try `warden help`"),
    }
}

async fn serve(config: Arc<config::Config>, db: db::Db, syncer: Arc<Syncer>) -> Result<()> {
    let keys = auth::ApiKeyValidator::parse(&config.api_keys).context("WARDEN_API_KEYS")?;
    if keys.is_empty() {
        tracing::warn!(
            "WARDEN_API_KEYS is empty: every /mcp request will be rejected (run `warden hash-key`)"
        );
    }
    let oauth = oauth::from_config(db.clone(), &config).context("OAuth setup")?;
    let mut validators: Vec<Arc<dyn auth::TokenValidator>> = vec![Arc::new(keys)];
    match &oauth {
        Some(o) => {
            validators.push(Arc::new(o.validator()));
            tracing::info!(resource = %o.cfg.resource, "OAuth authorization server enabled");
        }
        None => tracing::info!(
            "WARDEN_OWNER_PASSPHRASE_HASH is not set: OAuth endpoints are disabled, only API keys work"
        ),
    }
    if !config.trusted_proxies.is_empty() {
        tracing::info!(
            count = config.trusted_proxies.len(),
            "trusting forwarded client IPs from proxies"
        );
    }
    let shutdown = tokio_util::sync::CancellationToken::new();
    let scheduler = tokio::spawn(sync::run_scheduler(syncer.clone(), config.sync_interval));
    let app = http::router(http::AppState {
        db,
        config: config.clone(),
        syncer,
        validators,
        shutdown: shutdown.clone(),
        oauth,
    });
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("binding {}", config.bind))?;
    tracing::info!(addr = %config.bind, public_url = %config.public_url, "listening");

    let stop = shutdown.clone();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        stop.cancel();
    })
    .await?;
    scheduler.abort();
    tracing::info!("shut down");
    Ok(())
}

async fn shutdown_signal() {
    if let Err(e) = tokio::signal::ctrl_c().await {
        tracing::error!("ctrl-c handler failed: {e}");
        std::future::pending::<()>().await;
    }
}
