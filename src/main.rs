//! warden: self-hosted monitoring service. Phase 1a: config, DB, schema, /healthz.

// Phase 1a ships stubs and types that later phases call; remove once wired up.
#![allow(dead_code)]

mod auth;
mod config;
mod db;
mod http;
mod mcp;
mod model;
mod monitors;

use std::sync::Arc;

use anyhow::{Context, Result};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Arc::new(config::Config::from_env()?);
    let db = db::Db::open(&config.db_path)
        .with_context(|| format!("opening database {}", config.db_path.display()))?;
    tracing::info!(path = %config.db_path.display(), "database ready");

    let app = http::router(http::AppState {
        db,
        config: config.clone(),
    });
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("binding {}", config.bind))?;
    tracing::info!(addr = %config.bind, public_url = %config.public_url, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    tracing::info!("shut down");
    Ok(())
}

async fn shutdown_signal() {
    if let Err(e) = tokio::signal::ctrl_c().await {
        tracing::error!("ctrl-c handler failed: {e}");
        std::future::pending::<()>().await;
    }
}
