//! HTTP surface: `/healthz` (unauthenticated, ok/stale only) and the authenticated
//! MCP endpoint at `/mcp`. OAuth routes join in Phase 2b.

use std::{sync::Arc, time::Duration};

use axum::{Json, Router, extract::State, http::StatusCode, middleware, routing::get};
use chrono::Utc;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer};

use crate::{
    auth::{self, AuthState, TokenValidator},
    config::Config,
    db::Db,
    mcp::{self, McpDeps},
    monitors::cve::{feed, sync::Syncer},
};

/// Largest accepted `/mcp` request body.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Whole-request timeout on `/mcp` (discovery is capped at 60 s inside the tool).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub config: Arc<Config>,
    pub syncer: Arc<Syncer>,
    /// Accepted bearer-token validators (API keys now, OAuth tokens later).
    pub validators: Vec<Arc<dyn TokenValidator>>,
    /// Cancelled on shutdown so MCP streams end.
    pub shutdown: CancellationToken,
}

pub fn router(state: AppState) -> Router {
    let deps = McpDeps::new(state.db.clone(), state.syncer.clone(), state.config.clone())
        .expect("building the MCP HTTP client");
    let mcp_svc = mcp::service(deps, state.shutdown.child_token());
    let auth_state = AuthState::new(state.validators.clone(), &state.config.public_url);
    let mcp_routes = Router::new()
        .nest_service("/mcp", mcp_svc)
        .layer(middleware::from_fn_with_state(
            auth_state,
            auth::require_auth,
        ))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES));
    Router::new()
        .route("/healthz", get(healthz))
        .with_state(state)
        .merge(mcp_routes)
}

/// `{"status":"ok"}`, `{"status":"stale"}` (a core source is out of date; still 200)
/// or 503 `{"status":"degraded"}` when the database is unreachable. Nothing else.
async fn healthz(State(s): State<AppState>) -> (StatusCode, Json<Value>) {
    let now = Utc::now();
    match s.db.call(move |c| feed::source_health(c, now)).await {
        Ok(h) => {
            let stale = ["cvelist", "kev"]
                .iter()
                .any(|k| h.get(*k).is_none_or(|x| x.stale));
            (
                StatusCode::OK,
                Json(json!({"status": if stale { "stale" } else { "ok" }})),
            )
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "degraded"})),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    pub fn test_state() -> AppState {
        let db = Db::open_in_memory().unwrap();
        let syncer = Arc::new(Syncer::new(
            crate::monitors::cve::sources::SourceContext {
                db: db.clone(),
                http: reqwest::Client::new(),
            },
            None,
            180,
            14,
        ));
        AppState {
            db,
            config: Arc::new(Config::from_lookup(|_| None).unwrap()),
            syncer,
            validators: vec![],
            shutdown: CancellationToken::new(),
        }
    }

    use crate::auth::{ApiKeyValidator, hash_key};
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;

    const KEY_A: &str = "alpha-secret-key";
    const KEY_B: &str = "beta-secret-key";

    fn app() -> (Router, Db) {
        let mut st = test_state();
        let keys = ApiKeyValidator::parse(&[
            format!("alpha:{}", hash_key(KEY_A)),
            format!("beta:{}", hash_key(KEY_B)),
        ])
        .unwrap();
        st.validators = vec![Arc::new(keys)];
        let db = st.db.clone();
        (router(st), db)
    }

    fn post(key: Option<&str>, body: &Value) -> Request<Body> {
        let mut b = Request::post("/mcp")
            .header("host", "localhost:8080")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream");
        if let Some(k) = key {
            b = b.header("authorization", format!("Bearer {k}"));
        }
        b.body(Body::from(body.to_string())).unwrap()
    }

    async fn send(app: &Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
        let res = app.clone().oneshot(req).await.unwrap();
        let (status, headers) = (res.status(), res.headers().clone());
        let bytes = axum::body::to_bytes(res.into_body(), 4 << 20)
            .await
            .unwrap();
        (
            status,
            headers,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    async fn rpc(app: &Router, key: &str, method: &str, params: Value) -> Value {
        let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let (st, _, text) = send(app, post(Some(key), &body)).await;
        assert_eq!(st, StatusCode::OK, "{text}");
        serde_json::from_str(&text).unwrap_or_else(|_| panic!("not json: {text}"))
    }

    /// Call a tool; returns (is_error, parsed text content).
    async fn call(app: &Router, key: &str, tool: &str, args: Value) -> (bool, Value) {
        let v = rpc(
            app,
            key,
            "tools/call",
            json!({"name": tool, "arguments": args}),
        )
        .await;
        let r = &v["result"];
        let text = r["content"][0]["text"].as_str().unwrap_or("").to_owned();
        let parsed = serde_json::from_str(&text).unwrap_or(Value::String(text));
        (r["isError"].as_bool().unwrap_or(false), parsed)
    }

    fn seed(db: &Db) {
        use crate::db::repo;
        use crate::model::{CnaName, MatchMode, TrackedProduct};
        let now = Utc::now();
        let created = (now - chrono::Duration::days(1)).to_rfc3339();
        let published = now.to_rfc3339();
        db.with_conn(|c| {
            repo::upsert_product(
                c,
                &TrackedProduct {
                    id: "widget".into(),
                    name: "Widget".into(),
                    cpes: vec![],
                    cna_names: vec![CnaName {
                        vendor: "Acme".into(),
                        product: "widget".into(),
                        source_cna: None,
                    }],
                    kev_names: vec![],
                    aliases: vec![],
                    keywords: vec![],
                    exclude_keywords: vec![],
                    match_mode: MatchMode::CpeNames,
                    confirmed_by: "test".into(),
                    created_at: created.clone(),
                    updated_at: created.clone(),
                },
            )?;
            c.execute(
                "INSERT INTO cves (cve_id, description, published, last_modified, first_seen_at, \
                     nvd_cvss_score, nvd_cvss_primary) \
                 VALUES ('CVE-2026-1111', 'Widget bug', ?1, ?1, ?1, 9.8, 1)",
                [&published],
            )?;
            c.execute(
                "INSERT INTO cve_product_matches (cve_id, product_id, matched_by, matched_at) \
                 VALUES ('CVE-2026-1111', 'widget', 'cna_name', 'x')",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    }

    #[tokio::test]
    async fn mcp_handshake_and_tools() {
        let (app, _) = app();
        let init = rpc(
            &app,
            KEY_A,
            "initialize",
            json!({"protocolVersion":"2025-06-18","capabilities":{},
                   "clientInfo":{"name":"test","version":"0"}}),
        )
        .await;
        assert_eq!(init["result"]["serverInfo"]["name"], "warden");
        assert!(
            init["result"]["instructions"]
                .as_str()
                .unwrap()
                .contains("ack")
        );

        let list = rpc(&app, KEY_A, "tools/list", json!({})).await;
        let mut names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "ack",
                "add_tracked",
                "cve_detail",
                "discover_product",
                "get_new_cves",
                "list_tracked",
                "remove_tracked",
                "sync_status",
                "trigger_sync",
                "update_tracked"
            ]
        );

        let (err, v) = call(&app, KEY_A, "list_tracked", json!({})).await;
        assert!(!err);
        assert_eq!(v, json!([]));
        let (err, v) = call(&app, KEY_A, "sync_status", json!({})).await;
        assert!(!err && v["stale"] == true && v["running"] == false, "{v}");
    }

    #[tokio::test]
    async fn rejects_missing_or_wrong_key() {
        let (app, _) = app();
        let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
        for key in [None, Some("wrong")] {
            let (st, h, _) = send(&app, post(key, &body)).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED);
            let www = h["www-authenticate"].to_str().unwrap();
            assert!(www.starts_with("Bearer resource_metadata=\""), "{www}");
            assert!(www.contains("/.well-known/oauth-protected-resource"));
        }
        // healthz needs no key
        let (st, _, _) = send(&app, Request::get("/healthz").body(Body::empty()).unwrap()).await;
        assert_eq!(st, StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_foreign_host_and_origin() {
        let (app, _) = app();
        let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
        let mut req = post(Some(KEY_A), &body);
        req.headers_mut()
            .insert("host", "evil.example".parse().unwrap());
        assert_eq!(send(&app, req).await.0, StatusCode::FORBIDDEN);
        let mut req = post(Some(KEY_A), &body);
        req.headers_mut()
            .insert("origin", "https://evil.example".parse().unwrap());
        assert_eq!(send(&app, req).await.0, StatusCode::FORBIDDEN);
        let mut req = post(Some(KEY_A), &body);
        req.headers_mut()
            .insert("origin", "https://claude.ai".parse().unwrap());
        assert_eq!(send(&app, req).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn consumer_defaults_to_key_name() {
        let (app, db) = app();
        seed(&db);
        let (_, v) = call(&app, KEY_A, "get_new_cves", json!({})).await;
        assert_eq!(v["items"].as_array().unwrap().len(), 1, "{v}");
        assert_eq!(v["items"][0]["cve"], "CVE-2026-1111");

        let (err, v) = call(&app, KEY_A, "ack", json!({"cve_ids": ["cve-2026-1111"]})).await;
        assert!(!err, "{v}");
        assert_eq!(v, json!({"acked": 1, "consumer": "alpha"}));

        // alpha's cursor moved; beta (a different key) still sees it; explicit consumer wins
        let (_, v) = call(&app, KEY_A, "get_new_cves", json!({})).await;
        assert!(v["items"].as_array().unwrap().is_empty());
        let (_, v) = call(&app, KEY_B, "get_new_cves", json!({})).await;
        assert_eq!(v["items"].as_array().unwrap().len(), 1);
        let (_, v) = call(&app, KEY_A, "get_new_cves", json!({"consumer": "beta"})).await;
        assert_eq!(v["items"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn user_mistakes_are_tool_errors() {
        let (app, _) = app();
        let (err, v) = call(&app, KEY_A, "cve_detail", json!({"cve_id": "nope"})).await;
        assert!(err && v.as_str().unwrap().contains("not a CVE id"), "{v}");
        let (err, _) = call(&app, KEY_A, "ack", json!({"cve_ids": []})).await;
        assert!(err);
        let (err, v) = call(&app, KEY_A, "remove_tracked", json!({"id": "ghost"})).await;
        assert!(err && v.as_str().unwrap().contains("list_tracked"));
        let (err, _) = call(&app, KEY_A, "update_tracked", json!({"id": "ghost"})).await;
        assert!(err);
    }

    #[tokio::test]
    async fn repeated_failures_get_429_and_big_bodies_413() {
        let (app, _) = app();
        let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
        let addr: SocketAddr = "203.0.113.9:5555".parse().unwrap();
        let with_ip = |mut r: Request<Body>| {
            r.extensions_mut().insert(ConnectInfo(addr));
            r
        };
        for _ in 0..crate::auth::MAX_FAILURES {
            let (st, ..) = send(&app, with_ip(post(Some("bad"), &body))).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED);
        }
        let (st, ..) = send(&app, with_ip(post(Some("bad"), &body))).await;
        assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
        // another address is unaffected
        let (st, ..) = send(&app, post(Some(KEY_A), &body)).await;
        assert_eq!(st, StatusCode::OK);

        let big = Request::post("/mcp")
            .header("host", "localhost")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("authorization", format!("Bearer {KEY_A}"))
            .header("content-length", MAX_BODY_BYTES + 10)
            .body(Body::from(vec![b' '; MAX_BODY_BYTES + 10]))
            .unwrap();
        assert_eq!(send(&app, big).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn healthz_reports_only_status() {
        let res = router(test_state())
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        // Fresh database: nothing has synced yet.
        assert_eq!(v, json!({"status": "stale"}));
    }
}
