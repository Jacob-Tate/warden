//! HTTP surface. Phase 1a only serves `/healthz`; MCP and OAuth routes join later.

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde_json::{Value, json};

use crate::{config::Config, db::Db};

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub config: std::sync::Arc<Config>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .with_state(state)
}

async fn healthz(State(s): State<AppState>) -> (StatusCode, Json<Value>) {
    let db_ok =
        s.db.call(|c| Ok(c.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?))
            .await
            .is_ok();
    if db_ok {
        (StatusCode::OK, Json(json!({"status": "ok", "db": "ok"})))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "degraded", "db": "error"})),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn healthz_reports_ok() {
        let state = AppState {
            db: Db::open_in_memory().unwrap(),
            config: std::sync::Arc::new(Config::from_lookup(|_| None).unwrap()),
        };
        let res = router(state)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v, json!({"status": "ok", "db": "ok"}));
    }
}
