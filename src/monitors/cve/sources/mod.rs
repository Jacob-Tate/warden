//! Upstream data sources. Each source persists its own cursor in
//! `source_status` (see `db::repo::{get_source_status, mark_success, mark_error}`).
//!
//! Every source exposes `sync(&self, ctx)`; endpoints are struct fields so
//! tests can point them at a local server. Failures are recorded with
//! `mark_error` and returned; the cursor only moves on success.

pub mod cvelist;
pub mod epss;
pub mod kev;
pub mod nvd_api;
pub mod nvd_feed;
pub mod nvd_parse;

use std::time::Duration;

use anyhow::{Context, Result};

use crate::db::{Db, repo};

pub const USER_AGENT: &str = concat!(
    "warden/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/Jacob-Tate/warden)"
);

/// Shared dependencies handed to every source run.
#[derive(Clone)]
pub struct SourceContext {
    pub db: Db,
    pub http: reqwest::Client,
}

/// Build the one shared HTTP client (UA, timeouts, redirects followed).
pub fn build_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(300))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .context("building HTTP client")
}

/// What one sync run accomplished.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    /// Records created or changed.
    pub changed: usize,
    /// Records skipped as unchanged / not tracked.
    pub skipped: usize,
    /// CVE ids created or changed (for the matcher). Empty for KEV/EPSS.
    pub changed_ids: Vec<String>,
    /// CVE ids seen for the first time by this source (KEV: newly added entries).
    pub new_ids: Vec<String>,
}

/// A pollable upstream source.
///
/// Implementations load their cursor from `source_status`, fetch, apply, and
/// call `mark_success`/`mark_error` themselves so the scheduler stays generic.
#[allow(async_fn_in_trait)] // used with concrete types only, never as `dyn`
pub trait Source {
    /// Stable key used in `source_status.source` and in feed health.
    fn name(&self) -> &'static str;

    /// Run one sync pass.
    async fn sync(&self, ctx: &SourceContext) -> anyhow::Result<SyncOutcome>;
}

/// Record the attempt, run `run`, and record the error if it fails.
pub(crate) async fn tracked<F>(
    ctx: &SourceContext,
    source: &'static str,
    run: F,
) -> Result<SyncOutcome>
where
    F: std::future::Future<Output = Result<SyncOutcome>>,
{
    ctx.db.call(move |c| repo::mark_attempt(c, source)).await?;
    match run.await {
        Ok(o) => Ok(o),
        Err(e) => {
            let msg = format!("{e:#}");
            tracing::warn!(source, error = %msg, "sync failed");
            let m = msg.clone();
            // Best effort: never mask the original error with a bookkeeping one.
            let _ = ctx.db.call(move |c| repo::mark_error(c, source, &m)).await;
            Err(e)
        }
    }
}

/// Download a response body to a temp file in chunks (no full in-memory copy).
pub(crate) async fn download_to_temp(
    client: &reqwest::Client,
    url: &str,
) -> Result<tempfile::NamedTempFile> {
    use std::io::Write;
    let mut resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("GET {url}"))?;
    let mut file = tempfile::NamedTempFile::new().context("creating temp file")?;
    while let Some(chunk) = resp
        .chunk()
        .await
        .with_context(|| format!("reading {url}"))?
    {
        file.write_all(&chunk)?;
    }
    file.flush()?;
    Ok(file)
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Local HTTP server helpers for tests.
#[cfg(test)]
pub(crate) mod testutil {
    use std::{
        net::SocketAddr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use axum::{
        Router,
        body::Body,
        extract::State,
        http::{HeaderMap, Request, StatusCode, header},
        response::Response,
    };

    /// One canned response.
    #[derive(Clone)]
    pub struct Canned {
        pub status: u16,
        pub headers: Vec<(String, String)>,
        pub body: Vec<u8>,
    }

    impl Canned {
        pub fn ok(body: impl Into<Vec<u8>>) -> Self {
            Self {
                status: 200,
                headers: vec![],
                body: body.into(),
            }
        }
        pub fn status(status: u16) -> Self {
            Self {
                status,
                headers: vec![],
                body: vec![],
            }
        }
        pub fn header(mut self, k: &str, v: &str) -> Self {
            self.headers.push((k.into(), v.into()));
            self
        }
    }

    /// Request seen by the test server.
    #[derive(Debug, Clone)]
    pub struct Seen {
        pub path_and_query: String,
        pub headers: HeaderMap,
    }

    type Handler = Arc<dyn Fn(&Seen, usize) -> Canned + Send + Sync>;

    #[derive(Clone)]
    struct St {
        handler: Handler,
        hits: Arc<AtomicUsize>,
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    pub struct TestServer {
        pub base: String,
        pub hits: Arc<AtomicUsize>,
        pub seen: Arc<Mutex<Vec<Seen>>>,
    }

    impl TestServer {
        pub fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
        pub fn requests(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
    }

    async fn handle(State(st): State<St>, req: Request<Body>) -> Response {
        let seen = Seen {
            path_and_query: req
                .uri()
                .path_and_query()
                .map(|p| p.as_str().to_owned())
                .unwrap_or_default(),
            headers: req.headers().clone(),
        };
        st.seen.lock().unwrap().push(seen.clone());
        let n = st.hits.fetch_add(1, Ordering::SeqCst);
        let c = (st.handler)(&seen, n);
        let mut b = Response::builder().status(StatusCode::from_u16(c.status).unwrap());
        for (k, v) in &c.headers {
            b = b.header(k.as_str(), v.as_str());
        }
        if !c
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            b = b.header(header::CONTENT_TYPE, "application/octet-stream");
        }
        b.body(Body::from(c.body)).unwrap()
    }

    /// Serve every request through `handler(request, zero_based_hit_index)`.
    pub async fn serve(
        handler: impl Fn(&Seen, usize) -> Canned + Send + Sync + 'static,
    ) -> TestServer {
        let st = St {
            handler: Arc::new(handler),
            hits: Arc::new(AtomicUsize::new(0)),
            seen: Arc::new(Mutex::new(Vec::new())),
        };
        let (hits, seen) = (st.hits.clone(), st.seen.clone());
        let app = Router::new().fallback(handle).with_state(st);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        TestServer {
            base: format!("http://{addr}"),
            hits,
            seen,
        }
    }

    pub fn fixture(name: &str) -> Vec<u8> {
        let p = format!(
            "{}/tests/fixtures/sources/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read(&p).unwrap_or_else(|e| panic!("reading fixture {p}: {e}"))
    }

    pub fn ctx() -> super::SourceContext {
        super::SourceContext {
            db: crate::db::Db::open_in_memory().unwrap(),
            http: super::build_client().unwrap(),
        }
    }
}
