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

/// Download caps (bytes of the body as delivered to us, i.e. after any transport gzip).
pub(crate) const MAX_ZIP_BYTES: u64 = 200 * 1024 * 1024;
pub(crate) const MAX_KEV_BYTES: u64 = 20 * 1024 * 1024;
pub(crate) const MAX_EPSS_GZ_BYTES: u64 = 50 * 1024 * 1024;
pub(crate) const MAX_NVD_GZ_BYTES: u64 = 200 * 1024 * 1024;
/// Largest decompressed stream (gzip) accepted.
pub(crate) const MAX_DECOMPRESSED_BYTES: u64 = 1024 * 1024 * 1024;

/// A reader that fails (rather than silently truncating) once `limit` bytes have been read.
pub(crate) struct CapReader<R> {
    inner: R,
    left: u64,
}

impl<R> CapReader<R> {
    pub(crate) fn new(inner: R, limit: u64) -> Self {
        Self { inner, left: limit }
    }
}

impl<R: std::io::Read> std::io::Read for CapReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.left {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decompressed data exceeds the size limit",
            ));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

/// Stream a response body into `sink`, failing once more than `max` bytes arrive.
async fn stream_capped(
    mut resp: reqwest::Response,
    url: &str,
    max: u64,
    mut sink: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    if resp.content_length().is_some_and(|l| l > max) {
        anyhow::bail!("GET {url}: response is larger than the {max}-byte limit");
    }
    let mut seen = 0u64;
    while let Some(chunk) = resp
        .chunk()
        .await
        .with_context(|| format!("reading {url}"))?
    {
        seen += chunk.len() as u64;
        if seen > max {
            anyhow::bail!("GET {url}: response exceeded the {max}-byte limit");
        }
        sink(&chunk)?;
    }
    Ok(())
}

/// Read a response body into memory, capped at `max` bytes.
pub(crate) async fn read_body_capped(
    resp: reqwest::Response,
    url: &str,
    max: u64,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    stream_capped(resp, url, max, |c| {
        out.extend_from_slice(c);
        Ok(())
    })
    .await?;
    Ok(out)
}

/// Download a response body to a temp file in chunks (no full in-memory copy), capped at `max`.
pub(crate) async fn download_to_temp(
    client: &reqwest::Client,
    url: &str,
    max: u64,
) -> Result<tempfile::NamedTempFile> {
    use std::io::Write;
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("GET {url}"))?;
    let mut file = tempfile::NamedTempFile::new().context("creating temp file")?;
    stream_capped(resp, url, max, |c| Ok(file.write_all(c)?)).await?;
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

#[cfg(test)]
mod cap_tests {
    use super::testutil::{Canned, serve};
    use super::*;
    use std::io::Read;

    #[test]
    fn cap_reader_errors_instead_of_truncating() {
        let mut out = Vec::new();
        let r = CapReader::new(&b"0123456789"[..], 10).read_to_end(&mut out);
        assert!(r.is_ok() && out.len() == 10);
        let mut out = Vec::new();
        let e = CapReader::new(&b"0123456789x"[..], 10)
            .read_to_end(&mut out)
            .unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn downloads_are_capped() {
        let server = serve(|req, _| {
            let n: usize = req.path_and_query.trim_start_matches('/').parse().unwrap();
            Canned::ok(vec![b'x'; n])
        })
        .await;
        let client = build_client().unwrap();
        let get = |n: usize| {
            let (c, u) = (client.clone(), format!("{}/{n}", server.base));
            async move { c.get(&u).send().await.unwrap() }
        };
        let ok = read_body_capped(get(100).await, "u", 100).await.unwrap();
        assert_eq!(ok.len(), 100);
        let err = read_body_capped(get(101).await, "u", 100)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("limit"), "{err:#}");
        // temp-file variant
        let url = format!("{}/50", server.base);
        assert!(download_to_temp(&client, &url, 50).await.is_ok());
        let url = format!("{}/51", server.base);
        assert!(download_to_temp(&client, &url, 50).await.is_err());
    }
}
