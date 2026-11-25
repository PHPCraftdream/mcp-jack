use super::server::{append_log_visible, parse_jack_auth, request_row, Args};
use bytes::Bytes;
use http_body_util::channel::Channel;
use http_body_util::BodyExt;
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};
use tower_service::Service;

#[derive(Default)]
pub(super) struct Controls {
    pub(super) clock: tokio::sync::Notify,
    pub(super) shutdown: tokio::sync::Notify,
    pub(super) release: tokio::sync::Notify,
    pub(super) held_done: tokio::sync::Notify,
    pub(super) held_active: AtomicBool,
    pub(super) shutdown_requested: AtomicBool,
    pub(super) release_requested: AtomicBool,
    pub(super) latest_clock: Mutex<Option<serde_json::Value>>,
    pub(super) held_sid: Mutex<Option<String>>,
}

pub(super) type HandlerTask = tokio::task::JoinHandle<()>;
pub(super) type StreamBody = Channel<Bytes, Infallible>;

// Bounds wrapper buffering; the SDK rejects bodies above its 1 MiB default.
const WRAPPER_BODY_CAP: usize = 4 * 1024 * 1024;

pub(super) struct SharedService<S> {
    inner: Arc<Mutex<S>>,
    controls: Arc<Controls>,
    args: Args,
}

impl<S> Clone for SharedService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            controls: self.controls.clone(),
            args: self.args.clone(),
        }
    }
}

impl<S> SharedService<S> {
    pub(super) fn new(service: S, controls: Arc<Controls>, args: Args) -> Self {
        Self {
            inner: Arc::new(Mutex::new(service)),
            controls,
            args,
        }
    }
}

impl<S> Service<http::Request<hyper::body::Incoming>> for SharedService<S>
where
    S: Service<http::Request<http_body_util::Full<Bytes>>, Response = http::Response<StreamBody>>
        + Send
        + 'static,
    S::Error: Send + 'static,
    S::Future: Send + 'static,
{
    type Response = http::Response<StreamBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .poll_ready(cx)
    }
    fn call(&mut self, request: http::Request<hyper::body::Incoming>) -> Self::Future {
        let (parts, body) = request.into_parts();
        let method = parts.method.clone();
        let target = parts
            .uri
            .path_and_query()
            .map(|v| v.as_str().to_owned())
            .unwrap_or_else(|| "/".to_owned());
        let headers = parts.headers.clone();
        let verified = parts
            .extensions
            .get::<mcp_jack::server::identity::VerifiedIdentity>()
            .is_some();
        let auth = parse_jack_auth(&headers);
        let bytes = http_body_util::Limited::new(body, WRAPPER_BODY_CAP).collect();
        let inner = self.inner.clone();
        let controls = self.controls.clone();
        let args = self.args.clone();
        Box::pin(async move {
            let bytes = match bytes.await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    // Over the wrapper cap: refused unsigned; driver bodies stay below it.
                    let (tx, body) = Channel::new(1);
                    drop(tx);
                    return Ok(http::Response::builder()
                        .status(http::StatusCode::PAYLOAD_TOO_LARGE)
                        .body(body)
                        .expect("static status is valid"));
                }
            };
            let request =
                http::Request::from_parts(parts, http_body_util::Full::new(bytes.clone()));
            let future = inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .call(request);
            let response = future.await?;
            if response.status() == http::StatusCode::UNAUTHORIZED {
                let (parts, body) = response.into_parts();
                let payload = body
                    .collect()
                    .await
                    .unwrap_or_else(|never| match never {})
                    .to_bytes();
                let parsed: serde_json::Value =
                    serde_json::from_slice(&payload).unwrap_or(serde_json::Value::Null);
                if parsed
                    .pointer("/error/code")
                    .and_then(serde_json::Value::as_str)
                    == Some("replayed_nonce")
                {
                    append_log_visible(
                        &args,
                        serde_json::json!({"event":"replayed_nonce", "nonce":auth.as_ref().map(|v| v.nonce.clone()), "request_sig":auth.as_ref().map(|v| v.sig.clone())}),
                        "replayed_nonce",
                    );
                }
                let (mut tx, body) = Channel::new(1);
                let _ = tx.send_data(payload).await;
                drop(tx);
                return Ok(http::Response::from_parts(parts, body));
            }
            if response.status() == http::StatusCode::OK
                && response
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.starts_with("text/event-stream"))
            {
                let sid = response
                    .headers()
                    .get("Jack-Auth")
                    .and_then(|v| v.to_str().ok())
                    .filter(|v| v.starts_with("s1 "))
                    .and_then(|value| value.strip_prefix("s1 "))
                    .and_then(|fields| {
                        fields
                            .split(',')
                            .map(str::trim)
                            .find_map(|field| field.strip_prefix("sid=").map(str::to_owned))
                    });
                if let Some(sid) = sid {
                    if let Ok(mut held) = controls.held_sid.lock() {
                        *held = Some(sid.clone());
                    }
                    let nonce = auth.as_ref().map(|value| value.nonce.clone());
                    let request_sig = auth.as_ref().map(|value| value.sig.clone());
                    if verified {
                        append_log_visible(
                            &args,
                            serde_json::json!({"event":"nonce_committed", "nonce":nonce,
                            "request_sig":request_sig, "nonce_committed_before_first_byte":true}),
                            "nonce_committed",
                        );
                    }
                    append_log_visible(
                        &args,
                        serde_json::json!({"event":"stream_open", "sid":sid, "nonce":nonce,
                        "request_sig":request_sig, "nonce_committed_before_first_byte":true}),
                        "stream_open",
                    );
                }
            }
            if response.status() == http::StatusCode::TOO_MANY_REQUESTS {
                let mut row = request_row(&method, &target, &headers, &bytes, true);
                row["refused"] = serde_json::json!(429);
                append_log_visible(&args, row, "request");
            }
            Ok(response)
        })
    }
}

pub(super) async fn wait_for_release(controls: &Controls) -> bool {
    controls.held_active.store(true, Ordering::Release);
    if controls.release_requested.load(Ordering::Acquire) {
        return true;
    }
    if controls.shutdown_requested.load(Ordering::Acquire) {
        return false;
    }
    let release = controls.release.notified();
    tokio::pin!(release);
    release.as_mut().enable();
    if controls.release_requested.load(Ordering::Acquire) {
        return true;
    }
    let shutdown = controls.shutdown.notified();
    tokio::pin!(shutdown);
    shutdown.as_mut().enable();
    if controls.shutdown_requested.load(Ordering::Acquire) {
        return false;
    }
    tokio::select! {
        _ = async { if !controls.release_requested.load(Ordering::Acquire) { release.await; } } => true,
        _ = &mut shutdown => false,
    }
}
