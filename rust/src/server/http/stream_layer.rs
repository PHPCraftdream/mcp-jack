//! Tower layer that adds the signed-stream profile of spec 05 to [`JackLayer`].
//!
//! Every request keeps the exact [`JackLayer`] behaviour; a request that opts
//! in with `Jack-Accept: s1` (1.1) in the modern era may open a signed stream
//! (2.1) instead of the v1 `501 streaming_unsupported`. The layer resolves the
//! 3.3-3.5 limits once per request, hands the handler the 3.5 heartbeat and
//! the 3.7 cancellation through request extensions, and replaces the buffered
//! answer with the live signed body when a stream was opened.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use tower_layer::Layer;
use tower_service::Service;

use super::stream::{channel_body, spawn_stream, StreamCancellation, StreamHeartbeat, StreamSeam};
use super::{BoxError, HandlerConfig, JackLayer, JackService, RotatingHandlerConfig};
use crate::server::modern::Profile;
use crate::server::response_keys::ResponseKeys;
use crate::server::stream::{StreamOptions, StreamRegistry};
use crate::server::verify::Verifier;

/// The response body of the stream layer: a buffered answer or a live signed stream.
pub type StreamBody = http_body_util::Channel<Bytes, std::convert::Infallible>;

/// Configures [`StreamLayer::new`]: the static signing profile plus the 3.8 stream options.
pub struct StreamConfig {
    pub verifier: Arc<Verifier>,
    pub server_key: ed25519_dalek::SigningKey,
    pub max_body_bytes: usize,
    pub max_response_bytes: usize,
    pub streams: crate::server::stream::StreamOptions,
}

/// Configures [`StreamLayer::rotating`]: the rotating response profile plus the 3.8 stream
/// options.
pub struct RotatingStreamConfig {
    pub verifier: Arc<Verifier>,
    pub response_keys: Arc<dyn ResponseKeys>,
    pub max_body_bytes: usize,
    pub max_response_bytes: usize,
    pub streams: crate::server::stream::StreamOptions,
}

/// A [`JackLayer`] plus the signed-stream profile: every request keeps the exact `JackLayer`
/// behaviour; a request carrying `Jack-Accept: s1` (1.1) in the modern era may open a signed
/// stream instead of the 501.
pub struct StreamLayer {
    jack: JackLayer,
    options: StreamOptions,
    registry: Arc<StreamRegistry>,
    profile: Profile,
}

impl StreamLayer {
    /// Static signing profile (see [`JackLayer::new`]).
    pub fn new(cfg: StreamConfig) -> Self {
        StreamLayer {
            jack: JackLayer::new(HandlerConfig {
                verifier: cfg.verifier,
                server_key: cfg.server_key,
                max_body_bytes: cfg.max_body_bytes,
                max_response_bytes: cfg.max_response_bytes,
            }),
            options: cfg.streams,
            registry: Arc::new(StreamRegistry::new()),
            profile: Profile::default(),
        }
    }

    /// Rotating response profile (see [`JackLayer::rotating`]).
    pub fn rotating(cfg: RotatingStreamConfig) -> Self {
        StreamLayer {
            jack: JackLayer::rotating(RotatingHandlerConfig {
                verifier: cfg.verifier,
                response_keys: cfg.response_keys,
                max_body_bytes: cfg.max_body_bytes,
                max_response_bytes: cfg.max_response_bytes,
            }),
            options: cfg.streams,
            registry: Arc::new(StreamRegistry::new()),
            profile: Profile::default(),
        }
    }

    /// Selects the modern-profile deployment setting exactly like
    /// [`JackLayer::with_profile`].
    pub fn with_profile(mut self, profile: Profile) -> Self {
        self.jack = self.jack.with_profile(profile);
        self.profile = profile;
        self
    }

    /// The 3.3 registry shared by every service this layer produces.
    pub fn registry(&self) -> Arc<StreamRegistry> {
        Arc::clone(&self.registry)
    }
}

impl<S> Layer<S> for StreamLayer {
    type Service = StreamService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        StreamService {
            jack: self.jack.layer(inner),
            options: self.options,
            registry: Arc::clone(&self.registry),
            profile: self.profile,
        }
    }
}

/// The service produced by [`StreamLayer`].
pub struct StreamService<S> {
    jack: JackService<S>,
    options: StreamOptions,
    registry: Arc<StreamRegistry>,
    profile: Profile,
}

/// Boxed like [`super::JackService`]'s future: the stream and the buffered path share it.
type StreamFuture<E> = Pin<Box<dyn Future<Output = Result<http::Response<StreamBody>, E>> + Send>>;

impl<B, S, ResBody> Service<http::Request<B>> for StreamService<S>
where
    S: Service<http::Request<Full<Bytes>>, Response = http::Response<ResBody>>
        + Clone
        + Send
        + 'static,
    S::Error: Send + 'static,
    S::Future: Send + 'static,
    ResBody: BodyExt + Send + 'static,
    ResBody::Error: Into<BoxError>,
    B: BodyExt + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = http::Response<StreamBody>;
    type Error = S::Error;
    type Future = StreamFuture<S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <JackService<S> as Service<http::Request<B>>>::poll_ready(&mut self.jack, cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        // 1.1: every UTF-8 `Jack-Accept` value contributes its tokens; a non-UTF-8 value
        // contributes nothing.
        let accepted: Vec<&str> = req
            .headers()
            .get_all("Jack-Accept")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect();
        let armed = crate::stream::accepts_s1(&accepted);
        // 1.2: a legacy deployment ignores `Jack-Accept` and keeps the 501.
        let mut seam = None;
        if armed && self.profile != Profile::Legacy {
            let limits = self.options.limits(self.jack.verifier.window_seconds());
            let created = Arc::new(StreamSeam::new(limits, Arc::clone(&self.registry)));
            req.extensions_mut().insert(Arc::clone(&created));
            req.extensions_mut()
                .insert(StreamCancellation::new(created.cancellation()));
            req.extensions_mut().insert(StreamHeartbeat {
                granted_ms: created.granted_heartbeat_ms(),
            });
            seam = Some(created);
        }
        // The instance readied by poll_ready serves this request; self keeps a
        // fresh clone for the next readiness cycle, exactly like JackService::call.
        let fresh = self.jack.inner.clone();
        let ready = std::mem::replace(&mut self.jack.inner, fresh);
        let mut jack = JackService {
            verifier: Arc::clone(&self.jack.verifier),
            signing: self.jack.signing.clone(),
            limit: self.jack.limit,
            response_limit: self.jack.response_limit,
            profile: self.jack.profile,
            inner: ready,
        };
        Box::pin(async move {
            let response = jack.serve(req).await?;
            let (parts, body) = response.into_parts();
            let body = match seam.as_ref().and_then(|seam| seam.take_work()) {
                Some(work) => spawn_stream(work),
                None => {
                    // No stream byte was written: the 3.3 slot of this request is released here
                    // on the buffered, refused and native paths alike.
                    if let Some(seam) = &seam {
                        seam.release_slot();
                    }
                    // `Full<Bytes>` cannot fail; a defensive empty body keeps the shape.
                    let bytes = match body.collect().await {
                        Ok(collected) => collected.to_bytes(),
                        Err(_) => Bytes::new(),
                    };
                    channel_body(bytes)
                }
            };
            Ok(http::Response::from_parts(parts, body))
        })
    }
}
