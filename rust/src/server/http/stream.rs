//! Transport plumbing of the signed-stream profile (spec 05 sections 1, 2.1,
//! 3.3, 3.5-3.8 and 5.1): the seam the layer hands to the request, the open
//! header writer, the blocking body pump and the response body it feeds.
//!
//! The seam carries the per-identity 3.3 admission, the cancellation flag of
//! 3.7 and the granted heartbeat of 3.5 across the [`JackService`] call; the
//! adapter itself stays synchronous, so a spawned thread drives the handler's
//! body while the response is a [`http_body_util::Channel`] the transport
//! polls.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use http_body_util::channel::Sender;
use http_body_util::{BodyExt, Channel};
use tower_service::Service;

use super::stream_layer::StreamBody;
use super::wire::stream_limit_body;
use super::{BoxError, JackService, SigningProfile, CONTENT_TYPE};
use crate::client::transport::Clock;
use crate::encoding::{encode_b64url, key_id};
use crate::server::response_keys::{
    ReleaseGuard, ResponseKeyAuthorization, ResponseKeyRequest, ResponseSigner,
};
use crate::server::stream::{
    StreamLimits, StreamPipe, StreamPipeConfig, StreamRegistry, StreamSlot,
};
use crate::server::verify::VerifyResult;
use crate::stream::{format_open_auth, OpenAuth, StaticStreamSigner, StreamBuilder, StreamSigner};

/// 3.7: trip on client disconnect and after the end frame, so a handler can observe that the
/// stream's request context was cancelled. Cloned into the forwarded request extensions.
#[derive(Debug, Clone, Default)]
pub struct StreamCancellation(Arc<AtomicBool>);

impl StreamCancellation {
    /// Crate-only constructor: the seam owns the one flag every handle shares.
    pub(crate) fn new(cancellation: Arc<AtomicBool>) -> Self {
        StreamCancellation(cancellation)
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// 3.5: the granted heartbeat interval handed to the handler in the forwarded request
/// extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamHeartbeat {
    pub granted_ms: u64,
}

/// One 3.4 wake window: no handler byte for this long advances the pump clock and, when nothing
/// else is written, emits the 2.12 comment keep-alive. This is transport-only; it is not the
/// signed heartbeat granted to the handler and does not reset client idle state.
const MAX_WAKE_MS: u64 = 250;

/// What one `ChunkSource` poll produced.
pub(crate) enum ChunkOutcome {
    /// Handler bytes that arrived before the deadline.
    Data(Bytes),
    /// A frame without a data value (trailers); nothing to sign.
    Skip,
    /// The handler body ended.
    End,
    /// The deadline expired first.
    Timeout,
    /// The handler body failed; the stream closes with the end frame.
    Error,
}

/// A body the pump can pull without an async context of its own.
pub(crate) trait ChunkSource: Send {
    fn next_chunk(&mut self, deadline: Option<Instant>) -> ChunkOutcome;
}

/// The per-request seam between the HTTP adapter and the pump: the resolved
/// limits, the 3.3 slot, the 3.7 flag and the 3.5 grant.
pub(crate) struct StreamSeam {
    limits: StreamLimits,
    registry: Arc<StreamRegistry>,
    cancellation: Arc<AtomicBool>,
    heartbeat_ms: u64,
    slot: Mutex<Option<StreamSlot>>,
    work: Mutex<Option<StreamWork>>,
}

impl StreamSeam {
    pub(crate) fn new(limits: StreamLimits, registry: Arc<StreamRegistry>) -> Self {
        StreamSeam {
            limits,
            registry,
            cancellation: Arc::new(AtomicBool::new(false)),
            heartbeat_ms: limits.heartbeat_ms,
            slot: Mutex::new(None),
            work: Mutex::new(None),
        }
    }

    /// 3.5: the heartbeat value granted to the handler and the client.
    pub(crate) fn granted_heartbeat_ms(&self) -> u64 {
        self.heartbeat_ms
    }

    /// The one 3.7 flag, shared with the handler's [`StreamCancellation`].
    pub(crate) fn cancellation(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancellation)
    }

    /// 3.3: reserves the identity's slot; false when the ceiling is reached and no stream byte
    /// may be written.
    pub(crate) fn admit(&self, identity: &str) -> bool {
        let mut slot = self.lock_slot();
        if slot.is_some() {
            return true;
        }
        match self
            .registry
            .try_acquire(identity, self.limits.max_concurrent_streams)
        {
            Some(acquired) => {
                *slot = Some(acquired);
                true
            }
            None => false,
        }
    }

    /// Releases the 3.3 slot on every path that produced no stream.
    pub(crate) fn release_slot(&self) {
        let mut slot = self.lock_slot();
        *slot = None;
    }

    /// Moves the admitted slot into the stream work, which then owns the release.
    pub(crate) fn take_slot(&self) -> Option<StreamSlot> {
        self.lock_slot().take()
    }

    pub(crate) fn set_work(&self, work: StreamWork) {
        *self.lock_work() = Some(work);
    }

    pub(crate) fn take_work(&self) -> Option<StreamWork> {
        self.lock_work().take()
    }

    fn lock_slot(&self) -> MutexGuard<'_, Option<StreamSlot>> {
        self.slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_work(&self) -> MutexGuard<'_, Option<StreamWork>> {
        self.work
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Everything one opened stream still needs after its open header was signed.
pub(crate) struct StreamWork {
    inner: Box<dyn ChunkSource + Send>,
    sid: String,
    open_sig: String,
    open_ts: i64,
    limits: StreamLimits,
    request_id: Option<String>,
    method: String,
    /// The key cutoff is re-read while the stream is live.
    cutoff: Box<dyn Fn() -> Option<i64> + Send + Sync>,
    signer: Arc<dyn StreamSigner>,
    clock: Clock,
    release: Option<ReleaseGuard>,
    /// The 3.3 slot, released when the work is dropped on every path.
    slot: StreamSlot,
    cancellation: Arc<AtomicBool>,
}

/// A handler body polled from the pump thread.
///
/// `BodyExt::frame` needs an `Unpin` body, so the adapter pins the handler's
/// body once and hands the pump `BodyPump<Pin<Box<B>>>`.
pub(crate) struct BodyPump<B>(B);

impl<B> ChunkSource for BodyPump<std::pin::Pin<Box<B>>>
where
    B: BodyExt + Send + 'static,
    B::Error: Into<BoxError>,
{
    fn next_chunk(&mut self, deadline: Option<Instant>) -> ChunkOutcome {
        match block_on_until(self.0.frame(), deadline) {
            None => ChunkOutcome::Timeout,
            Some(None) => ChunkOutcome::End,
            Some(Some(Ok(frame))) => match frame.into_data() {
                Ok(mut data) => {
                    let len = data.remaining();
                    ChunkOutcome::Data(data.copy_to_bytes(len))
                }
                // Trailer frames carry no data value; nothing is signable.
                Err(_) => ChunkOutcome::Skip,
            },
            Some(Some(Err(_))) => ChunkOutcome::Error,
        }
    }
}

/// Parks the pump thread until `future` completes or `deadline` passes (`None` on expiry).
fn block_on_until<F: Future>(future: F, deadline: Option<Instant>) -> Option<F::Output> {
    let mut future = Box::pin(future);
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return Some(output);
        }
        match deadline {
            None => std::thread::park(),
            Some(deadline) => {
                let now = Instant::now();
                if now >= deadline {
                    return None;
                }
                std::thread::park_timeout(deadline - now);
            }
        }
    }
}

fn earliest_deadline(
    now: Instant,
    wake_ms: u64,
    duration: Option<Instant>,
    cutoff: Option<Instant>,
) -> Instant {
    let wake = now.checked_add(Duration::from_millis(wake_ms));
    [wake, duration, cutoff]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(now)
}

/// Polling cancellation at short intervals also detects a peer-close flag without requiring a
/// wake-up from the channel future.
fn block_on_until_or_cancelled<F: Future>(
    future: F,
    deadline: Instant,
    cancellation: &AtomicBool,
) -> Option<F::Output> {
    let mut future = Box::pin(future);
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
        if cancellation.load(Ordering::SeqCst) {
            return None;
        }
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return Some(output);
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        std::thread::park_timeout((deadline - now).min(Duration::from_millis(1)));
    }
}

/// Polls the final end send once. The slot must be released even if the receiver has stopped
/// draining, so the terminal frame is best-effort rather than another bounded wait.
fn try_send_data(tx: &mut Sender<Bytes, std::convert::Infallible>, chunk: Bytes) {
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut send = Box::pin(tx.send_data(chunk));
    let _ = send.as_mut().poll(&mut cx);
}

/// A deadline-free wait: the signalled future always completes.
fn block_on<F: Future>(future: F) -> F::Output {
    block_on_until(future, None).expect("a deadline-free wait never expires")
}

/// A waker that unparks the pump thread; no unsafe and no executor is involved.
struct ThreadWaker(std::thread::Thread);

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

impl<S, ResBody> JackService<S>
where
    S: Service<http::Request<http_body_util::Full<Bytes>>, Response = http::Response<ResBody>>
        + Clone
        + Send
        + 'static,
    S::Error: Send + 'static,
    S::Future: Send + 'static,
    ResBody: BodyExt + Send + 'static,
    ResBody::Error: Into<BoxError>,
{
    /// 3.3: the signed 429 whose body is exactly the concurrency refusal of the spec.
    pub(super) fn stream_limit(
        &self,
        res: &VerifyResult,
        head: bool,
    ) -> http::Response<http_body_util::Full<Bytes>> {
        let body = stream_limit_body(res.rpc_id.as_deref());
        self.signed(head, 429, res, body.into_bytes().into())
    }

    /// 2.1: signs the open header and stores the stream work in the seam. The placeholder body is
    /// replaced by the [`crate::server::http::StreamService`] with the live stream.
    pub(super) fn open_stream(
        &self,
        res: &VerifyResult,
        _inner_parts: http::response::Parts,
        inner_body: ResBody,
        method: String,
        seam: &StreamSeam,
    ) -> http::Response<http_body_util::Full<Bytes>> {
        // 2.4: a random 16-byte sid; a failing OS source is an internal error like any other
        // unmarshalable answer.
        let mut sid_bytes = [0u8; 16];
        if getrandom::fill(&mut sid_bytes).is_err() {
            return self.internal(res, false);
        }
        let sid = encode_b64url(&sid_bytes);
        // 3.1/5.1: the open header and every frame read the one injected clock of the
        // server, so an injected verifier clock keeps the stream inside the client's window.
        let clock: Clock = {
            let verifier = Arc::clone(&self.verifier);
            Arc::new(move || verifier.now())
        };
        let open_ts = (clock)();

        let mut release: Option<ReleaseGuard> = None;
        let mut live_cutoff: Box<dyn Fn() -> Option<i64> + Send + Sync> = Box::new(|| None);
        let (signer, open_sig, jack_auth): (Arc<dyn StreamSigner>, String, String) = match &self
            .signing
        {
            SigningProfile::Static { key, kid } => {
                // 3.1: the open header and every frame use the same static key.
                let signer: Arc<dyn StreamSigner> =
                    Arc::new(StaticStreamSigner::new((**key).clone(), None));
                let Some((_, open)) =
                    StreamBuilder::open(200, &res.request_sig, kid, open_ts, &sid, &*signer)
                else {
                    return self.internal(res, false);
                };
                (signer, open.sig, open.jack_auth)
            }
            SigningProfile::Rotating { keys } => {
                let input = ResponseKeyRequest {
                    status: 200,
                    tool: &res.tool,
                    request_signature: &res.request_sig,
                    body: &[],
                };
                let Ok(auth) = keys.authorize_response(&input) else {
                    return super::unsigned_rejection(
                        false,
                        503,
                        "rotation_state_unavailable",
                        "response authorization unavailable",
                    );
                };
                let ResponseKeyAuthorization {
                    signer: response_signer,
                    timestamp,
                    final_gate,
                    release: lease,
                } = auth;
                // Runs on EVERY path below, success and refusal alike.
                let guard = ReleaseGuard::new(lease);
                if timestamp > crate::rotation::MAX_TIMESTAMP {
                    return super::unsigned_rejection(
                        false,
                        503,
                        "rotation_state_unavailable",
                        "response authorization unavailable",
                    );
                }
                let public = response_signer.public_key();
                if crate::ed25519::validate_public_key(&public).is_err() {
                    return super::unsigned_rejection(
                        false,
                        503,
                        "rotation_state_unavailable",
                        "response authorization unavailable",
                    );
                }
                let kid = key_id(&public);
                // 2.5: the open string binds the stream to this request's sig.
                let signing =
                    crate::stream::open_signing_string(200, &res.request_sig, &kid, open_ts, &sid);
                let Ok(signature) = response_signer.sign(signing.as_bytes()) else {
                    return super::unsigned_rejection(
                        false,
                        503,
                        "rotation_state_unavailable",
                        "response authorization unavailable",
                    );
                };
                let Ok(signature) = <[u8; 64]>::try_from(signature.as_slice()) else {
                    return super::unsigned_rejection(
                        false,
                        503,
                        "rotation_state_unavailable",
                        "response authorization unavailable",
                    );
                };
                if !crate::ed25519::verify(&public, signing.as_bytes(), &signature) {
                    return super::unsigned_rejection(
                        false,
                        503,
                        "rotation_state_unavailable",
                        "response authorization unavailable",
                    );
                }
                // The completion sample re-confirms eligibility; a retired key fails here.
                if final_gate().is_err() {
                    return super::unsigned_rejection(
                        false,
                        503,
                        "rotation_state_unavailable",
                        "response authorization unavailable",
                    );
                }
                let open_sig = encode_b64url(&signature);
                let jack_auth = format_open_auth(&OpenAuth {
                    kid: kid.clone(),
                    ts: open_ts,
                    sid: sid.clone(),
                    sig: open_sig.clone(),
                });
                // 5.1: the successor activation of the opening key, when the provider knows it.
                let cutoff_keys = Arc::clone(keys);
                let cutoff_kid = kid.clone();
                live_cutoff = Box::new(move || cutoff_keys.successor_activation(&cutoff_kid));
                release = Some(guard);
                (
                    Arc::new(RotationStreamSigner(response_signer)),
                    open_sig,
                    jack_auth,
                )
            }
        };

        // The admitted slot moves into the work, which releases it on drop (3.3).
        let Some(slot) = seam.take_slot() else {
            return self.internal(res, false);
        };
        seam.set_work(StreamWork {
            // The handler body is pinned once: `BodyExt::frame` needs an `Unpin` body.
            inner: Box::new(BodyPump(Box::pin(inner_body))),
            sid,
            open_sig,
            open_ts,
            limits: seam.limits,
            request_id: res.rpc_id.clone(),
            method,
            cutoff: live_cutoff,
            signer,
            clock,
            release,
            slot,
            cancellation: seam.cancellation(),
        });

        // 2.1: exactly the success shape; the transport replaces the empty placeholder body.
        http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/event-stream")
            .header("X-Accel-Buffering", "no")
            .header("Jack-Auth", jack_auth)
            .body(http_body_util::Full::new(Bytes::new()))
            .expect("static status and header values cannot fail")
    }
}

/// Per-frame signer adapter of the rotating profile: a refused signature is the pump's
/// `SignerRefused` stop, never a different key.
struct RotationStreamSigner(Arc<dyn ResponseSigner>);

impl StreamSigner for RotationStreamSigner {
    fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        self.0.sign(message).ok()
    }
}

/// Spawns the pump and returns the body the transport polls. A thread that cannot be spawned
/// trips the 3.7 flag and leaves an empty body (the work is dropped with the closure).
pub(crate) fn spawn_stream(work: StreamWork) -> StreamBody {
    let (tx, body) = Channel::<Bytes, std::convert::Infallible>::new(1);
    let cancellation = Arc::clone(&work.cancellation);
    let spawned = std::thread::Builder::new()
        .name("jack-stream".to_owned())
        .spawn(move || pump(work, tx));
    if spawned.is_err() {
        cancellation.store(true, Ordering::SeqCst);
    }
    body
}

/// A one-frame body carrying an already buffered answer.
pub(crate) fn channel_body(bytes: Bytes) -> StreamBody {
    let (mut tx, body) = Channel::<Bytes, std::convert::Infallible>::new(1);
    if !bytes.is_empty() {
        let _ = block_on(tx.send_data(bytes));
    }
    drop(tx);
    body
}

/// The pump of one stream: it feeds the handler's body into the signer pipe and writes the
/// signed frames to the channel until the handler ends, fails, or the 3.4 duration closes it.
fn pump(work: StreamWork, mut tx: Sender<Bytes, std::convert::Infallible>) {
    let StreamWork {
        mut inner,
        sid,
        open_sig,
        open_ts,
        limits,
        request_id,
        method,
        cutoff,
        signer,
        clock,
        release: _release,
        slot: _slot,
        cancellation,
    } = work;
    let pump_started = Instant::now();
    let duration_deadline =
        pump_started.checked_add(Duration::from_millis(limits.max_stream_duration_ms));
    let epoch_ms = (clock)().saturating_mul(1000);
    let now_ms = || {
        epoch_ms
            .saturating_add(i64::try_from(pump_started.elapsed().as_millis()).unwrap_or(i64::MAX))
    };
    let mut cutoff_value = cutoff();
    let mut pipe = StreamPipe::new(StreamPipeConfig {
        sid,
        open_sig,
        open_ts,
        limits,
        request_id,
        method,
        cutoff: cutoff_value,
        started_ms: epoch_ms,
        signer,
    });
    // 3.4: the wake window is bounded by the 3.5 grant, so a heartbeat comment cannot outrun the
    // client's idle budget.
    let wake_ms = limits.heartbeat_ms.clamp(1, MAX_WAKE_MS);
    let mut out = Vec::new();
    loop {
        let now = Instant::now();
        cutoff_value = cutoff();
        pipe.update_cutoff(cutoff_value);
        let cutoff_deadline = cutoff_value.and_then(|activation| {
            let activation_ms = activation.saturating_mul(1000);
            // Reserve a full timestamp second for the signed end frame and its
            // channel handoff, rather than waking at the already-active key.
            let close_ms = activation_ms.saturating_sub(1000);
            let remaining_ms = close_ms.saturating_sub(now_ms());
            now.checked_add(Duration::from_millis(
                u64::try_from(remaining_ms).unwrap_or(0),
            ))
        });
        let deadline = earliest_deadline(now, wake_ms, duration_deadline, cutoff_deadline);
        let timeout_at_duration = duration_deadline.is_some_and(|duration| now >= duration)
            || cutoff_deadline.is_some_and(|cutoff| now >= cutoff);
        let running = if timeout_at_duration {
            let running = pipe.tick(now_ms(), &mut out);
            if running && out.is_empty() {
                out.extend_from_slice(b":\n");
            }
            running
        } else {
            match inner.next_chunk(Some(deadline)) {
                ChunkOutcome::Data(bytes) => {
                    let now_ms = now_ms();
                    pipe.push(&bytes, now_ms, &mut out)
                }
                ChunkOutcome::Skip => true,
                ChunkOutcome::End | ChunkOutcome::Error => false,
                ChunkOutcome::Timeout => {
                    let now_ms = now_ms();
                    let running = pipe.tick(now_ms, &mut out);
                    // 2.12: a wake that wrote nothing keeps the connection alive only.
                    if running && out.is_empty() {
                        out.extend_from_slice(b":\n");
                    }
                    running
                }
            }
        };
        if !out.is_empty() {
            let chunk = Bytes::from(std::mem::take(&mut out));
            let send_deadline = deadline;
            if block_on_until_or_cancelled(tx.send_data(chunk), send_deadline, &cancellation)
                .is_none_or(|result| result.is_err())
            {
                break;
            }
        }
        if !running {
            break;
        }
    }
    // 2.16 and 5.1: exactly one end frame, cut back below the cutoff.
    let now_ms = now_ms();
    pipe.finish(now_ms, &mut out);
    if !out.is_empty() {
        let chunk = Bytes::from(std::mem::take(&mut out));
        try_send_data(&mut tx, chunk);
    }
    // 3.7: the handler observes the cancelled request context when its body is dropped below.
    cancellation.store(true, Ordering::SeqCst);
}

pub(super) fn rpc_method(body: &[u8]) -> String {
    #[derive(serde::Deserialize)]
    struct RequestMethod<'a> {
        #[serde(borrow)]
        method: Option<&'a str>,
    }
    match serde_json::from_slice::<RequestMethod<'_>>(body) {
        Ok(request) => request.method.unwrap_or_default().to_owned(),
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::stream::StreamOptions;

    struct TwoChunkSource(usize);

    impl ChunkSource for TwoChunkSource {
        fn next_chunk(&mut self, _deadline: Option<Instant>) -> ChunkOutcome {
            if self.0 == 2 {
                return ChunkOutcome::End;
            }
            self.0 += 1;
            ChunkOutcome::Data(Bytes::from_static(b"data: {\"ok\":true}\n\n"))
        }
    }

    #[test]
    fn pump_blocked_capacity_one_send_observes_duration_and_releases_slot() {
        use ed25519_dalek::SigningKey;

        let registry = Arc::new(StreamRegistry::new());
        let slot = registry.try_acquire("identity", 1).expect("slot");
        let (tx, _body) = Channel::<Bytes, std::convert::Infallible>::new(1);
        let seed = [
            0xcc, 0x9e, 0x39, 0xe8, 0x30, 0xa4, 0x3e, 0x09, 0xc6, 0x37, 0x2b, 0x14, 0x85, 0x2e,
            0xf8, 0x0a, 0x2b, 0xb8, 0xe7, 0xb1, 0xaa, 0x4c, 0x04, 0xbf, 0x07, 0x6f, 0x33, 0xe0,
            0xaa, 0xd2, 0xc9, 0x01,
        ];
        let concrete_signer =
            Arc::new(StaticStreamSigner::new(SigningKey::from_bytes(&seed), None));
        let signer: Arc<dyn StreamSigner> = concrete_signer.clone();
        let open = StreamBuilder::open(
            200,
            "OsOug0yCJZPIkJ5Huk2UcIxlstzaz4b22EBRHfQHO0YgoHkDflI7kNPpSGO4HzueDASfxlEQRL1Kt45PN0pfBw",
            "wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88",
            1_767_225_600,
            "q9nUNYuH-Xf_cgJBVu4_Dg",
            concrete_signer.as_ref(),
        )
        .expect("static signer creates a valid open header")
        .1;
        let limits = StreamLimits {
            max_stream_duration_ms: 30,
            ..StreamOptions::default().limits(30)
        };
        let cancellation = Arc::new(AtomicBool::new(false));
        let work = StreamWork {
            inner: Box::new(TwoChunkSource(0)),
            sid: "q9nUNYuH-Xf_cgJBVu4_Dg".to_string(),
            open_sig: open.sig,
            open_ts: 1_767_225_600,
            limits,
            request_id: None,
            method: "GET".to_string(),
            cutoff: Box::new(|| None),
            signer,
            clock: Arc::new(|| 1_767_225_600),
            release: None,
            slot,
            cancellation: Arc::clone(&cancellation),
        };
        let (completed_tx, completed_rx) = std::sync::mpsc::channel();
        let pump_thread = std::thread::spawn(move || {
            pump(work, tx);
            let _ = completed_tx.send(());
        });

        completed_rx
            .recv_timeout(Duration::from_millis(250))
            .expect("pump must stop at the duration despite the undrained response");
        pump_thread.join().expect("pump thread must finish");
        assert!(
            cancellation.load(Ordering::SeqCst),
            "pump must cancel the request"
        );
        assert_eq!(registry.active("identity"), 0, "pump must release its slot");
    }

    #[test]
    fn blocked_capacity_one_send_is_bounded_by_cutoff() {
        let registry = Arc::new(StreamRegistry::new());
        let slot = registry.try_acquire("identity", 1).expect("slot");
        let (mut tx, _body) = Channel::<Bytes, std::convert::Infallible>::new(1);
        block_on(tx.send_data(Bytes::from_static(b"occupies capacity"))).expect("first frame fits");
        let now = Instant::now();
        let cutoff = now;
        let duration = now + Duration::from_secs(60);
        let deadline = earliest_deadline(now, MAX_WAKE_MS, Some(duration), Some(cutoff));
        assert_eq!(deadline, cutoff, "cutoff must bound a blocked send");
        assert!(block_on_until_or_cancelled(
            tx.send_data(Bytes::from_static(b"blocked")),
            deadline,
            &AtomicBool::new(false),
        )
        .is_none());
        drop(slot);
        assert_eq!(registry.active("identity"), 0);
    }
    #[test]
    fn final_end_send_is_best_effort_and_slot_releases_with_full_channel() {
        let registry = Arc::new(StreamRegistry::new());
        let slot = registry.try_acquire("identity", 1).expect("slot");
        let (mut tx, _body) = Channel::<Bytes, std::convert::Infallible>::new(1);
        block_on(tx.send_data(Bytes::from_static(b"occupies capacity"))).expect("first frame fits");

        try_send_data(&mut tx, Bytes::from_static(b"final end"));
        drop(slot);
        assert_eq!(registry.active("identity"), 0);
    }

    #[test]
    fn blocked_capacity_one_send_stops_on_cancellation() {
        let (mut tx, _body) = Channel::<Bytes, std::convert::Infallible>::new(1);
        block_on(tx.send_data(Bytes::from_static(b"occupies capacity"))).expect("first frame fits");
        let cancellation = AtomicBool::new(true);
        assert!(block_on_until_or_cancelled(
            tx.send_data(Bytes::from_static(b"blocked")),
            Instant::now() + Duration::from_secs(60),
            &cancellation,
        )
        .is_none());
    }
}
