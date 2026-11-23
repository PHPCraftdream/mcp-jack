//! The framework-neutral receiver state machine of spec 06 section 3
//! (R3.1-R3.18), plus R1.10, R5.6, R7.6 and R4.5/R4.6: one [`Receiver`] that
//! verifies a delivery, records its `webhook-id`, keeps its routing,
//! termination and secret state, and answers the response bodies the section 3
//! table assigns.
//!
//! Everything here is pure: `now` is an argument, the caller supplies the raw
//! headers, the body bytes and the durable-enqueue callback, and no function
//! performs I/O, reads a clock or logs a secret. The step order, the checks,
//! the error codes and the response bodies mirror `handle` of
//! `spec/tools/modern/webhooks/ref/receiver.mjs` exactly, so the same inputs
//! produce the same observable state.
//!
//! # Acknowledgement and durable enqueue (spec 06 R1.10)
//!
//! A `2xx` is returned only after the caller's enqueue callback reported
//! success, and only that `2xx` records the `webhook-id`: a failed enqueue
//! answers `503 enqueue_failed` and records nothing, so the sender's retry is
//! processed exactly once. A duplicate answer, an echoed verification
//! envelope and a delivery a pending secret authenticated without being that
//! envelope never call the callback at all: the last one is refused as
//! `503 subscription_not_routed` before the enqueue, so an unrouted event is
//! never persisted (spec 06 R3.8, R5.6).
//!
//! # Locking order (spec 06 R1.10, R3.16)
//!
//! One mutex guards all mutable state — routing, termination, secrets,
//! accepted ids and the in-flight set of [`dispatch`]. Steps 7 to 15 read it
//! under one short-lived guard, step 16 reserves the `webhook-id` under it,
//! and a delivery of an id another thread owns waits on the condition
//! variable, which releases the mutex while waiting. The enqueue callback, the
//! key source snapshot and the challenge echo of a verification envelope all
//! run with **no lock held**, and no other lock is ever taken while the state
//! mutex is held. A poisoned mutex is recovered with `PoisonError::into_inner`
//! instead of panicking.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Value};

use crate::encoding::{decode_b64url_fixed, key_id};
use crate::webhook::card::keys::{record_jwk, KeySnapshot, KeySource};
use crate::webhook::card::{accept_jwk_set, cross_check_webhook_key_jwks, WebhookKeyRecord};
use crate::webhook::delivery::freshness;
use crate::webhook::receiver::body::BodyCollector;
use crate::webhook::receiver::config::{JackConfig, ReceiverConfig};
use crate::webhook::receiver::dispatch::{Dispatch, ReceiverState, Reservation, SecretEntry};
use crate::webhook::receiver::errors::{rejection, DeliveryOutcome};
use crate::webhook::signatures::{
    asymmetric_verify, check_schemes, decode_signatures, parse_signature_header, v1_verify,
    SignatureContent,
};
use crate::webhook::verification::nonce::nonce_ok;
use crate::webhook::w1::{self, JackSigningParts};
use crate::webhook::{codes, MessageKind, WebhookError};

/// The `webhook-id` header name, lowercased (spec 06 R1.1).
const H_ID: &str = "webhook-id";

/// The `webhook-timestamp` header name, lowercased (spec 06 R1.1).
const H_TS: &str = "webhook-timestamp";

/// The `webhook-signature` header name, lowercased (spec 06 R1.1).
const H_SIG: &str = "webhook-signature";

/// The `X-MCP-Subscription-Id` header name, lowercased (spec 06 R1.1).
const H_SUB: &str = "x-mcp-subscription-id";

/// The `Jack-Webhook-Auth` header name, lowercased (spec 06 R1.1, R4.6).
const H_JACK: &str = "jack-webhook-auth";

/// The `Content-Length` header name, lowercased (spec 06 R3.6).
const H_LEN: &str = "content-length";

/// The four headers every delivery must carry exactly once (spec 06 R1.1,
/// R3.1, R3.2).
const REQUIRED: [&str; 4] = [H_ID, H_TS, H_SIG, H_SUB];

/// The decoded length of a configured MCP server public key (spec 06 R4.5).
const SERVER_KEY_BYTES: usize = 32;

/// The shortest and longest `webhook-id`, in characters (spec 06 R1.4).
const WEBHOOK_ID_LEN: std::ops::RangeInclusive<usize> = 8..=128;

/// The longest `webhook-timestamp`, in characters (spec 06 R1.5).
const TIMESTAMP_MAX_CHARS: usize = 12;

/// The number of hex characters of a subscription id (spec 06 R3.5).
const SUBSCRIPTION_ID_HEX: usize = 16;

/// The prefix of every subscription id (spec 06 R3.5).
const SUBSCRIPTION_ID_PREFIX: &str = "sub_";

/// The status every accepted delivery answers with (spec 06 R3.18).
const ACCEPTED_STATUS: u16 = 200;

/// The days of each month in a non-leap year (spec 06 R1.3).
const MONTH_DAYS: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// The verdict of the caller's durable enqueue (spec 06 R1.10, R3.17).
///
/// `Ok(())` means the message is durably enqueued, so a `2xx` may be returned;
/// `Err` means it is not, so the delivery answers `503 enqueue_failed` and
/// records nothing (spec 06 R1.10).
pub type EnqueueResult = Result<(), WebhookError>;

/// The observable state of one configured secret (spec 06 R3.7, R5.6).
///
/// A pending entry starts with `subscription_id` `None` and keeps the
/// callback url it was registered with; a verification envelope binds it to
/// the `X-MCP-Subscription-Id` it authenticated (spec 06 R5.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverSecretView {
    /// The subscription id the secret is bound to, `None` while pending
    /// (spec 06 R3.7, R5.6).
    pub subscription_id: Option<String>,
    /// The callback url the entry expects its challenge under
    /// (spec 06 R5.6).
    pub callback_url: Option<String>,
}

/// The observable routing, termination, secret and dedup state of a
/// [`Receiver`] (spec 06 R3.1-R3.18, R5.6).
///
/// `routed`, `terminated` and `accepted` are sorted, and the secrets are
/// listed in configuration order with their `subscription_id` and
/// `callback_url`, so two receivers with the same history render the same
/// snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverSnapshot {
    /// The subscription ids the receiver currently routes, sorted
    /// (spec 06 R3.8).
    pub routed: Vec<String>,
    /// The subscription ids marked terminated, sorted (spec 06 R3.17).
    pub terminated: Vec<String>,
    /// Every configured secret in configuration order (spec 06 R5.6).
    pub secrets: Vec<ReceiverSecretView>,
    /// The `webhook-id` values answered with a `2xx`, sorted (spec 06 R3.16).
    pub accepted: Vec<String>,
}

/// The outcome of steps 7 to 15 for one delivery (spec 06 R3.7-R3.15).
struct Verified {
    /// `true` when the secret was selected from the pending entries of
    /// section 5, so step 18 refuses anything but a verification envelope
    /// before the enqueue (spec 06 R3.8, R5.6).
    deferred: bool,
    /// The index of the entry whose secret verified the `v1` HMAC
    /// (spec 06 R3.13, R5.6).
    matched: usize,
}

/// The values steps 7 to 15 read, grouped so the pipeline takes one argument
/// (spec 06 R3.7-R3.15).
struct Context<'a> {
    /// The delivery clock time of step 13 and of the dedup window
    /// (spec 06 R3.9, R3.16).
    now: i64,
    /// The grouped request headers (spec 06 R3.1, R3.2).
    all: &'a BTreeMap<String, Vec<String>>,
    /// The raw body bytes of steps 6, 12, 14 and 15 (spec 06 R3.6).
    body: &'a [u8],
    /// The `webhook-id` of steps 3 and 12 (spec 06 R1.4, R3.13).
    webhook_id: &'a str,
    /// The `webhook-timestamp` of steps 4, 12 and 13 (spec 06 R1.5).
    timestamp: &'a str,
    /// The `X-MCP-Subscription-Id` of steps 5, 7 and 8 (spec 06 R3.5).
    subscription_id: &'a str,
    /// The accepted card keys of steps 14 and 15 (spec 06 R3.14, R7.3).
    accepted: &'a [WebhookKeyRecord],
    /// The raw published JWKs of the R7.6 cross-check (spec 06 R7.6).
    published: &'a [Value],
}

/// The framework-neutral receiver of spec 06 section 3 (R3.1-R3.18).
///
/// A receiver owns its routing set, its terminated set, its secret entries and
/// its accepted-id table. [`Receiver::handle`] runs the eighteen steps of
/// section 3 in order and stops at the first failure; [`Receiver::route`]
/// adds ids to the routing set; [`Receiver::snapshot`] reads the observable
/// state. No error carries a secret, a header value or a body byte
/// (spec 06 section 3).
///
/// Every mutable part sits behind the one mutex of [`dispatch`], so `handle`
/// takes `&self` and a receiver is usable from several threads at once: two
/// deliveries of the same `webhook-id` enqueue exactly once (spec 06 R1.10,
/// R3.16).
pub struct Receiver {
    /// The freshness window of step 13, in seconds (spec 06 R3.9).
    window: i64,
    /// The body limit of step 6, in bytes (spec 06 R1.2, R3.6).
    max_body: usize,
    /// How long an accepted id is remembered, in seconds (spec 06 R3.16).
    dedup_retention: i64,
    /// Whether step 14 enforces server identity (spec 06 R3.14).
    enforce_server_identity: bool,
    /// The kid a `w1` header must never name: the configured
    /// `mcp_server_kid`, else the kid of the configured raw server key
    /// (spec 06 R4.5).
    server_key_id: Option<String>,
    /// The static accepted card keys of steps 14 and 15, used when no key
    /// source is configured (spec 06 R2.7, R4.5, R7.3).
    keys: Vec<WebhookKeyRecord>,
    /// The static keys rendered as the JWKs the R7.6 cross-check compares
    /// (spec 06 R7.3, R7.6).
    published: Vec<Value>,
    /// The rotating key source, or `None` to use `keys`/`published`
    /// (spec 06 R7.1-R7.4).
    key_source: Option<Arc<dyn KeySource>>,
    /// Whether the optional R7.6 cross-check is required (spec 06 R7.6).
    require_webhook_key_check: bool,
    /// The `jack.server.webhook_key` tool result of the R7.6 cross-check
    /// (spec 06 R7.6).
    webhook_key_tool: Option<Value>,
    /// The `w1` settings, or `None` when the header is ignored
    /// (spec 06 R4.6).
    jack: Option<JackConfig>,
    /// The one mutex and condition variable over routing, termination,
    /// secrets, accepted ids and in-flight ids (spec 06 R1.10,
    /// R3.7-R3.17).
    dispatch: Dispatch,
}

impl Receiver {
    /// Builds a receiver from its configuration (spec 06 R3.1-R3.18).
    ///
    /// A `max_body` above [`crate::webhook::receiver::MAX_BODY_BYTES`] is
    /// refused, because no receiver may accept a body the profile caps
    /// (spec 06 R1.2). The configured MCP server key is taken out of the
    /// static card keys by kid or by raw public key (spec 06 R4.5), the raw
    /// server key alone names the kid a `w1` header must not carry
    /// (spec 06 R4.5), and the routing set starts from the configured ids
    /// (spec 06 R3.8). Every secret entry keeps its `subscription_id` and
    /// `callback_url`, `None` for a pending entry of section 5
    /// (spec 06 R5.6).
    pub fn new(config: ReceiverConfig) -> Result<Self, WebhookError> {
        // R1.2: the shared bounded collector validates the configured limit.
        BodyCollector::new(config.max_body)?;
        let server_kid = config.mcp_server_kid.clone();
        let server_public_key = config.mcp_server_public_key.clone();
        let server_key_id = server_kid
            .clone()
            .or_else(|| server_public_key.as_deref().and_then(server_kid_of));
        let keys = accepted_keys(
            &config.keys,
            server_kid.as_deref(),
            server_public_key.as_deref(),
        );
        let published: Vec<Value> = keys.iter().map(record_jwk).collect();
        let state = ReceiverState {
            entries: config
                .secrets
                .into_iter()
                .map(|entry| SecretEntry {
                    secret: entry.secret,
                    subscription_id: entry.subscription_id,
                    callback_url: entry.callback_url,
                })
                .collect(),
            routed: config.routed.into_iter().collect(),
            ..ReceiverState::default()
        };
        Ok(Self {
            window: config.window,
            max_body: config.max_body,
            dedup_retention: config.dedup_retention,
            enforce_server_identity: config.enforce_server_identity,
            server_key_id,
            keys,
            published,
            key_source: config.key_source,
            require_webhook_key_check: config.require_webhook_key_check,
            webhook_key_tool: config.webhook_key_tool,
            jack: config.jack,
            dispatch: Dispatch::new(state),
        })
    }

    /// Handles one delivery and returns the answer (spec 06 R3.1-R3.18).
    ///
    /// The eighteen steps run in the order of the section 3 table and stop at
    /// the first failure: missing header, duplicate header, `webhook-id`
    /// grammar, `webhook-timestamp` grammar, subscription-id grammar, body
    /// size and declared `Content-Length`, secret selection, routing,
    /// signature-header grammar, scheme set, value lengths, `v1` HMAC,
    /// freshness, asymmetric verification, `w1`, the required R7.6
    /// cross-check, deduplication, parse and field validation, then
    /// termination, the pending-secret routing refusal and finally enqueue
    /// and dispatch (spec 06 R3.1-R3.18).
    ///
    /// `enqueue` is the caller's durable enqueue of the parsed message
    /// objects; it is required, and it is the only way a delivery is
    /// acknowledged. `Ok(())` makes the delivery a `2xx` and records the
    /// `webhook-id`; `Err` answers `503 enqueue_failed` and records nothing, so
    /// the sender's retry is processed exactly once (spec 06 R1.10). A
    /// duplicate answer, an echoed verification envelope and a non-verification
    /// body that only a pending secret authenticated never call it
    /// (spec 06 R3.16, R3.8, R5.6).
    ///
    /// `enqueue` runs with no lock held, and the answer bodies are the section
    /// 3 table's: `{"status":"accepted"}`, `{"status":"duplicate"}`,
    /// `{"challenge":"<nonce>"}` or the fixed error object of the code.
    pub fn handle<F>(
        &self,
        now: i64,
        headers: &[(String, String)],
        body: &[u8],
        enqueue: F,
    ) -> DeliveryOutcome
    where
        F: FnOnce(&[Value]) -> EnqueueResult,
    {
        let all = collect_headers(headers);

        // Step 1 (R3.1): a required header absent, or present with an empty
        // value list, is the same refusal.
        for name in REQUIRED {
            if values_of(&all, name).is_none() {
                return reject(codes::MISSING_WEBHOOK_HEADER);
            }
        }
        // Step 2 (R3.2): a repeated header is refused before any value is read.
        for name in REQUIRED {
            if values_of(&all, name).is_some_and(|values| values.len() > 1) {
                return reject(codes::DUPLICATE_WEBHOOK_HEADER);
            }
        }
        let Some(webhook_id) = single(&all, H_ID) else {
            return reject(codes::MISSING_WEBHOOK_HEADER);
        };
        let Some(timestamp) = single(&all, H_TS) else {
            return reject(codes::MISSING_WEBHOOK_HEADER);
        };
        let Some(subscription_id) = single(&all, H_SUB) else {
            return reject(codes::MISSING_WEBHOOK_HEADER);
        };
        // Steps 3, 4 and 5 (R3.3-R3.5): the three grammars.
        if !webhook_id_ok(webhook_id) {
            return reject(codes::MALFORMED_WEBHOOK_ID);
        }
        if !timestamp_ok(timestamp) {
            return reject(codes::MALFORMED_WEBHOOK_TIMESTAMP);
        }
        if !subscription_ok(subscription_id) {
            return reject(codes::MALFORMED_SUBSCRIPTION_ID);
        }
        // Step 6 (R3.6): the raw length, then the declared length.
        if body.len() > self.max_body {
            return reject(codes::BODY_TOO_LARGE);
        }
        if let Some(declared) = single(&all, H_LEN) {
            let limit = self.max_body as u128;
            let too_large = match declared.parse::<u128>() {
                Ok(length) => length > limit,
                // A declared length too long to express is above any limit.
                Err(_) => true,
            };
            if !content_length_ok(declared) || too_large {
                return reject(codes::BODY_TOO_LARGE);
            }
        }
        // R7.1-R7.4: the keys valid at this delivery's clock time. The source
        // is caller code, so its snapshot is taken with no lock held.
        let snapshot = self.key_source.as_ref().map(|source| source.snapshot(now));
        let (accepted, published) = self.key_view(snapshot.as_ref());
        let context = Context {
            now,
            all: &all,
            body,
            webhook_id,
            timestamp,
            subscription_id,
            accepted,
            published,
        };
        // Steps 7 to 15 (R3.7-R3.15): the pipeline reads the one state mutex.
        let verified = match self
            .dispatch
            .with_state(|state| self.verify(state, &context))
        {
            Ok(verified) => verified,
            Err(code) => return reject(code),
        };
        // Step 16 (R3.16, R1.10): an id already answered with a 2xx stays
        // answered while retention holds, and an id another delivery owns is
        // waited for before it is re-checked.
        let (mut state, reservation) = self.dispatch.reserve(webhook_id, now, self.dedup_retention);
        if matches!(reservation, Reservation::Duplicate) {
            return DeliveryOutcome::ok(ACCEPTED_STATUS, json!({ "status": "duplicate" }), false);
        }
        // Step 17 (R3.18): parse and validate only after every verification
        // step passed.
        let message: Value = match serde_json::from_slice(body) {
            Ok(message) => message,
            Err(_) => return self.leave(&mut state, webhook_id, codes::MALFORMED_BODY),
        };
        if !message.is_object() {
            return self.leave(&mut state, webhook_id, codes::MALFORMED_BODY);
        }
        let kind = match message.get("type") {
            None => None,
            Some(value) => match value.as_str().and_then(MessageKind::from_type) {
                Some(kind) => Some(kind),
                None => return self.leave(&mut state, webhook_id, codes::UNKNOWN_ENVELOPE_TYPE),
            },
        };
        if !fields_ok(kind, &message) {
            return self.leave(&mut state, webhook_id, codes::MALFORMED_BODY);
        }
        // Step 18 (R3.17, R3.8, R5.6): termination, the pending-secret routing
        // refusal, enqueue and dispatch.
        if state.terminated.contains(subscription_id) {
            return self.leave(&mut state, webhook_id, codes::SUBSCRIPTION_TERMINATED);
        }
        if kind == Some(MessageKind::Verification) {
            // R5.6, R3.18: the echoed nonce is consumed locally and the pending
            // entry keeps its callback url, so the envelope is never
            // forwarded and nothing is enqueued.
            let challenge = message.get("challenge").cloned().unwrap_or(Value::Null);
            if verified.deferred {
                state.entries[verified.matched].subscription_id = Some(subscription_id.to_owned());
                state.routed.insert(subscription_id.to_owned());
            }
            self.dispatch.record(&mut state, webhook_id, now);
            return DeliveryOutcome::ok(ACCEPTED_STATUS, json!({ "challenge": challenge }), true);
        }
        if verified.deferred {
            // R3.8, R5.6: a pending secret authenticated this delivery, so the
            // only body it may carry is the verification envelope answered
            // above. Routing is decided here, before the caller's enqueue
            // runs, so an unrouted event never reaches the durable store; the
            // reservation is released and nothing is recorded (R1.10).
            return self.leave(&mut state, webhook_id, codes::SUBSCRIPTION_NOT_ROUTED);
        }
        // R1.10: the durable enqueue runs with no state lock held.
        drop(state);
        let enqueued = enqueue(std::slice::from_ref(&message));
        let mut state = self.dispatch.lock();
        if enqueued.is_err() {
            // R1.10, R3.17: nothing is recorded, so the sender's retry of the
            // same message is processed exactly once.
            self.dispatch.abandon(&mut state, webhook_id);
            return reject(codes::ENQUEUE_FAILED);
        }
        if kind == Some(MessageKind::Terminated) {
            // R3.17, R8.8: a verified terminated envelope is forwarded and
            // then stops routing.
            state.terminated.insert(subscription_id.to_owned());
            state.routed.remove(subscription_id);
        }
        self.dispatch.record(&mut state, webhook_id, now);
        DeliveryOutcome {
            status: ACCEPTED_STATUS,
            body: json!({ "status": "accepted" }),
            delivered: vec![message],
            code: None,
            recorded: true,
        }
    }

    /// Adds `ids` to the routing set (spec 06 R3.8).
    ///
    /// The id becomes routable on the same receiver, so state recorded by
    /// earlier steps stays observable; nothing is parsed and no delivery is
    /// answered here.
    pub fn route(&self, ids: &[String]) {
        let mut state = self.dispatch.lock();
        for id in ids {
            state.routed.insert(id.clone());
        }
    }

    /// Returns the observable routing, termination, secret and dedup state
    /// (spec 06 R3.1-R3.18, R5.6).
    ///
    /// `routed`, `terminated` and `accepted` are sorted, and the secrets are
    /// listed in configuration order with the `subscription_id` and
    /// `callback_url` each entry currently carries.
    pub fn snapshot(&self) -> ReceiverSnapshot {
        self.dispatch.with_state(|state| ReceiverSnapshot {
            routed: state.routed.iter().cloned().collect(),
            terminated: state.terminated.iter().cloned().collect(),
            secrets: state
                .entries
                .iter()
                .map(|entry| ReceiverSecretView {
                    subscription_id: entry.subscription_id.clone(),
                    callback_url: entry.callback_url.clone(),
                })
                .collect(),
            accepted: state.accepted.keys().cloned().collect(),
        })
    }

    /// Returns the accepted keys and the raw published JWKs of this delivery
    /// (spec 06 R7.1-R7.4, R7.6).
    ///
    /// A configured source wins over the static configuration, and its raw
    /// published JWKs are compared as they are, so a key the R7.3 validator
    /// rejects still fails the required R7.6 check (spec 06 R7.6). Without a
    /// source the static keys are the accepted set and their records are the
    /// published set.
    fn key_view<'a>(
        &'a self,
        snapshot: Option<&'a KeySnapshot>,
    ) -> (&'a [WebhookKeyRecord], &'a [Value]) {
        match snapshot {
            Some(snapshot) => (snapshot.accepted.as_slice(), snapshot.published.as_slice()),
            None => (self.keys.as_slice(), self.published.as_slice()),
        }
    }

    /// Releases the reservation of one id and answers its rejection
    /// (spec 06 R1.10, R3.16).
    ///
    /// Every post-dedup rejection goes through here, so the id is never
    /// recorded for an answer that is not a `2xx` and a concurrent waiter
    /// becomes the new owner.
    fn leave(&self, state: &mut ReceiverState, id: &str, code: &'static str) -> DeliveryOutcome {
        self.dispatch.abandon(state, id);
        reject(code)
    }

    /// Runs steps 7 to 15 against the state under the one lock
    /// (spec 06 R3.7-R3.15).
    ///
    /// The function is pure: it reads secrets, routing, termination, the
    /// configured callback urls and the accepted keys, verifies the `v1`
    /// HMAC, the freshness window, the optional asymmetric entries, the Jack
    /// `w1` header and the optional R7.6 cross-check, and returns the entry
    /// that matched or the first failing code. It never calls the enqueue
    /// callback and never takes another lock.
    fn verify(&self, state: &ReceiverState, ctx: &Context<'_>) -> Result<Verified, &'static str> {
        // Step 7 (R3.7, R5.6): the one registered secret for the id, else
        // every pending secret of section 5.
        let registered = state
            .entries
            .iter()
            .position(|entry| entry.subscription_id.as_deref() == Some(ctx.subscription_id));
        let candidates: Vec<usize> = match registered {
            Some(index) => vec![index],
            None => state
                .entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.subscription_id.is_none())
                .map(|(index, _)| index)
                .collect(),
        };
        let deferred = registered.is_none();
        if deferred && candidates.is_empty() {
            return Err(codes::UNKNOWN_SUBSCRIPTION);
        }
        // Step 8 (R3.8): a routed or terminated id passes; a delivery the
        // pending-secret path authenticates is refused in step 18, before the
        // enqueue, because only the verification envelope can route it
        // (R5.6).
        if !deferred
            && !state.routed.contains(ctx.subscription_id)
            && !state.terminated.contains(ctx.subscription_id)
        {
            return Err(codes::SUBSCRIPTION_NOT_ROUTED);
        }
        // Steps 9, 10 and 11 (R3.10-R3.12): grammar, scheme set, lengths.
        let Some(signature) = single(ctx.all, H_SIG) else {
            return Err(codes::MISSING_WEBHOOK_HEADER);
        };
        let parsed = match parse_signature_header(signature) {
            Ok(parsed) => parsed,
            Err(error) => return Err(error.code),
        };
        if let Err(error) = check_schemes(&parsed) {
            return Err(error.code);
        }
        let decoded = match decode_signatures(&parsed) {
            Ok(decoded) => decoded,
            Err(error) => return Err(error.code),
        };
        // Step 12 (R3.13): the v1 HMAC with every selected secret.
        let content = SignatureContent {
            webhook_id: ctx.webhook_id,
            timestamp: ctx.timestamp,
            body: ctx.body,
        };
        let mut matched = None;
        for index in candidates {
            if v1_verify(&decoded, &state.entries[index].secret, &content) {
                matched = Some(index);
                break;
            }
        }
        let Some(matched) = matched else {
            return Err(codes::BAD_SIGNATURE);
        };
        // Step 13 (R3.9): freshness, only after the HMAC verified.
        let Ok(seconds) = ctx.timestamp.parse::<i64>() else {
            return Err(codes::MALFORMED_WEBHOOK_TIMESTAMP);
        };
        if let Err(error) = freshness(ctx.now, seconds, self.window) {
            return Err(error.code);
        }
        // Step 14 (R3.14): asymmetric verification, only when identity is
        // enforced.
        if self.enforce_server_identity {
            if ctx.accepted.is_empty() {
                return Err(codes::NO_SERVER_KEYS);
            }
            if asymmetric_verify(&decoded, ctx.subscription_id, &content, ctx.accepted).is_none() {
                return Err(codes::BAD_SERVER_SIGNATURE);
            }
        }
        // Step 15 (R3.15, R4.1-R4.6): the Jack w1 header, when configured.
        if let Some(jack) = &self.jack {
            let Some(header_value) = single(ctx.all, H_JACK) else {
                return Err(codes::MISSING_JACK_AUTH);
            };
            // R5.6: the pending path signs the verified entry's callback url;
            // a routed id signs the configured callback url of R4.3.
            let callback_url = if deferred {
                state.entries[matched].callback_url.as_deref()
            } else {
                jack.callback_urls
                    .get(ctx.subscription_id)
                    .map(String::as_str)
            };
            let parts = JackSigningParts {
                aud: &jack.aud,
                subscription_id: ctx.subscription_id,
                webhook_id: ctx.webhook_id,
                timestamp: ctx.timestamp,
                // An entry without a callback url cannot verify a signature
                // that binds one, so the empty placeholder only lets the
                // earlier checks of R4.1-R4.4 run in their spec order; the
                // entry is refused as bad_jack_signature right after them.
                callback_url: callback_url.unwrap_or_default(),
                body: ctx.body,
            };
            if let Err(error) = w1::verify(
                Some(header_value),
                &parts,
                ctx.accepted,
                ctx.now,
                jack.window,
                self.server_key_id.as_deref(),
            ) {
                return Err(error.code);
            }
            if callback_url.is_none() {
                return Err(codes::BAD_JACK_SIGNATURE);
            }
        }
        // R7.6: the optional cross-check of the raw published card JWKs
        // against the native tool result.
        if self.require_webhook_key_check {
            if let Err(error) =
                cross_check_webhook_key_jwks(ctx.published, self.webhook_key_tool.as_ref(), true)
            {
                return Err(error.code);
            }
        }
        Ok(Verified { deferred, matched })
    }
}

/// Builds the rejection answer of one closed code (spec 06 section 3).
fn reject(code: &'static str) -> DeliveryOutcome {
    DeliveryOutcome::from_error(&rejection(code))
}

/// Groups header values by their lowercase name (spec 06 R3.1, R3.2).
///
/// A name that appears twice keeps both values in order, which is what makes
/// a repeated required header visible as a two-value list; a pair with an
/// empty value is still a present header carrying one empty string.
fn collect_headers(headers: &[(String, String)]) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in headers {
        map.entry(name.to_ascii_lowercase())
            .or_default()
            .push(value.clone());
    }
    map
}

/// Returns the value list of a header, `None` when absent or empty
/// (spec 06 R3.1).
fn values_of<'a>(all: &'a BTreeMap<String, Vec<String>>, name: &str) -> Option<&'a [String]> {
    all.get(name)
        .map(Vec::as_slice)
        .filter(|values| !values.is_empty())
}

/// Returns the first value of a header, `None` when absent or empty
/// (spec 06 R3.1).
fn single<'a>(all: &'a BTreeMap<String, Vec<String>>, name: &str) -> Option<&'a str> {
    all.get(name)
        .and_then(|values| values.first())
        .map(String::as_str)
}

/// Returns the kid of a configured raw server key, `base64url(SHA-256(raw
/// 32-byte public key))` (spec 06 R4.5).
///
/// A value that is not the canonical unpadded base64url of exactly 32 bytes
/// names no kid and so drops no card key.
fn server_kid_of(public_key: &str) -> Option<String> {
    decode_b64url_fixed(public_key, SERVER_KEY_BYTES)
        .ok()
        .map(|raw| key_id(&raw))
}

/// Filters the configured card keys with the R7.3 rules, so a key equal to
/// the configured MCP server key, by kid or by raw public key, is never
/// accepted (spec 06 R4.5, R7.3).
fn accepted_keys(
    keys: &[WebhookKeyRecord],
    mcp_server_kid: Option<&str>,
    mcp_server_public_key: Option<&str>,
) -> Vec<WebhookKeyRecord> {
    let jwks: Vec<Value> = keys
        .iter()
        .map(|key| {
            json!({
                "kty": key.kty,
                "crv": key.crv,
                "x": key.x,
                "kid": key.kid,
            })
        })
        .collect();
    accept_jwk_set(
        Some(&json!({ "keys": jwks })),
        mcp_server_kid,
        mcp_server_public_key,
    )
    .accepted
}

/// Reports whether `value` matches `^[A-Za-z0-9_-]{8,128}$` (spec 06 R1.4).
fn webhook_id_ok(value: &str) -> bool {
    WEBHOOK_ID_LEN.contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// Reports whether `value` matches `^(0|[1-9][0-9]{0,11})$` (spec 06 R1.5).
fn timestamp_ok(value: &str) -> bool {
    value == "0"
        || (!value.is_empty()
            && value.len() <= TIMESTAMP_MAX_CHARS
            && value.as_bytes()[0] != b'0'
            && value.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Reports whether `value` matches `^sub_[0-9a-f]{16}$` (spec 06 R3.5).
fn subscription_ok(value: &str) -> bool {
    match value.strip_prefix(SUBSCRIPTION_ID_PREFIX) {
        Some(rest) => {
            rest.len() == SUBSCRIPTION_ID_HEX
                && rest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }
        None => false,
    }
}

/// Reports whether `value` matches `^[0-9]+$` (spec 06 R3.6).
fn content_length_ok(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// Validates the field set of one parsed envelope or event occurrence
/// (spec 06 R1.3, R3.18).
///
/// An `EventOccurrence` needs the four required members, a `gap` needs
/// `cursor` a string or `null`, a `terminated` needs an `error` object with an
/// integer `code` and a string `message` and an optional object `data`, and a
/// `verification` needs a challenge matching the nonce rule of R5.3. Members
/// outside the shape are ignored.
fn fields_ok(kind: Option<MessageKind>, message: &Value) -> bool {
    match kind {
        Some(MessageKind::Verification) => message
            .get("challenge")
            .and_then(Value::as_str)
            .is_some_and(nonce_ok),
        Some(MessageKind::Gap) => {
            matches!(message.get("cursor"), Some(Value::String(_) | Value::Null))
        }
        Some(MessageKind::Terminated) => terminated_ok(message),
        Some(MessageKind::Event) | None => event_ok(message),
    }
}

/// Validates one `terminated` envelope (spec 06 R1.3).
fn terminated_ok(message: &Value) -> bool {
    let Some(error) = message.get("error") else {
        return false;
    };
    if !error.is_object() {
        return false;
    }
    let Some(code) = error.get("code") else {
        return false;
    };
    if !is_integer(code) || error.get("message").and_then(Value::as_str).is_none() {
        return false;
    }
    match error.get("data") {
        None => true,
        Some(data) => data.is_object(),
    }
}

/// Validates one `EventOccurrence` (spec 06 R1.3).
fn event_ok(message: &Value) -> bool {
    if !message.get("data").is_some_and(Value::is_object) {
        return false;
    }
    if let Some(cursor) = message.get("cursor") {
        if !(cursor.is_string() || cursor.is_null()) {
            return false;
        }
    }
    let Some(event_id) = message.get("eventId").and_then(Value::as_str) else {
        return false;
    };
    let Some(name) = message.get("name").and_then(Value::as_str) else {
        return false;
    };
    let Some(timestamp) = message.get("timestamp").and_then(Value::as_str) else {
        return false;
    };
    !event_id.is_empty() && !name.is_empty() && is_iso_timestamp(timestamp)
}

/// Reports whether `value` is a JSON number with no fractional part, the
/// `Number.isInteger` check of the `terminated` envelope (spec 06 R1.3).
fn is_integer(value: &Value) -> bool {
    match value {
        Value::Number(number) => {
            number.as_i64().is_some()
                || number.as_u64().is_some()
                || number.as_f64().is_some_and(|float| float.fract() == 0.0)
        }
        _ => false,
    }
}

/// Reports whether `value` is the RFC 3339 profile of an occurrence timestamp
/// (spec 06 R1.3).
///
/// The form is `YYYY-MM-DDThh:mm:ss` with an optional fractional part and a
/// mandatory `Z`, `+hh:mm` or `-hh:mm` zone; calendar and clock ranges are
/// checked by arithmetic, including leap days, so `not-a-date`,
/// `2026-02-30T00:00:00Z`, `2026-01-01` and `2026-01-01T00:00:00` are all
/// invalid.
fn is_iso_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20 {
        return false;
    }
    if !digits(&bytes[0..4])
        || bytes[4] != b'-'
        || !digits(&bytes[5..7])
        || bytes[7] != b'-'
        || !digits(&bytes[8..10])
        || bytes[10] != b'T'
        || !digits(&bytes[11..13])
        || bytes[13] != b':'
        || !digits(&bytes[14..16])
        || bytes[16] != b':'
        || !digits(&bytes[17..19])
    {
        return false;
    }
    let mut index = 19;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == start {
            return false;
        }
    }
    let zone = &bytes[index..];
    let zone_ok = match zone.len() {
        1 => zone[0] == b'Z',
        6 => {
            (zone[0] == b'+' || zone[0] == b'-')
                && zone[3] == b':'
                && digits(&zone[1..3])
                && digits(&zone[4..6])
                && two(&zone[1..3]) <= 23
                && two(&zone[4..6]) <= 59
        }
        _ => false,
    };
    if !zone_ok {
        return false;
    }
    let year = four(&bytes[0..4]);
    let month = two(&bytes[5..7]);
    let day = two(&bytes[8..10]);
    let hour = two(&bytes[11..13]);
    let minute = two(&bytes[14..16]);
    let second = two(&bytes[17..19]);
    if !(1..=12).contains(&month) {
        return false;
    }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let month_days = if month == 2 && leap {
        29
    } else {
        MONTH_DAYS[(month - 1) as usize]
    };
    if !(1..=month_days).contains(&day) {
        return false;
    }
    hour <= 23 && minute <= 59 && second <= 59
}

/// Reports whether every byte is an ASCII decimal digit (spec 06 R1.3).
fn digits(bytes: &[u8]) -> bool {
    bytes.iter().all(u8::is_ascii_digit)
}

/// Reads two decimal digits (spec 06 R1.3).
fn two(bytes: &[u8]) -> u32 {
    u32::from(bytes[0] - b'0') * 10 + u32::from(bytes[1] - b'0')
}

/// Reads four decimal digits (spec 06 R1.3).
fn four(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |value, byte| value * 10 + u32::from(byte - b'0'))
}
