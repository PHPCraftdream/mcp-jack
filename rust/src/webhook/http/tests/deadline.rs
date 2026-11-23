//! The absolute R1.6 deadline of the hardened delivery path
//! (spec 06 R1.6, R6.8, R1.9).
//!
//! The deadline of one attempt is an [`std::time::Instant`], not a duration,
//! so the DNS lookups, the request build and every transport phase share it.
//! The resolvers below ignore the budget they are handed and block for a
//! fixed delay, which proves that the caller — not the resolver — bounds the
//! lookup.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::rebinding::{
    ip, message, FakeClock, FakeResolver, FakeTransport, GateMode, ScriptedGate, NAME_URL, PUBLIC,
    T0_MS,
};
use crate::webhook::delivery::{LastError, MAX_BODY_BYTES};
use crate::webhook::http::sender::{SendAction, Sender, SenderConfig};
use crate::webhook::http::transport::{resolve_answers, HostResolver};
use crate::webhook::ssrf::url::check_url;
use crate::webhook::WebhookError;

/// A resolver whose lookup blocks for `delay` and never inspects the budget it
/// is handed, so only the caller's absolute deadline can bound it
/// (spec 06 R1.6, R6.8).
pub(super) struct SlowResolver {
    delay: Duration,
}

impl HostResolver for SlowResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, WebhookError> {
        self.resolve_within(host, port, Duration::ZERO)
    }

    fn resolve_within(
        &self,
        _host: &str,
        _port: u16,
        _budget: Duration,
    ) -> Result<Vec<IpAddr>, WebhookError> {
        std::thread::sleep(self.delay);
        Ok(vec![ip(PUBLIC)])
    }
}

/// A resolver that spends `delay` and then reports the fixed R1.6 `timeout`
/// error, standing in for a lookup the attempt deadline spent
/// (spec 06 R1.6, R1.9).
pub(super) struct SpentResolver {
    delay: Duration,
}

impl HostResolver for SpentResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, WebhookError> {
        self.resolve_within(host, port, Duration::ZERO)
    }

    fn resolve_within(
        &self,
        _host: &str,
        _port: u16,
        _budget: Duration,
    ) -> Result<Vec<IpAddr>, WebhookError> {
        std::thread::sleep(self.delay);
        Err(WebhookError::new(
            500,
            "timeout",
            "the webhook host lookup ran out of time",
        ))
    }
}

#[test]
fn r1_6_a_blocking_lookup_is_abandoned_at_the_absolute_deadline() {
    // The resolver blocks for 300 ms whatever budget it is handed; the lookup
    // is abandoned when the caller's deadline is 50 ms away, so the fixed
    // `timeout` failure arrives in well under the lookup's own runtime and no
    // request is ever built (spec 06 R1.6, R6.8).
    let resolver: Arc<dyn HostResolver> = Arc::new(SlowResolver {
        delay: Duration::from_millis(300),
    });
    let endpoint = check_url(NAME_URL).expect("the test url is a valid endpoint");
    let started = Instant::now();
    let error = resolve_answers(&resolver, &endpoint, started + Duration::from_millis(50))
        .expect_err("a blocking lookup answered the host");
    let elapsed = started.elapsed();
    assert_eq!(error.http_status, 500);
    assert_eq!(error.code, "timeout");
    assert!(
        elapsed < Duration::from_millis(300),
        "the blocking lookup was not bounded: {elapsed:?}"
    );
}

#[test]
fn r1_6_a_spent_lookup_budget_is_timeout_on_the_delivery_path() {
    // A resolver that spends its budget and reports `timeout` must end the
    // delivery as the retryable `timeout` category, never as a request
    // (spec 06 R1.6, R1.9).
    let transport = Arc::new(FakeTransport::new(vec![(200, None)]));
    let resolver: Arc<dyn HostResolver> = Arc::new(SpentResolver {
        delay: Duration::from_millis(20),
    });
    let clock = Arc::new(FakeClock::new(T0_MS));
    let gate = Arc::new(ScriptedGate::new(GateMode::Verified));
    let sender = Sender::new(
        transport.clone(),
        resolver,
        clock,
        SenderConfig {
            allowed_ranges: Vec::new(),
            max_body_bytes: MAX_BODY_BYTES,
            verification_ttl_ms: None,
        },
        gate,
    );

    let started = Instant::now();
    let outcome = sender.deliver(&message(NAME_URL));
    let elapsed = started.elapsed();
    assert_eq!(
        outcome.action,
        SendAction::Abandoned {
            last_error: LastError::Timeout
        }
    );
    assert_eq!(outcome.attempts, 4);
    assert_eq!(outcome.last_status, None);
    assert_eq!(transport.calls(), 0, "a timed-out lookup sent a request");
    assert!(
        elapsed < Duration::from_millis(300),
        "the timeout path was not prompt: {elapsed:?}"
    );
}

#[test]
fn r1_6_a_deadline_in_the_past_fails_with_timeout_before_any_lookup() {
    let fake = Arc::new(FakeResolver::new(vec![vec![ip(PUBLIC)]]));
    let resolver: Arc<dyn HostResolver> = fake.clone();
    let endpoint = check_url(NAME_URL).expect("the test url is a valid endpoint");
    let deadline = Instant::now() - Duration::from_millis(1);
    let error = resolve_answers(&resolver, &endpoint, deadline)
        .expect_err("an expired deadline still answered the host");
    assert_eq!(error.http_status, 500);
    assert_eq!(error.code, "timeout");
    assert!(
        fake.queries().is_empty(),
        "an expired deadline looked the host up"
    );
}
