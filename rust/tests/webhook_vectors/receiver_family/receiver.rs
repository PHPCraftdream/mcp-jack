//! Runner for `spec/fixtures/modern/webhook-receiver-vectors.json`
//! (spec 06 section 1, section 3 and R7.6: R1.1-R1.10, R3.1-R3.18, R4.3,
//! R4.5, R5.6 and R7.6).
//!
//! Every kind is driven through the public `mcp_jack::webhook` API: a
//! `sequence` replays its steps on one [`Receiver`] built from the case
//! configuration, so state recorded by earlier steps stays observable, and
//! `sender`, `schedule` and `last-error` drive the pure sender rules.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use mcp_jack::webhook::card::WebhookKeyRecord;
use mcp_jack::webhook::codes;
use mcp_jack::webhook::delivery::{
    last_error_of, retry_schedule, sender_decision, LastError, SenderAction, SenderAttempt,
    SenderDecision,
};
use mcp_jack::webhook::encoding::WebhookSecret;
use mcp_jack::webhook::receiver::{
    DeliveryOutcome, JackConfig, Receiver, ReceiverConfig, ReceiverSecret,
};
use mcp_jack::webhook::WebhookError;
use serde_json::{json, Map, Value};

use crate::common::{assert_case, body_of, cases, key_record, summary, text_of};

/// The committed case count of the corpus (spec/tests/modern/CASES.md).
const CASE_COUNT: usize = 107;

/// The Jack window of R4.4, used when a configuration names none.
const DEFAULT_JACK_WINDOW: i64 = 30;

/// The `webhook_key_check` setting that requires the R7.6 cross-check.
const REQUIRE_KEY_CHECK: &str = "require";

/// The `enqueue` step member that makes the callback refuse
/// (spec 06 R1.10).
const ENQUEUE_FAIL: &str = "fail";

/// The status of a failed durable enqueue (spec 06 R1.10).
const ENQUEUE_STATUS: u16 = 503;

#[test]
fn webhook_receiver_vectors() {
    let corpus = cases("webhook-receiver-vectors.json");
    assert_eq!(
        corpus.len(),
        CASE_COUNT,
        "webhook-receiver-vectors.json cases"
    );
    let mut pass = 0;
    for case in &corpus {
        let actual = run(case);
        assert_case(case, &actual);
        pass += 1;
    }
    summary("webhook-receiver", pass, CASE_COUNT);
}

/// R1.10: the durable-enqueue callback refuses when the step asks it to, so a
/// `webhook-id` is never recorded on a failed enqueue.
///
/// The case this drives is the corpus case that carries `enqueue: "fail"`;
/// only that step's answer is judged here, because the corpus test already
/// compares every step with its fixture expectation.
#[test]
fn enqueue_failure_is_refused_by_the_callback() {
    let corpus = cases("webhook-receiver-vectors.json");
    let case = corpus
        .iter()
        .find(|case| fails_enqueue(case))
        .unwrap_or_else(|| {
            panic!("webhook-receiver-vectors.json has no step with enqueue: \"fail\"")
        });
    let input = &case["input"];
    let receiver = Receiver::new(config_of(&input["config"])).unwrap_or_else(|error| {
        panic!(
            "{}: the receiver configuration is refused ({error})",
            id_of(case)
        )
    });
    let steps = input["steps"]
        .as_array()
        .unwrap_or_else(|| panic!("{}: steps is not an array", id_of(case)));
    for step in steps {
        if let Some(ids) = step.get("route") {
            receiver.route(&strings_of(ids));
        }
        let enqueue = Enqueue::of(step);
        let outcome = receiver.handle(
            integer_of(&step["now"]),
            &headers_of(&step["headers"]),
            &body_bytes(step),
            |messages| enqueue.record(messages),
        );
        if !enqueue.fail {
            continue;
        }
        assert_eq!(outcome.status, ENQUEUE_STATUS, "{}: status", id_of(case));
        assert_eq!(
            outcome.code.as_deref(),
            Some(codes::ENQUEUE_FAILED),
            "{}: code",
            id_of(case)
        );
        assert!(!outcome.recorded, "{}: recorded", id_of(case));
        assert_eq!(enqueue.calls(), 1, "{}: enqueue calls", id_of(case));
        assert!(
            enqueue.delivered().is_empty(),
            "{}: a refused enqueue acknowledges nothing",
            id_of(case)
        );
        return;
    }
    panic!("{}: no step refused the enqueue", id_of(case));
}

/// Reports whether any step of a sequence case carries `enqueue: "fail"`
/// (spec 06 R1.10).
fn fails_enqueue(case: &Value) -> bool {
    case["input"]["steps"].as_array().is_some_and(|steps| {
        steps
            .iter()
            .any(|step| step.get("enqueue").and_then(Value::as_str) == Some(ENQUEUE_FAIL))
    })
}

/// Drives one case and returns the observed JSON.
fn run(case: &Value) -> Value {
    match case["kind"]
        .as_str()
        .unwrap_or_else(|| panic!("{}: the case has no kind", id_of(case)))
    {
        "sequence" => sequence(case),
        "sender" => sender(&case["input"]),
        "schedule" => schedule(&case["input"]),
        "last-error" => last_error(&case["input"]),
        other => panic!("{}: unknown kind {other}", id_of(case)),
    }
}

/// R1.1-R1.10, R3.1-R3.18, R4.5, R5.6, R7.6: one receiver, every step replayed
/// on it in order.
fn sequence(case: &Value) -> Value {
    let input = &case["input"];
    let receiver = Receiver::new(config_of(&input["config"])).unwrap_or_else(|error| {
        panic!(
            "{}: the receiver configuration is refused ({error})",
            id_of(case)
        )
    });
    let steps = input["steps"]
        .as_array()
        .unwrap_or_else(|| panic!("{}: steps is not an array", id_of(case)));
    let mut answers = Vec::with_capacity(steps.len());
    for step in steps {
        // R3.8: the id is routed on this same receiver, so state recorded by
        // earlier steps stays observable.
        if let Some(ids) = step.get("route") {
            receiver.route(&strings_of(ids));
        }
        // R1.10: every step carries its own durable-enqueue callback.
        let enqueue = Enqueue::of(step);
        let outcome = receiver.handle(
            integer_of(&step["now"]),
            &headers_of(&step["headers"]),
            &body_bytes(step),
            |messages| enqueue.record(messages),
        );
        answers.push(outcome_json(&outcome));
    }
    json!({
        "steps": answers,
        "final_state": snapshot_of(&receiver),
    })
}

/// R1.10: the durable-enqueue callback of one step, driven by the case.
///
/// `enqueue: "fail"` records the call and answers `503 enqueue_failed` with
/// the fixed-literal message of a test enqueue; every other step records the
/// delivered messages and acknowledges them.
#[derive(Debug)]
struct Enqueue {
    /// `true` when this step asks the callback to refuse (spec 06 R1.10).
    fail: bool,
    /// How many times the callback ran (spec 06 R1.10).
    calls: Cell<usize>,
    /// The message objects the callback acknowledged (spec 06 R3.18).
    delivered: RefCell<Vec<Value>>,
}

impl Enqueue {
    /// Builds the callback one step asks for (spec 06 R1.10).
    fn of(step: &Value) -> Self {
        Self {
            fail: step.get("enqueue").and_then(Value::as_str) == Some(ENQUEUE_FAIL),
            calls: Cell::new(0),
            delivered: RefCell::new(Vec::new()),
        }
    }

    /// Runs the durable enqueue once and records the call (spec 06 R1.10).
    fn record(&self, messages: &[Value]) -> Result<(), WebhookError> {
        self.calls.set(self.calls.get() + 1);
        if self.fail {
            return Err(WebhookError::new(
                ENQUEUE_STATUS,
                codes::ENQUEUE_FAILED,
                "test enqueue failure",
            ));
        }
        self.delivered.borrow_mut().extend_from_slice(messages);
        Ok(())
    }

    /// Returns how many times the callback ran (spec 06 R1.10).
    fn calls(&self) -> usize {
        self.calls.get()
    }

    /// Returns the message objects the callback acknowledged (spec 06 R3.18).
    fn delivered(&self) -> Vec<Value> {
        self.delivered.borrow().clone()
    }
}

/// Renders one delivery answer as the corpus step object (spec 06 section 3).
fn outcome_json(outcome: &DeliveryOutcome) -> Value {
    json!({
        "status": outcome.status,
        "body": outcome.body,
        "delivered": outcome.delivered,
        "code": outcome.code,
        "recorded": outcome.recorded,
    })
}

/// R1.7-R1.9: the accept, retry or abandon decision after one attempt.
fn sender(input: &Value) -> Value {
    decision_of(sender_decision(&attempt_of(input)))
}

/// R1.8: the four absolute attempt times from `t0`.
fn schedule(input: &Value) -> Value {
    json!({"times": retry_schedule(integer_of(&input["t0"]))})
}

/// R1.7, R1.9: the category of one status, `null` when it has none.
fn last_error(input: &Value) -> Value {
    let status = integer_of(&input["status"]) as u16;
    json!({"lastError": last_error_of(status).map(LastError::as_str)})
}

/// Builds one [`SenderAttempt`] from `{status?, transport?, retryAfter?,
/// attempt, t0, responseTime}` (spec 06 R1.7, R1.8).
fn attempt_of(input: &Value) -> SenderAttempt {
    SenderAttempt {
        status: input.get("status").map(|value| integer_of(value) as u16),
        transport: input
            .get("transport")
            .and_then(Value::as_str)
            .map(transport_of),
        retry_after: input.get("retryAfter").map(integer_of),
        attempt: integer_of(&input["attempt"]) as u32,
        t0: integer_of(&input["t0"]),
        response_time: integer_of(&input["responseTime"]),
    }
}

/// Renders one decision as the corpus `expect` object: `action`, `lastError`
/// unless accepted, and `nextAt` only on a retry.
fn decision_of(decision: SenderDecision) -> Value {
    let action = match decision.action {
        SenderAction::Accept => "accept",
        SenderAction::Retry { .. } => "retry",
        SenderAction::Final => "final",
    };
    let mut answer = Map::new();
    answer.insert("action".to_owned(), json!(action));
    if let Some(last_error) = decision.last_error {
        answer.insert("lastError".to_owned(), json!(last_error.as_str()));
    }
    if let SenderAction::Retry { next_at } = decision.action {
        answer.insert("nextAt".to_owned(), json!(next_at));
    }
    Value::Object(answer)
}

/// Returns the [`LastError`] category of one transport spelling
/// (spec 06 R1.9).
fn transport_of(spelling: &str) -> LastError {
    match spelling {
        "connection_refused" => LastError::ConnectionRefused,
        "timeout" => LastError::Timeout,
        "tls_error" => LastError::TlsError,
        "http_4xx" => LastError::Http4xx,
        "http_5xx" => LastError::Http5xx,
        "challenge_failed" => LastError::ChallengeFailed,
        other => panic!("{other}: no `lastError` category carries this spelling"),
    }
}

/// Builds the receiver configuration of one sequence (spec 06 R3.7, R3.8,
/// R3.14, R4.5, R4.6, R5.6, R7.6).
///
/// `keys` are fixture identity names, resolved to their card key record, and
/// every absent member keeps the reference default of [`ReceiverConfig`].
fn config_of(value: &Value) -> ReceiverConfig {
    let mut config = ReceiverConfig::default();
    if let Some(secrets) = value.get("secrets").and_then(Value::as_array) {
        config.secrets = secrets.iter().map(secret_of).collect();
    }
    let keys: Vec<WebhookKeyRecord> = value
        .get("keys")
        .and_then(Value::as_array)
        .map(|names| {
            names
                .iter()
                .map(|name| key_record(&text_of(name)))
                .collect()
        })
        .unwrap_or_default();
    config.keys = keys;
    if let Some(routed) = value.get("routed") {
        config.routed = strings_of(routed);
    }
    config.enforce_server_identity = value
        .get("enforce_server_identity")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    config.mcp_server_kid = optional_string(value, "mcp_server_kid");
    config.mcp_server_public_key = optional_string(value, "mcp_server_public_key");
    config.require_webhook_key_check =
        value.get("webhook_key_check").and_then(Value::as_str) == Some(REQUIRE_KEY_CHECK);
    config.webhook_key_tool = value
        .get("webhook_key_tool")
        .filter(|tool| !tool.is_null())
        .cloned();
    config.jack = value.get("jack").map(jack_of);
    config
}

/// Builds one registered or pending secret entry (spec 06 R3.7, R5.6).
fn secret_of(entry: &Value) -> ReceiverSecret {
    let secret = WebhookSecret::parse(&text_of(&entry["secret"]))
        .unwrap_or_else(|_| panic!("the case carries a secret the profile rejects"));
    ReceiverSecret {
        secret,
        subscription_id: optional_string(entry, "subscription_id"),
        callback_url: optional_string(entry, "callback_url"),
    }
}

/// Builds the [`JackConfig`] of a sequence (spec 06 R4.2-R4.6).
fn jack_of(value: &Value) -> JackConfig {
    let callback_urls: BTreeMap<String, String> = value
        .get("callback_urls")
        .and_then(Value::as_object)
        .map(|members| {
            members
                .iter()
                .map(|(subscription_id, url)| (subscription_id.clone(), text_of(url)))
                .collect()
        })
        .unwrap_or_default();
    JackConfig {
        aud: text_of(&value["aud"]),
        window: value
            .get("window")
            .map(integer_of)
            .unwrap_or(DEFAULT_JACK_WINDOW),
        callback_urls,
    }
}

/// Renders `receiver.snapshot()` as the corpus `final_state`: sorted `routed`,
/// `terminated` and `accepted`, and one `(subscription id, callback url)` pair
/// per secret entry (spec 06 R3.7, R3.8, R3.16, R3.17, R5.6).
fn snapshot_of(receiver: &Receiver) -> Value {
    let snapshot = receiver.snapshot();
    let secrets: Vec<Value> = snapshot
        .secrets
        .iter()
        .map(|entry| {
            json!({
                "subscription_id": entry.subscription_id.as_deref(),
                "callback_url": entry.callback_url.as_deref(),
            })
        })
        .collect();
    json!({
        "routed": snapshot.routed,
        "terminated": snapshot.terminated,
        "secrets": secrets,
        "accepted": snapshot.accepted,
    })
}

/// Returns the raw body bytes of one step: `body_text`, else `body_b64u`,
/// else `body_repeat`, else the empty body (spec 06 R3.6, R3.12-R.3.15).
fn body_bytes(step: &Value) -> Vec<u8> {
    if let Some(text) = step.get("body_text").and_then(Value::as_str) {
        return text.as_bytes().to_vec();
    }
    if step.get("body_b64u").is_some() {
        return body_of(step);
    }
    if let Some(repeat) = step.get("body_repeat") {
        let character = text_of(&repeat["char"]);
        let count = integer_of(&repeat["count"]) as usize;
        return character.repeat(count).into_bytes();
    }
    Vec::new()
}

/// Returns the header pairs of one step, repeated names included (spec 06
/// R3.1, R3.2).
fn headers_of(value: &Value) -> Vec<(String, String)> {
    value
        .as_array()
        .map(|pairs| {
            pairs
                .iter()
                .map(|pair| (text_of(&pair[0]), text_of(&pair[1])))
                .collect()
        })
        .unwrap_or_default()
}

/// Returns the JSON strings of an array.
fn strings_of(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| items.iter().map(text_of).collect())
        .unwrap_or_default()
}

/// Returns an optional JSON string member, `None` when absent or `null`.
fn optional_string(value: &Value, member: &str) -> Option<String> {
    value.get(member).and_then(Value::as_str).map(str::to_owned)
}

/// Reads a JSON integer.
fn integer_of(value: &Value) -> i64 {
    value
        .as_i64()
        .unwrap_or_else(|| panic!("expected a JSON integer, got {value}"))
}

/// Returns the id of a case, for panic messages.
fn id_of(case: &Value) -> &str {
    case["id"].as_str().unwrap_or("<unnamed case>")
}
