//! Two-phase verification (P1-B): `authenticate` performs steps 1-8 and the
//! body classification with NO native effect and NO audit event, and
//! `dispatch` performs the dispatch. An era-aware caller can therefore refuse a
//! request between the phases (spec 04 `S1`-`S12`) without committing state.
//!
//! The tests drive the verifier directly: the era decision and the header rules
//! live in the HTTP adapter and in `server::modern`, so "the mirrors will be
//! refused" is represented here by simply dropping the pending request.

use super::*;
use crate::server::audit::AUDIT_SUCCESS;

/// Arguments of a `jack.admin.user.create` for a fresh key named `name`.
fn create_args(name: &str) -> (RegistryEntry, String) {
    let (_, created) = test_key(name);
    let args = format!(
        r#"{{"name":"{name}","public_key":"{}"}}"#,
        created.public_key
    );
    (created, args)
}

/// A real native implementation plus the recording audit sink.
fn native_and_audit(
    sink: &Arc<MemoryAuditSink>,
) -> (Arc<dyn NativeTools>, Option<Arc<dyn AuditSink>>) {
    let native: Arc<dyn NativeTools> = Arc::new(Native::new(NativeOptions::default()));
    (native, Some(Arc::clone(sink) as Arc<dyn AuditSink>))
}

fn pending_of(authentication: Authentication) -> PendingRequest {
    match authentication {
        Authentication::Pending(pending) => pending,
        Authentication::Refused(res) => {
            panic!("expected a pending request, got rejection {res:?}")
        }
    }
}

#[test]
fn pending_request_dropped_without_dispatch_has_no_native_effect() {
    let (key, entry) = admin_key("root");
    let state = seeded_state(&[&entry]);
    let sink = Arc::new(MemoryAuditSink::new());
    let (native, audit) = native_and_audit(&sink);
    let mut cfg = config(NOW, Arc::clone(&state), Some(native));
    cfg.audit = audit;
    let v = verifier(cfg);

    let (created, args) = create_args("bob");
    let req = post_call(
        TOOL_ADMIN_USER_CREATE,
        Some(&args),
        &key,
        &entry.kid,
        &nonce(1),
    );
    let pending = pending_of(v.authenticate(&req));
    // The era-aware adapter refuses the mirrors here and stops: the pending
    // request is dropped instead of dispatched.
    drop(pending);

    // No registry write: the tool never ran.
    assert!(
        state.lookup(&created.kid).is_none(),
        "a dropped pending request must not create the user"
    );
    assert!(
        state.view().keys.iter().all(|e| e.name != "bob"),
        "a dropped pending request must not commit any registry entry"
    );
    // No audit event: the call never reached a tool.
    assert!(
        sink.events().is_empty(),
        "a dropped pending request must not write an audit event"
    );

    // Authentication itself did record the nonce, exactly like the one-shot
    // path always did.
    let replay = v.verify(&req);
    assert_eq!(replay.code, codes::REPLAYED_NONCE);
    assert!(!replay.nonce_recorded);
}

#[test]
fn dispatch_after_authenticate_runs_the_tool_and_audits_once() {
    let (key, entry) = admin_key("root");
    let state = seeded_state(&[&entry]);
    let sink = Arc::new(MemoryAuditSink::new());
    let (native, audit) = native_and_audit(&sink);
    let mut cfg = config(NOW, Arc::clone(&state), Some(native));
    cfg.audit = audit;
    let v = verifier(cfg);

    let (created, args) = create_args("bob");
    let req = post_call(
        TOOL_ADMIN_USER_CREATE,
        Some(&args),
        &key,
        &entry.kid,
        &nonce(1),
    );
    let pending = pending_of(v.authenticate(&req));
    // Nothing happened yet.
    assert!(state.lookup(&created.kid).is_none());
    assert!(sink.events().is_empty());

    let res = v.dispatch(pending);
    assert!(res.accepted);
    assert!(res.native);
    assert!(res.structured.is_some());
    assert_eq!(res.kid, entry.kid);
    assert!(state.lookup(&created.kid).is_some(), "the tool ran once");

    let events = sink.events();
    assert_eq!(events.len(), 1, "exactly one audit event");
    assert_eq!(events[0].tool, TOOL_ADMIN_USER_CREATE);
    assert_eq!(events[0].outcome, AUDIT_SUCCESS);
    assert_eq!(events[0].actor_kid, entry.kid);
    assert_eq!(events[0].target, "bob");

    // The pending request was consumed by `dispatch`; a second attempt with
    // the same request can only be a replay.
    assert_eq!(v.verify(&req).code, codes::REPLAYED_NONCE);
}

#[test]
fn pending_request_of_another_verifier_fails_closed() {
    let (key, entry) = admin_key("root");
    let state = seeded_state(&[&entry]);
    let sink = Arc::new(MemoryAuditSink::new());
    let (native_a, audit_a) = native_and_audit(&sink);
    let (native_b, audit_b) = native_and_audit(&sink);
    let mut cfg_a = config(NOW, Arc::clone(&state), Some(native_a));
    cfg_a.audit = audit_a;
    let mut cfg_b = config(NOW, Arc::clone(&state), Some(native_b));
    cfg_b.audit = audit_b;
    let a = verifier(cfg_a);
    let b = verifier(cfg_b);

    let (created, args) = create_args("mallory");
    let req = post_call(
        TOOL_ADMIN_USER_CREATE,
        Some(&args),
        &key,
        &entry.kid,
        &nonce(1),
    );
    let pending = pending_of(a.authenticate(&req));
    let res = b.dispatch(pending);

    // Fail closed: the signed 500 internal_error shape, nothing dispatched.
    assert!(!res.accepted);
    assert_eq!(res.http_status, 500);
    assert_eq!(res.code, "internal_error");
    assert_eq!(res.message, "internal error");
    assert_eq!(res.kid, entry.kid);
    // Signed: the nonce was consumed by the issuing verifier's authentication,
    // so the client holds a request signature to bind to.
    assert!(res.nonce_recorded);
    assert!(res.structured.is_none());
    assert!(res.audit.is_none());
    assert!(
        state.lookup(&created.kid).is_none(),
        "the foreign dispatch must not run the tool"
    );
    assert!(
        sink.events().is_empty(),
        "no audit event of the foreign call"
    );
}

#[test]
fn one_shot_verify_keeps_accept_and_reject_shapes() {
    let (key, entry) = test_key("alice");
    let state = seeded_state(&[&entry]);
    let v = verifier(config(NOW, Arc::clone(&state), Some(stub())));

    // A forwarded request: accepted, not native, carrying the identity.
    let forwarded = v.verify(&post_call("svc.status", None, &key, &entry.kid, &nonce(1)));
    assert!(forwarded.accepted);
    assert!(!forwarded.native);
    assert_eq!(forwarded.kid, entry.kid);
    assert_eq!(forwarded.rpc_id.as_deref(), Some("9"));
    assert_eq!(forwarded.tool, "svc.status");
    let identity = forwarded.identity.as_ref().expect("forwarded accept");
    assert_eq!(identity.kid(), entry.kid);
    assert_eq!(identity.name(), "alice");
    assert!(!identity.admin());

    // A native request: accepted, native, with the handler's structured content.
    let native = v.verify(&post_call(TOOL_WHOAMI, None, &key, &entry.kid, &nonce(2)));
    assert!(native.accepted);
    assert!(native.native);
    assert!(native.structured.is_some());
    assert!(native.identity.is_none());

    // A rejected request keeps its authentication rejection shape.
    let (_, other) = test_key("mallory");
    let unknown = v.verify(&post_call("svc.status", None, &key, &other.kid, &nonce(3)));
    assert!(!unknown.accepted);
    assert_eq!(unknown.http_status, 401);
    assert_eq!(unknown.code, codes::UNKNOWN_KEY);
    assert!(!unknown.nonce_recorded);
}
