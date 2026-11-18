use super::*;

// ---------------------------------------------------------------------------
// Identity hand-off (spec 02 section 3): every forwarded accept carries a
// VerifiedIdentity extension built by the layer from the verifier result;
// native jack.* calls and rejections never reach the inner service, so no
// identity exists for them.
// ---------------------------------------------------------------------------

/// Alice (non-admin) sends an ordinary tool call: the wrapped service observes
/// the typed extension with exactly her registry snapshot {kid, "alice",
/// false}. The typed lookup cannot see more than the one extension the layer
/// inserted (no public constructor -> no duplicate insertion).
#[tokio::test]
async fn identity_extension_forwarded_to_wrapped_service() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let alice_kid = alice.kid().to_string();
    let signed = signed_request(&alice, "POST", "/mcp", STATUS_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "POST", "/mcp", STATUS_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    let seen = h.inner.seen_identities();
    assert_eq!(seen.len(), 1, "exactly one forwarded request");
    let id = seen[0]
        .as_ref()
        .expect("forwarded accept carries the identity extension");
    assert_eq!(id.kid(), alice_kid);
    assert_eq!(id.name(), "alice");
    assert!(!id.admin());
}

/// The admin caller's identity keeps admin()==true on an ORDINARY tool call
/// (the flag gates only jack.admin.*): mirrors the fixture
/// accept-admin-identity vector.
#[tokio::test]
async fn identity_admin_flag_true_forwarded() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let root = harness::signer_by_name("root");
    let root_kid = root.kid().to_string();
    let signed = signed_request(&root, "POST", "/mcp", STATUS_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "POST", "/mcp", STATUS_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    let seen = h.inner.seen_identities();
    assert_eq!(seen.len(), 1);
    let id = seen[0].as_ref().expect("identity extension present");
    assert_eq!(id.kid(), root_kid);
    assert_eq!(id.name(), "root");
    assert!(id.admin());
}

/// No identity anywhere outside forwarded accepts: the native root
/// jack.admin.user.list answer never touches the inner service, and an
/// unknown-key rejection (401) stops before any dispatch.
#[tokio::test]
async fn identity_absent_on_native_and_rejects() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let root = harness::signer_by_name("root");
    let signed = signed_request(&root, "POST", "/mcp", LIST_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "POST", "/mcp", LIST_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(h.inner.calls(), 0, "native dispatch never calls the inner");

    // A key NOT in the registry: signed with a locally built signer that was
    // never seeded into the harness store (same idiom as the harness'
    // UNRELATED_SEED_HEX; a local constant is fine).
    const UNKNOWN_SEED_HEX: &str =
        "b7e2c41d08a95f36c7d0e4b8a16f3925dc8047ab6e1c5f92384d0bec7a6f1520";
    let stranger = harness::seed_signer(UNKNOWN_SEED_HEX);
    let signed = signed_request(&stranger, "POST", "/mcp", STATUS_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "POST", "/mcp", STATUS_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 401);
    assert_eq!(error_code(&got.body), "unknown_key");
    assert_eq!(h.inner.calls(), 0, "rejections never call the inner");
    assert!(
        h.inner.seen_identities().is_empty(),
        "no identity exists for native calls or rejections"
    );
}

/// SERVER-AUTHENTICATED (spec 02 section 3): forged identity material in the
/// request bytes — an "identity" member in the arguments plus X-Jack-Kid /
/// X-Jack-Admin / X-Jack-Name headers — cannot influence the extension. The
/// inner service still sees exactly the registry snapshot for alice.
#[tokio::test]
async fn identity_unspoofable_by_remote_data() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let alice_kid = alice.kid().to_string();
    let root = harness::signer_by_name("root");
    let root_kid = root.kid().to_string();
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"svc.status","arguments":{"identity":{"kid":"root-kid-forged","name":"root","admin":true}}}}"#;
    let signed = signed_request(&alice, "POST", "/mcp", body);
    let req = http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Jack-Auth", signed.header_value.as_str())
        .header("X-Jack-Kid", root_kid.as_str())
        .header("X-Jack-Admin", "true")
        .header("X-Jack-Name", "root")
        .body(Full::new(Bytes::copy_from_slice(body)))
        .expect("static request parts");
    let got = inspect(send(&h.service, req).await.expect("no inner error")).await;
    assert_eq!(got.status, 200);
    let seen = h.inner.seen_identities();
    assert_eq!(seen.len(), 1);
    let id = seen[0].as_ref().expect("identity extension present");
    // Exactly the registry snapshot — the extension is constructed only by
    // the layer from the verifier result (no public constructor), so request
    // bytes cannot influence it.
    assert_eq!(id.kid(), alice_kid);
    assert_eq!(id.name(), "alice");
    assert!(!id.admin());
}

/// Coordinates the first request with the handler's identity signal. The
/// request future is owned here: every error path drops it, and the timeout
/// caller can cancel it without leaving a detached task behind.
/// Cancellation is terminal, not resumable: it drops the owned request future
/// and its in-flight handler work; no detached task remains.
/// cancel-safe: NO — cancellation is terminal; the owned request is dropped, not retried.
async fn request_after_identity<F, C>(
    request: F,
    entered: tokio::sync::oneshot::Receiver<Option<VerifiedIdentity>>,
    release: tokio::sync::oneshot::Sender<()>,
    before_release: C,
) -> Result<(VerifiedIdentity, F::Output), &'static str>
where
    F: std::future::Future,
    C: FnOnce(&VerifiedIdentity) -> Result<(), &'static str>,
{
    tokio::pin!(request);
    let identity = tokio::select! {
        signal = entered => match signal {
            Ok(Some(identity)) => identity,
            Ok(None) => {
                if release.send(()).is_err() {
                    return Err("handler received no verified identity; release gate was already closed");
                }
                return Err("handler received no verified identity");
            }
            Err(_) => {
                let _ = release.send(());
                return Err("first handler identity signal was dropped");
            }
        },
        _ = &mut request => {
            return Err("first request completed before the handler identity signal");
        }
    };

    if let Err(error) = before_release(&identity) {
        let _ = release.send(());
        return Err(error);
    }
    if release.send(()).is_err() {
        return Err("handler release gate closed before release");
    }
    let response = request.await;
    Ok((identity, response))
}

/// SNAPSHOT LIFECYCLE (spec 02 section 3): an in-flight handler keeps the
/// identity snapshot from verification time even while the registry changes
/// under it; the NEXT request observes the change.
#[tokio::test]
async fn identity_snapshot_lifecycle_across_registry_change() {
    // Built manually like new_harness, keeping a handle to the MemoryState.
    let state = Arc::new(MemoryState::new());
    seed_registry(&state);
    let verifier = {
        let now_clock: Clock = Arc::new(move || FIXTURE_NOW);
        Arc::new(
            Verifier::new(Config {
                aud: FIXTURE_AUD.to_string(),
                state: state.clone() as Arc<dyn StateStore>,
                nonces: Arc::new(NonceStore::new()),
                audit: None,
                native: Some(Arc::new(Native::new(NativeOptions::default()))),
                window_seconds: 30,
                now: now_clock,
            })
            .expect("verifier"),
        )
    };
    let layer = JackLayer::new(HandlerConfig {
        verifier,
        server_key: server_signing_key(),
        max_body_bytes: 0,
        max_response_bytes: 0,
    });

    let entered: Arc<Mutex<Option<tokio::sync::oneshot::Sender<Option<VerifiedIdentity>>>>> =
        Arc::new(Mutex::new(None));
    let gate: Arc<Mutex<Option<tokio::sync::oneshot::Receiver<()>>>> = Arc::new(Mutex::new(None));
    let retained: Arc<Mutex<Vec<Option<VerifiedIdentity>>>> = Arc::new(Mutex::new(Vec::new()));
    let svc = layer.layer(tower::util::BoxCloneService::new(tower::service_fn({
        let entered = Arc::clone(&entered);
        let gate = Arc::clone(&gate);
        let retained = Arc::clone(&retained);
        move |req: http::Request<Full<Bytes>>| {
            let entered = Arc::clone(&entered);
            let gate = Arc::clone(&gate);
            let retained = Arc::clone(&retained);
            async move {
                let entered_tx = entered.lock().expect("entered mutex").take();
                let parked_rx = gate.lock().expect("gate mutex").take();
                if let Some(tx) = entered_tx {
                    // Always report handler entry, including a missing extension.
                    let _ = tx.send(req.extensions().get::<VerifiedIdentity>().cloned());
                }
                if let Some(rx) = parked_rx {
                    let _ = rx.await;
                }
                // Read the actual request extension only AFTER the test releases
                // the parked handler and changes the registry.
                retained
                    .lock()
                    .expect("retained identities mutex")
                    .push(req.extensions().get::<VerifiedIdentity>().cloned());
                Ok::<_, String>(
                    http::Response::builder()
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from(INNER_OK_BODY.to_vec())))
                        .expect("static response parts"),
                )
            }
        }
    })));

    let alice = harness::signer_by_name("alice");
    let alice_kid = alice.kid().to_string();

    // The outer timeout bounds the identity handshake, parked-handler release
    // and completion, plus the subsequent request. The first request future is
    // polled directly and dropped on every failure/timeout path.
    let flow = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        *entered.lock().expect("entered mutex") = Some(entered_tx);
        *gate.lock().expect("gate mutex") = Some(release_rx);

        // First request: handler parks with alice's admin=false snapshot.
        let signed = signed_request(&alice, "POST", "/mcp", STATUS_BODY);
        let request = svc
            .clone()
            .oneshot(build_request(&signed, "POST", "/mcp", STATUS_BODY));
        let (in_flight, first_response) =
            request_after_identity(request, entered_rx, release_tx, |identity| {
                // Mutate the registry only after the handler has signalled
                // entry and while it is still parked.
                let mut entry = state.lookup(&alice_kid).ok_or("alice is not registered")?;
                entry.admin = true;
                let promoted = entry;
                state
                    .update(&mut |edit| {
                        edit.put_key(promoted.clone());
                        Ok(())
                    })
                    .map_err(|_| "registry update failed")?;

                // The signal's snapshot was false before promotion.
                if identity.admin() {
                    return Err("handler-entry identity was already promoted");
                }
                Ok(())
            })
            .await?;
        let first_response = first_response.map_err(|_| "first request returned an inner error")?;
        if first_response.status() != 200 {
            return Err("first request returned an unexpected status");
        }

        // Second signature is fresh (including its nonce) and uses the same
        // FIXTURE_NOW clock through signed_request and the verifier fixture.
        let signed = signed_request(&alice, "POST", "/mcp", STATUS_BODY);
        let second_response = svc
            .clone()
            .oneshot(build_request(&signed, "POST", "/mcp", STATUS_BODY))
            .await
            .map_err(|_| "second request returned an inner error")?;
        if second_response.status() != 200 {
            return Err("second request returned an unexpected status");
        }

        Ok::<_, &'static str>(in_flight)
    })
    .await
    .expect("identity snapshot lifecycle must finish within its deadline")
    .expect("identity handshake and requests must succeed");

    assert_eq!(flow.kid(), alice_kid);
    assert_eq!(flow.name(), "alice");
    assert!(
        !flow.admin(),
        "the handler-entry snapshot predates promotion"
    );

    let retained = retained.lock().expect("retained identities mutex").clone();
    assert_eq!(retained.len(), 2);
    let first_retained = retained[0]
        .as_ref()
        .expect("first handler retained its request identity");
    assert_eq!(first_retained.kid(), alice_kid);
    assert_eq!(first_retained.name(), "alice");
    assert!(
        !first_retained.admin(),
        "the actual request extension remains the pre-promotion snapshot after release"
    );
    let second_retained = retained[1]
        .as_ref()
        .expect("subsequent handler received an identity");
    assert!(
        second_retained.admin(),
        "subsequent requests see the registry change"
    );
}

#[tokio::test]
async fn identity_snapshot_handshake_cancellation_drops_request_future() {
    struct DropWitness(Arc<AtomicBool>);
    impl Drop for DropWitness {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let dropped = Arc::new(AtomicBool::new(false));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<Option<VerifiedIdentity>>();
    let (release_tx, _release_rx) = tokio::sync::oneshot::channel();
    let request = {
        let dropped = Arc::clone(&dropped);
        async move {
            let _witness = DropWitness(dropped);
            std::future::pending::<()>().await
        }
    };

    let timed_out = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        request_after_identity(request, entered_rx, release_tx, |_| Ok(())),
    )
    .await;
    drop(entered_tx);

    let timeout_error: tokio::time::error::Elapsed =
        timed_out.expect_err("identity handshake should remain pending");
    assert_eq!(timeout_error.to_string(), "deadline has elapsed");
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn identity_snapshot_handshake_rejects_missing_identity_and_early_completion() {
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    entered_tx.send(None).expect("test receiver is present");
    let parked_request = async move {
        let _ = release_rx.await;
        "parked request"
    };
    let missing = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        request_after_identity(parked_request, entered_rx, release_tx, |_| Ok(())),
    )
    .await
    .expect("missing-identity coordination must be bounded");
    assert_eq!(
        missing.unwrap_err(),
        "handler received no verified identity"
    );

    let (_entered_tx, entered_rx) = tokio::sync::oneshot::channel::<Option<VerifiedIdentity>>();
    let (release_tx, _release_rx) = tokio::sync::oneshot::channel();
    let early = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        request_after_identity(
            std::future::ready("completed too early"),
            entered_rx,
            release_tx,
            |_| Ok(()),
        ),
    )
    .await
    .expect("early-completion coordination must be bounded");
    assert_eq!(
        early.unwrap_err(),
        "first request completed before the handler identity signal"
    );
}

/// Availability (spec 02 section 3): a GET that a handler runs forwards with
/// the identity extension.
#[tokio::test]
async fn get_forwards_with_identity() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let alice_kid = alice.kid().to_string();
    let signed = signed_request(&alice, "GET", "/mcp", b"");
    let got = inspect(
        send(&h.service, build_request(&signed, "GET", "/mcp", b""))
            .await
            .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(h.inner.calls(), 1);
    let seen = h.inner.seen_identities();
    assert_eq!(seen.len(), 1);
    let id = seen[0].as_ref().expect("GET forwards carry the identity");
    assert_eq!(id.kid(), alice_kid);
    assert_eq!(id.name(), "alice");
    assert!(!id.admin());
}

/// A plain response-object JSON-RPC body forwards like any other ordinary
/// traffic and carries the identity: mirrors the fixture accept-response-object.
#[tokio::test]
async fn response_object_forwards_with_identity() {
    let h = new_harness(0, InnerResponse::ok_json(INNER_OK_BODY));
    let alice = harness::signer_by_name("alice");
    let alice_kid = alice.kid().to_string();
    let signed = signed_request(&alice, "POST", "/mcp", INNER_OK_BODY);
    let got = inspect(
        send(
            &h.service,
            build_request(&signed, "POST", "/mcp", INNER_OK_BODY),
        )
        .await
        .expect("no inner error"),
    )
    .await;
    assert_eq!(got.status, 200);
    assert_eq!(got.body.as_ref(), INNER_OK_BODY);
    assert_eq!(h.inner.calls(), 1);
    let seen = h.inner.seen_identities();
    assert_eq!(seen.len(), 1);
    let id = seen[0].as_ref().expect("identity extension present");
    assert_eq!(id.kid(), alice_kid);
    assert_eq!(id.name(), "alice");
    assert!(!id.admin());
}
