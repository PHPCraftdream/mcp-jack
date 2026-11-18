use super::*;

// ---------------------------------------------------------------------------
// Driven event_cases: server emission.
// ---------------------------------------------------------------------------

struct PinnedKey {
    reference: String,
    signer: Arc<InMemorySigner>,
}

impl PinnedKey {
    fn handle(&self) -> RotationServerKey {
        RotationServerKey {
            reference: self.reference.clone(),
            signer: Arc::clone(&self.signer) as Arc<dyn Signer>,
        }
    }
}

struct ServerRing {
    sandbox: Sandbox,
    provider: RotationServerProvider<ServerClock>,
    now: Arc<AtomicU64>,
    keys: Vec<PinnedKey>,
}

/// Builds a real three-key ring whose record arithmetic matches the fixture
/// exactly (R1 published 1000 activates 173800, R2 published 4600 activates
/// 177400). The fixture ships no private keys, so the kids are seed-derived.
fn server_ring(announces: &[(usize, u64)]) -> ServerRing {
    let sandbox = Sandbox::new();
    let keys: Vec<PinnedKey> = [51u8, 52, 53]
        .iter()
        .enumerate()
        .map(|(index, seed)| PinnedKey {
            reference: format!("k{index}"),
            signer: Arc::new(InMemorySigner::from_seed(&[*seed; 32]).expect("signer")),
        })
        .collect();
    let anchor = &keys[0];
    let options = RotationServerStoreOptions {
        binding: OwnedBinding {
            endpoint: "https://svc.example.test/mcp".to_owned(),
            aud: "https://svc.example.test".to_owned(),
        },
        window: 30,
        checkpoint: Checkpoint {
            ordinal: 0,
            hash: "-".to_owned(),
            kid: anchor.signer.kid().to_owned(),
            public_key: anchor.signer.public_key(),
            published_at: 0,
        },
        anchor_reference: anchor.reference.clone(),
    };
    let now = Arc::new(AtomicU64::new(1_000));
    let init_now = Arc::clone(&now);
    RotationServerStore::initialize_unused(&sandbox.file(), options.clone(), || {
        Ok(init_now.load(Ordering::SeqCst))
    })
    .expect("initialize server store");
    let store_now = Arc::clone(&now);
    let store = Arc::new(Mutex::new(
        RotationServerStore::open(
            &sandbox.file(),
            options,
            Box::new(move || Ok(store_now.load(Ordering::SeqCst))) as ServerClock,
        )
        .expect("open server store"),
    ));
    let handles: Vec<RotationServerKey> = keys.iter().map(PinnedKey::handle).collect();
    let provider = RotationServerProvider::new(store, handles).expect("provider");
    for (index, at) in announces {
        now.store(*at, Ordering::SeqCst);
        let publication = provider
            .announce(&keys[*index].reference, keys[*index].signer.kid())
            .expect("announce");
        assert_eq!(
            publication.record.published_at, *at,
            "publication time is the fresh sample"
        );
    }
    ServerRing {
        sandbox,
        provider,
        now,
        keys,
    }
}

/// Fixture ring-slot kid: ordinal 0 is the anchor (old kid of R1), ordinal k
/// is the new kid of record ordinal k.
fn fixture_selected_kid(records: &[String], ordinal: u64) -> String {
    let lines: Vec<&str> = records[0].split('\n').collect();
    if ordinal == 0 {
        lines[5].to_owned()
    } else {
        lines[6].to_owned()
    }
}

/// Selects the signer at signing_time and checks ring-slot equivalence with
/// the fixture's selectedOrdinal (kid literals differ; no private keys ship).
fn emission_authorized(
    ring: &ServerRing,
    ordinal: usize,
    signing_time: u64,
) -> ResponseKeyAuthorization {
    assert!(ring.sandbox.file().exists(), "server store file present");
    ring.now.store(signing_time, Ordering::SeqCst);
    let request = ResponseKeyRequest {
        status: 200,
        tool: "other/tool",
        request_signature: "candidate-event-request-signature",
        body: b"{}",
    };
    let auth = ring
        .provider
        .authorize_response(&request)
        .expect("authorized");
    assert_eq!(auth.timestamp, signing_time, "fresh signing sample");
    let selected = &ring.keys[ordinal];
    assert_eq!(
        auth.signer.public_key(),
        selected.signer.public_key(),
        "exactly one pinned signer selected (structural signatures:1)"
    );
    auth
}

#[test]
fn vector_server_final_eligible_single_signature() {
    let vectors = load_vectors();
    let case = find_event(&vectors, "server-final-eligible-single-signature");
    let EventInput::Emission {
        clock_generation_before,
        clock_generation_now,
        emission_time,
        records,
        selected_ordinal,
        signing_time,
        selected_kid,
        ..
    } = &case.input
    else {
        panic!("emission input");
    };
    assert_eq!(clock_generation_before, clock_generation_now);
    assert_eq!(signing_time, emission_time);
    assert_eq!(records.len(), 1, "fixture ring holds R1 only");
    assert_eq!(
        selected_kid.as_str(),
        fixture_selected_kid(records, *selected_ordinal),
        "fixture selected kid matches its ring slot"
    );
    let ring = server_ring(&[(1, 1_000)]);
    assert_eq!(
        1_000 + GRACE_SECONDS,
        173_800,
        "R1 activates at A1 like the fixture"
    );
    let auth = emission_authorized(&ring, *selected_ordinal as usize, *signing_time);
    let gate = auth.final_gate;
    assert!(gate().is_ok(), "eligible emission passes the final gate");
    (auth.release)();
    eprintln!(
        "verdict {} = driven-with-deviation (gate Ok; signer selected exactly once; fixture kid \
         literals mapped by ring ordinal/public-key equivalence)",
        case.id
    );
}

#[test]
fn vector_server_final_cutoff_no_resign() {
    let vectors = load_vectors();
    let case = find_event(&vectors, "server-final-cutoff-no-resign");
    let EventInput::Emission {
        emission_time,
        records,
        selected_ordinal,
        signer_ready,
        signing_time,
        selected_kid,
        ..
    } = &case.input
    else {
        panic!("emission input");
    };
    assert_eq!(*signer_ready, Some(true));
    assert_eq!(records.len(), 2, "fixture ring holds R1 and R2");
    assert_eq!(
        selected_kid.as_str(),
        fixture_selected_kid(records, *selected_ordinal),
        "fixture selected kid matches its ring slot"
    );
    let ring = server_ring(&[(1, 1_000), (2, 4_600)]);
    assert_eq!(4_600 + GRACE_SECONDS, 177_400, "R2 activates at A2");
    let auth = emission_authorized(&ring, *selected_ordinal as usize, *signing_time);
    // Emission at the exact cutoff: the signed key is strictly retired.
    ring.now.store(*emission_time, Ordering::SeqCst);
    let gate = auth.final_gate;
    let error = gate().expect_err("cutoff refuses").code;
    assert_eq!(
        error, "rotation_state_unavailable",
        "strict cutoff, no fallback"
    );
    (auth.release)();
    eprintln!(
        "verdict {} = driven-with-deviation (emit:false via refused final gate at emission 177400 \
         vs cutoff 177400; resigns:0 structural - there is no re-sign API)",
        case.id
    );
}

#[test]
fn vector_server_final_generation_fence_no_fallback() {
    let vectors = load_vectors();
    let case = find_event(&vectors, "server-final-generation-fence-no-fallback");
    let EventInput::Emission {
        clock_generation_before,
        clock_generation_now,
        emission_time,
        records,
        selected_ordinal,
        signing_time,
        ..
    } = &case.input
    else {
        panic!("emission input");
    };
    assert_eq!(
        clock_generation_before + 1,
        *clock_generation_now,
        "the model bumps clockGeneration between signing and emission"
    );
    assert_eq!(records.len(), 2);
    let ring = server_ring(&[(1, 1_000), (2, 4_600)]);
    let auth = emission_authorized(&ring, *selected_ordinal as usize, *signing_time);
    // Semantic equivalent of the generation fence: the clock moves backward
    // between signing and emission; the final gate must refuse, no fallback.
    ring.now.store(*emission_time - 1, Ordering::SeqCst);
    let gate = auth.final_gate;
    let error = gate().expect_err("fence refuses").code;
    assert_eq!(error, "rotation_state_unavailable");
    (auth.release)();
    eprintln!(
        "verdict {} = driven-with-deviation (emit:false via refused final gate after a clock \
         rollback; Rust has no clockGeneration so the rollback is the documented equivalent)",
        case.id
    );
}
