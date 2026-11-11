use mcp_jack::auth_header::{ResponseAuth, format_response_auth};
use mcp_jack::client::signer::Signer;
use mcp_jack::client::{InMemorySigner, random_nonce, sign_request};
use mcp_jack::encoding::encode_b64url;
use mcp_jack::rotation::{
    Checkpoint, OwnedBinding, ResultCursor, RotationController, RotationResponse,
    RotationStoreOptions, RotationTrustStore,
};
use mcp_jack::signing::response_signing_string;
use std::cell::Cell;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;

struct Sandbox(PathBuf);

impl Drop for Sandbox {
    fn drop(&mut self) {
        // Только свежий test-owned каталог, без чужих артефактов.
        fs::remove_dir_all(&self.0).expect("remove consumer store sandbox");
    }
}

fn signed_response(signer: &dyn Signer, request_body: &[u8], body: &[u8]) -> Result<RotationResponse, String> {
    let client = InMemorySigner::generate().map_err(|_| "generate packaged controller client")?;
    let nonce = random_nonce().map_err(|_| "packaged controller nonce")?;
    let request = sign_request(&client, super::AUD, "POST", "/mcp", request_body, &nonce, super::NOW)
        .map_err(|_| "sign packaged controller request")?;
    let signing = response_signing_string(200, &request.auth.sig, signer.kid(), super::NOW, body);
    let signature = signer.sign(signing.as_bytes()).map_err(|_| "sign packaged controller response")?;
    Ok(RotationResponse {
        status: 200,
        headers: vec![format_response_auth(&ResponseAuth {
            kid: signer.kid().into(), ts: super::NOW, sig: encode_b64url(&signature),
        })],
        request_signature: request.auth.sig,
        body: body.to_vec(),
    })
}

pub(super) fn verify(signer: &dyn Signer) -> Result<(), String> {
    let root = std::env::temp_dir().join(format!(
        "jack-packaged-store-{}-{}",
        signer.kid(),
        std::process::id()
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .map_err(|_| "create consumer store sandbox")?;
    let sandbox = Sandbox(root);
    let path = sandbox.0.join("trust");
    let now = u64::try_from(super::NOW).map_err(|_| "consumer clock domain")?;
    let options = RotationStoreOptions {
        binding: OwnedBinding {
            endpoint: super::BASE_URL.into(),
            aud: super::AUD.into(),
        },
        window: 30,
        checkpoint: Checkpoint {
            ordinal: 0,
            hash: "-".into(),
            kid: signer.kid().into(),
            public_key: signer.public_key(),
            published_at: 0,
        },
    };
    let calls = Cell::new(0);
    let absent = RotationTrustStore::open(&path, options.clone(), || {
        calls.set(calls.get() + 1);
        Ok(now)
    });
    super::check(
        absent.is_err() && calls.get() == 0 && !path.exists(),
        "noncreating packaged store open",
    )?;
    RotationTrustStore::initialize_unused(&path, options.clone(), || Ok(now))
        .map_err(|_| "initialize packaged store")?;
    let mut store = RotationTrustStore::open(&path, options.clone(), || Ok(now))
        .map_err(|_| "open packaged store")?;
    super::check(
        sandbox.0.join("trust.owner").exists(),
        "packaged store owner lifetime",
    )?;
    let competing = RotationTrustStore::open(&path, options.clone(), || {
        calls.set(calls.get() + 1);
        Ok(now)
    });
    super::check(
        competing.is_err() && calls.get() == 0,
        "packaged store exclusive owner",
    )?;
    let (mut snapshot, clock) = store.snapshot().map_err(|_| "read packaged store")?;
    super::check(
        snapshot.revision == 1 && clock.high_water == now,
        "packaged store initialized state",
    )?;
    let guarded = store
        .check_snapshot_clock(&snapshot)
        .map_err(|_| "packaged store clock gate")?;
    super::check(guarded == clock, "packaged store stable guard")?;
    snapshot.head.hash = "caller-owned mutation".into();
    super::check(
        store
            .snapshot()
            .map_err(|_| "reread packaged store")?
            .0
            .head
            .hash
            == "-",
        "packaged store owned snapshot",
    )?;
    {
        let mut controller = RotationController::new(&mut store)
            .map_err(|_| "construct packaged response controller")?;
        let request = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"consumer.echo","arguments":{}}}"#;
        let opaque = [0xff, 0, 10];
        let verified = controller.verify_response(signed_response(signer, request.as_bytes(), &opaque)?)
            .map_err(|_| "verify packaged opaque response")?;
        super::check(verified == opaque, "packaged controller exact response bytes")?;
        let mut tampered = signed_response(signer, request.as_bytes(), &opaque)?;
        tampered.body.push(0);
        match controller.verify_response(tampered) {
            Err(error) => super::check(error.code == "bad_signature" && error.http_status == 0, "packaged controller tamper refusal")?,
            Ok(_) => return Err("packaged controller accepted tampered bytes".into()),
        }
        let cursor = ResultCursor { ordinal: 0, hash: "-".into() };
        let request = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"jack.server.key","arguments":{"after_ordinal":0,"after_hash":"-"}}}"#;
        // Fixed fixture: подставляются только canonical base64url public values.
        let page = format!(
            concat!(
                r#"{{"current":{{"kid":"{}","public_key":"{}"}},"#,
                r#""records":[],"head":{{"ordinal":0,"hash":"-"}},"complete":true}}"#,
            ),
            mcp_jack::encoding::key_id(&signer.public_key()),
            encode_b64url(&signer.public_key()),
        );
        super::check(
            !page.as_bytes().contains(&92) && page.bytes().all(|byte| byte.is_ascii() && !byte.is_ascii_control()),
            "packaged page fixture has no backslash or control bytes",
        )?;
        let mirror = page.replace('"', r#"\""#);
        let body = format!(
            concat!(
                r#"{{"jsonrpc":"2.0","id":7,"result":{{"#,
                r#""content":[{{"type":"text","text":"{}"}}],"structuredContent":{},"isError":false}}}}"#,
            ),
            mirror, page,
        ).into_bytes();
        let result = controller.accept_refresh(signed_response(signer, request.as_bytes(), &body)?, b"7", &cursor)
            .map_err(|_| "accept packaged explicit empty refresh")?;
        super::check(!result.committed && result.complete && result.revision == 1 && result.head == cursor && result.terminal == cursor,
            "packaged empty refresh is not a trust mutation")?;
    }
    store.close().map_err(|_| "close packaged store")?;
    super::check(
        !sandbox.0.join("trust.owner").exists(),
        "packaged store owner release",
    )?;
    let mut restored = RotationTrustStore::open(&path, options, || Ok(now))
        .map_err(|_| "reopen packaged store")?;
    let (snapshot, clock) = restored
        .snapshot()
        .map_err(|_| "read reopened packaged store")?;
    super::check(
        snapshot.revision == 1 && snapshot.head.hash == "-" && clock.high_water == now,
        "packaged store durable reopen",
    )?;
    restored
        .close()
        .map_err(|_| "close reopened packaged store")?;
    Ok(())
}
