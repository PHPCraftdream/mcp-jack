use mcp_jack::client::signer::Signer;
use mcp_jack::rotation::{Checkpoint, OwnedBinding, RotationStoreOptions, RotationTrustStore};
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
