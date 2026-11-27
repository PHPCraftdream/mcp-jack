use super::*;
use crate::server::state::MemoryState;
use crate::user_key::ServerSigningKey;
use std::sync::atomic::{AtomicUsize, Ordering};

const NOW: i64 = 1_767_225_600;
const AUD: &str = "aud";

/// Deterministic key material derived from `id` (Go: stateTestKey).
fn test_signing(id: &str) -> ServerSigningKey {
    let seed = Sha256::digest(id.as_bytes());
    ServerSigningKey::from_bytes(&seed.into())
}

fn test_key(id: &str, name: &str) -> RegistryEntry {
    let public = test_signing(id).verifying_key().to_bytes();
    RegistryEntry {
        kid: key_id(&public),
        public_key: encode_b64url(&public),
        name: name.to_owned(),
        admin: false,
        not_before: None,
        not_after: None,
    }
}

/// Like `test_key` but with the admin flag set.
fn admin_key(id: &str, name: &str) -> RegistryEntry {
    let mut entry = test_key(id, name);
    entry.admin = true;
    entry
}

/// Native with a deterministic random source; invite codes repeat.
fn deterministic_native() -> Native {
    Native::new(NativeOptions {
        random_bytes: Some(Arc::new(|n| Ok(vec![0xA5; n]))),
    })
}

fn raw_args(json: &str) -> Option<Box<RawValue>> {
    Some(serde_json::from_str::<Box<RawValue>>(json).unwrap())
}

fn args_of(json: &str) -> Args {
    parse_args(&raw_args(json)).unwrap()
}

fn make_call<'a>(
    tool: &'static str,
    arguments: Option<Box<RawValue>>,
    caller: Option<&'a RegistryEntry>,
    kid: &'a str,
    state: Arc<dyn StateStore>,
) -> NativeCall<'a> {
    NativeCall {
        tool,
        arguments,
        caller,
        kid,
        ts: NOW,
        now: NOW,
        aud: AUD,
        state,
        target: String::new(),
    }
}

fn seed(entries: &[RegistryEntry], invites: &[InviteRecord], state: &dyn StateStore) {
    state
        .update(&mut |e| {
            for k in entries {
                e.put_key(k.clone());
            }
            for i in invites {
                e.put_invite(i.clone());
            }
            Ok(())
        })
        .unwrap();
}

mod arguments_and_audit;

mod lifecycle_and_admin;
