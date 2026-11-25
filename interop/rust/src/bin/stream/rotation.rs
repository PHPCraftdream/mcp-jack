use std::io::Write as _;
use std::sync::{Arc, Mutex};

use mcp_jack::rotation::{
    Checkpoint, OwnedBinding, RotationServerKey, RotationServerProvider, RotationServerStore,
    RotationServerStoreOptions,
};
use mcp_jack::server::http::RotatingStreamConfig;
use mcp_jack::server::server_key::ServerKeyTool;

#[allow(dead_code)]
type StoreClock = Box<dyn FnMut() -> Result<u64, mcp_jack::rotation::RotationError> + Send>;

#[allow(dead_code)]
#[derive(Clone)]
struct RotationClockFile {
    path: String,
}

#[allow(dead_code)]
impl RotationClockFile {
    fn new(path: &str) -> Self {
        Self {
            path: path.to_owned(),
        }
    }

    fn sample(&self) -> Result<u64, mcp_jack::rotation::RotationError> {
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .ok_or(mcp_jack::rotation::RotationError {
                code: "rotation_clock_unavailable",
            })
    }
}

#[allow(dead_code)]
fn rotation_clock_fn(clock: RotationClockFile) -> StoreClock {
    Box::new(move || clock.sample())
}

#[allow(dead_code)]
pub(super) type RotationSetup = (
    Arc<Mutex<RotationServerStore<StoreClock>>>,
    Arc<RotationServerProvider<StoreClock>>,
    u64,
);

fn arg(arguments: &[String], name: &str) -> Option<String> {
    for (index, value) in arguments.iter().enumerate() {
        if value == name {
            return arguments.get(index + 1).cloned();
        }
        if let Some(value) = value.strip_prefix(&format!("{name}=")) {
            return Some(value.to_owned());
        }
    }
    None
}

fn required(arguments: &[String], name: &str) -> String {
    arg(arguments, name)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            eprintln!("stream server: missing {name}");
            std::process::exit(1)
        })
}

fn number_opt(arguments: &[String], name: &str) -> Option<u64> {
    arg(arguments, name).map(|value| {
        value.parse().unwrap_or_else(|_| {
            eprintln!("stream server: invalid {name}");
            std::process::exit(1)
        })
    })
}

pub(super) fn setup(
    arguments: &[String],
    seed: &[u8; 32],
    clock_file: &str,
) -> Option<RotationSetup> {
    let rotation_store_path = arg(arguments, "--rotation-store");
    let ring_seeds: Vec<(String, [u8; 32])> = arguments
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            (value == "--ring-seed")
                .then(|| arguments.get(index + 1))
                .flatten()
        })
        .map(|value| {
            let (reference, hex) = value.split_once('=').unwrap_or_else(|| {
                eprintln!("stream server: --ring-seed must be reference=hex");
                std::process::exit(1)
            });
            crate::interop::hex_decode_32(hex)
                .map(|seed| (reference.to_owned(), seed))
                .unwrap_or_else(|_| {
                    eprintln!("stream server: invalid ring seed");
                    std::process::exit(1)
                })
        })
        .collect();
    if ring_seeds.is_empty() != rotation_store_path.is_none() {
        eprintln!("stream server: --ring-seed and --rotation-store must be supplied together");
        std::process::exit(1);
    }
    if ring_seeds.is_empty() {
        return None;
    }
    let activation = number_opt(arguments, "--successor-activation").unwrap_or_else(|| {
        eprintln!("stream server: rotation requires --successor-activation");
        std::process::exit(1)
    });
    let store_path = std::path::Path::new(rotation_store_path.as_deref().unwrap());
    let server_key = ed25519_dalek::SigningKey::from_bytes(seed);
    let kid0 = mcp_jack::encoding::key_id(server_key.verifying_key().as_bytes());
    let checkpoint = Checkpoint {
        ordinal: 0,
        hash: "-".into(),
        kid: kid0,
        public_key: *server_key.verifying_key().as_bytes(),
        published_at: 0,
    };
    let store_options = RotationServerStoreOptions {
        binding: OwnedBinding {
            endpoint: format!("http://127.0.0.1:{}", required(arguments, "--port")),
            aud: required(arguments, "--aud"),
        },
        window: 30,
        checkpoint,
        anchor_reference: "ring-0".into(),
    };
    let clock = RotationClockFile::new(clock_file);
    if !store_path.exists() {
        RotationServerStore::initialize_unused(
            store_path,
            store_options.clone(),
            rotation_clock_fn(clock.clone()),
        )
        .unwrap_or_else(|error| {
            eprintln!("stream server: rotation store: {}", error.code);
            std::process::exit(1)
        });
    }
    let store = Arc::new(Mutex::new(
        RotationServerStore::open(store_path, store_options, rotation_clock_fn(clock))
            .unwrap_or_else(|error| {
                eprintln!("stream server: rotation store: {}", error.code);
                std::process::exit(1)
            }),
    ));
    let mut keys = vec![RotationServerKey {
        reference: "ring-0".into(),
        signer: Arc::new(
            mcp_jack::client::signer::InMemorySigner::from_seed(seed).unwrap_or_else(|error| {
                eprintln!("stream server: signer: {error}");
                std::process::exit(1)
            }),
        ),
    }];
    keys.extend(
        ring_seeds
            .iter()
            .map(|(reference, ring_seed)| RotationServerKey {
                reference: reference.clone(),
                signer: Arc::new(
                    mcp_jack::client::signer::InMemorySigner::from_seed(ring_seed).unwrap_or_else(
                        |error| {
                            eprintln!("stream server: signer: {error}");
                            std::process::exit(1)
                        },
                    ),
                ),
            }),
    );
    let provider = Arc::new(
        RotationServerProvider::new(store.clone(), keys).unwrap_or_else(|error| {
            eprintln!("stream server: rotation provider: {}", error.code);
            std::process::exit(1)
        }),
    );
    Some((store, provider, activation))
}

pub(super) fn announce(
    provider: &RotationServerProvider<StoreClock>,
    reference: &str,
    kid: &str,
    mut append_log: impl FnMut(serde_json::Value) -> Result<(), String>,
) -> bool {
    match provider.announce(reference, kid) {
        Ok(publication) => {
            let row = serde_json::json!({"event":"rotation_announced","reference":reference,"kid":kid,"published_at":publication.record.published_at,"activates_at":publication.record.activates_at,"head_hash":publication.record.hash});
            if let Err(error) = append_log(row) {
                eprintln!("stream server: rotation log: {error}");
                return false;
            }
            println!(
                "{}",
                serde_json::json!({"announced":true,"ordinal":publication.record.ordinal,"head_ordinal":publication.record.ordinal,"published_at":publication.record.published_at,"activates_at":publication.record.activates_at,"head_hash":publication.record.hash})
            );
            let _ = std::io::stdout().flush();
            true
        }
        Err(error) => {
            eprintln!("stream server: announce: {}", error.code);
            true
        }
    }
}

pub(super) fn server_key_tool(
    store: Arc<Mutex<RotationServerStore<StoreClock>>>,
    provider: Arc<RotationServerProvider<StoreClock>>,
) -> ServerKeyTool<StoreClock> {
    ServerKeyTool::new(store, provider)
}

pub(super) fn rotating_config(
    verifier: Arc<mcp_jack::server::verify::Verifier>,
    provider: Arc<RotationServerProvider<StoreClock>>,
    streams: mcp_jack::server::stream::StreamOptions,
) -> RotatingStreamConfig {
    RotatingStreamConfig {
        verifier,
        response_keys: provider,
        max_body_bytes: 0,
        max_response_bytes: 0,
        streams,
    }
}
