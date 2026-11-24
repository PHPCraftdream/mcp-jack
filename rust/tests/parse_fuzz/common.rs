use std::panic::{catch_unwind, AssertUnwindSafe};

pub const SEEDS: [u64; 6] = [0x51a1, 0xa017, 0xacce, 0xead3, 0x51a6, 0xec31];

pub fn iterations() -> usize {
    std::env::var("MCP_JACK_FUZZ_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(20_000)
}

pub fn seed(group: usize) -> u64 {
    let seed = std::env::var("MCP_JACK_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(SEEDS[group]);
    if seed == 0 {
        SEEDS[group]
    } else {
        seed
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn assert_mutations<F>(group: usize, corpus: &[&[u8]], mut operation: F)
where
    F: FnMut(&[u8]),
{
    assert!(!corpus.is_empty(), "empty deterministic corpus");
    let seed = seed(group);
    let count = iterations();
    let mut state = seed;
    let overlong_base64url = [b'A'; 128];
    let boundaries: [&[u8]; 12] = [
        b"0",
        b"-1",
        b"9007199254740992",
        b"9223372036854775808",
        b"1.5",
        b"\r",
        b"\n",
        b"\0",
        &[0xff],
        b"AAAA",
        &overlong_base64url,
        b"jack-auth",
    ];
    let mut run = |iteration: usize, bytes: &[u8]| {
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| operation(bytes))) {
            let decoded = String::from_utf8(bytes.to_vec());
            eprintln!(
                "panic seed={seed} iteration={iteration} input_hex={} input_utf8={decoded:?}",
                hex(bytes)
            );
            panic!("property failed seed={seed} iteration={iteration} input_hex={} input_utf8={decoded:?} input_bytes={bytes:?} payload={payload:?}", hex(bytes));
        }
    };
    for (i, item) in boundaries.iter().enumerate() {
        run(i, item);
    }
    let mut iteration = boundaries.len();
    for source in corpus.iter().filter(|source| source.len() <= 64) {
        for length in 0..=source.len() {
            run(iteration, &source[..length]);
            iteration += 1;
        }
    }
    let random_start = iteration;
    for n in 0..count.saturating_sub(boundaries.len()) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let source_full = corpus[n % corpus.len()];
        let source = &source_full[..source_full.len().min(4096)];
        let mut bytes = source.to_vec();
        match state % 5 {
            0 if !bytes.is_empty() => {
                let index = (state as usize >> 8) % bytes.len();
                bytes[index] ^= state as u8;
            }
            1 => {
                let index = (state as usize >> 8) % (bytes.len() + 1);
                bytes.insert(index, state as u8);
            }
            2 if !bytes.is_empty() => {
                let index = (state as usize >> 8) % bytes.len();
                bytes.remove(index);
            }
            3 => {
                let index = (state as usize >> 8) % (bytes.len() + 1);
                let tail = bytes[index..].to_vec();
                bytes.extend_from_slice(&tail);
            }
            _ => {
                let other_full = corpus[(n + 1) % corpus.len()];
                let other = &other_full[..other_full.len().min(4096)];
                let cut = (state as usize >> 8) % (other.len() + 1);
                bytes.extend_from_slice(&other[..cut]);
            }
        }
        run(random_start + n, &bytes);
    }
}

pub fn fixture(name: &str) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../spec/fixtures/modern")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse fixture {}: {error}", path.display()))
}

pub fn strings(value: &serde_json::Value, out: &mut Vec<Vec<u8>>) {
    match value {
        serde_json::Value::String(s) => out.push(s.as_bytes().to_vec()),
        serde_json::Value::Array(a) => {
            for v in a {
                strings(v, out);
            }
        }
        serde_json::Value::Object(o) => {
            for v in o.values() {
                strings(v, out);
            }
        }
        _ => {}
    }
}
