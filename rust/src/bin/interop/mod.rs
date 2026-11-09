//! Helpers shared by the interop executables (interop/README.md sections 4-5),
//! mirroring the Go interop harness (interop/go/client).

pub mod net;
pub mod scenarios;

/// The only response codes whose 401 answers may be unsigned (interop README
/// section 5; mirror of interop/go/client/scenarios.go authFailureCodes).
pub const AUTH_FAILURE_CODES: [&str; 8] = [
    "missing_auth",
    "malformed_auth",
    "unsupported_version",
    "unknown_key",
    "key_inactive",
    "timestamp_out_of_window",
    "bad_signature",
    "replayed_nonce",
];

/// Reports whether `code` is one of the auth-failure codes.
pub fn is_auth_failure_code(code: &str) -> bool {
    AUTH_FAILURE_CODES.contains(&code)
}

/// Unix seconds now (negative before the epoch, mirroring Go time.Time.Unix).
/// Local copy: the client crate's helper is pub(crate) and unreachable from a
/// bin target.
pub fn unix_now() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

/// Strictly decodes 64 hex chars (upper or lower case) into 32 bytes.
pub fn hex_decode_32(s: &str) -> Result<[u8; 32], String> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", b.len()));
    }
    let mut out = [0u8; 32];
    for (i, pair) in b.as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("invalid hex character '{}'", c as char)),
    }
}

/// Tolerantly extracts the string at `{"error":{"code":...}}` (mirror of Go
/// parseErrorBody): a parse failure yields None, and so does a non-string
/// code (Go's unmarshal error path).
pub fn parse_error_code(body: &[u8]) -> Option<String> {
    let doc: serde_json::Value = serde_json::from_slice(body).ok()?;
    doc.get("error")?.get("code")?.as_str().map(str::to_owned)
}

/// Classification of a completed scenario step (interop README section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Rejected,
    ClientError,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Rejected => "rejected",
            Outcome::ClientError => "client_error",
        }
    }
}

impl serde::Serialize for Outcome {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// One reported scenario step (Go: stepResult).
#[derive(Debug)]
pub struct StepResult {
    pub kind: Outcome,
    /// Wire status; None only for a client_error (interop README section 5).
    pub status: Option<u16>,
    pub code: Option<String>,
    /// The JSON-RPC result member verbatim.
    pub data: Option<Box<serde_json::value::RawValue>>,
}

impl StepResult {
    /// Server accepted and the response signature verified.
    pub fn ok(data: Box<serde_json::value::RawValue>) -> Self {
        Self {
            kind: Outcome::Ok,
            // Every ok wire result reports http_status 200; sign-only builds
            // the struct directly with None.
            status: Some(200),
            code: None,
            data: Some(data),
        }
    }

    /// Server rejected; the status is always set (Go hasStatus=true).
    pub fn rejected(status: u16, code: impl Into<String>) -> Self {
        Self {
            kind: Outcome::Rejected,
            status: Some(status),
            code: Some(code.into()),
            data: None,
        }
    }

    /// Client-side verification failure; status stays None.
    pub fn client_error(code: impl Into<String>) -> Self {
        Self {
            kind: Outcome::ClientError,
            status: None,
            code: Some(code.into()),
            data: None,
        }
    }

    /// Wrapper for a failed intermediate step (mirror of Go
    /// requireIntermediate's failure shape): data = {"step":idx}; status and
    /// code come from `got` only when it is not already a client error.
    pub fn step_failure(idx: usize, got: &StepResult) -> Self {
        let data = serde_json::value::RawValue::from_string(format!(r#"{{"step":{idx}}}"#))
            .expect("static JSON object");
        let (status, code) = if got.kind == Outcome::ClientError {
            (None, got.code.clone())
        } else {
            // A failed intermediate carries its step's wire status (README 5).
            (got.status, got.code.clone())
        };
        Self {
            kind: Outcome::ClientError,
            status,
            code,
            data: Some(data),
        }
    }
}

/// One identity of spec/fixtures/keys.json. Unknown members are ignored by
/// design, mirroring Go.
#[derive(Debug, serde::Deserialize)]
pub struct SeedKey {
    pub name: String,
    pub seed_hex: String,
    pub kid: String,
}

/// The seeds file (Go: seedsFile).
#[derive(Debug, serde::Deserialize)]
pub struct SeedsFile {
    pub keys: Vec<SeedKey>,
}

/// Builds the JSON-RPC request body (mirror of Go rpcBody): tool "" means
/// ping with no params member; otherwise tools/call with the tool name and
/// the pre-serialized arguments verbatim (None omits the arguments member,
/// like Go's omitempty).
pub fn rpc_body(id: i64, tool: &str, arguments: Option<&str>) -> Vec<u8> {
    if tool.is_empty() {
        return format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#).into_bytes();
    }
    // serde_json escaping keeps the tool name valid JSON.
    let name = serde_json::to_string(tool).expect("String serialization cannot fail");
    match arguments {
        Some(args) => format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":{name},"arguments":{args}}}}}"#
        ),
        None => format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":{name}}}}}"#
        ),
    }
    .into_bytes()
}

/// Prints the ONE stdout result line of a completed scenario (interop README
/// section 5) and exits 0.
pub fn emit(scenario: &str, r: StepResult) -> ! {
    #[derive(serde::Serialize)]
    struct Emit<'a> {
        scenario: &'a str,
        outcome: Outcome,
        http_status: Option<u16>,
        code: Option<String>,
        data: Option<Box<serde_json::value::RawValue>>,
    }
    let line = Emit {
        scenario,
        outcome: r.kind,
        http_status: r.status,
        // An empty code is absent (Go: `if r.code != ""`); rejected steps
        // whose error body had no code report null the same way.
        code: r.code.filter(|c| !c.is_empty()),
        data: r.data,
    };
    println!(
        "{}",
        serde_json::to_string(&line).expect("static result shape serializes")
    );
    std::process::exit(0)
}

/// Harness-level failure: reason on stderr, no JSON (Go: fatal in
/// interop/go/client/main.go).
pub fn fatal(msg: impl std::fmt::Display) -> ! {
    eprintln!("interop-client: {msg}");
    std::process::exit(1)
}
