//! The JSON-RPC client of the SDK (Go: client/rpc.go). Client performs
//! signed, response-verified MCP tool calls over JSON-RPC.

use std::fmt;
use std::sync::atomic::AtomicI64;
use std::sync::{Arc, Mutex};

use crate::client::error::{ClientError, RpcError, ToolError};
use crate::client::modern::flow::FlowState;
use crate::client::modern::ClientEra;
use crate::client::signer::Signer;
use crate::client::transport::{Clock, NonceSource, SigningTransport, Transport};

/// Everything NewClient needs to reach and trust one server.
pub struct Config {
    /// Absolute http/https MCP endpoint.
    pub base_url: String,
    /// Audience bound into the signing string.
    pub aud: String,
    /// The client's Ed25519 signer.
    pub signer: Arc<dyn Signer>,
    /// Pinned 32-byte raw server public key.
    pub server_key: [u8; 32],
    /// The unsigned underlying transport. The client signs every request and
    /// verifies every response around it (SigningTransport). Go's Config.HTTP
    /// (a caller-supplied, itself-signing http.Client) has no Rust analogue:
    /// a caller needing a standalone signing transport uses SigningTransport
    /// directly.
    pub transport: Arc<dyn Transport>,
    /// Optional signing clock; defaults to the system clock.
    pub now: Option<Clock>,
    /// Optional nonce source; defaults to OS randomness.
    pub nonce: Option<NonceSource>,
    /// Response timestamp tolerance; <= 0 means the default window.
    pub window_seconds: i64,
}

/// Performs signed, response-verified MCP tool calls over JSON-RPC (Go:
/// client.Client). Send + Sync; the id counter is atomic.
pub struct Client {
    pub(crate) base_url: String,
    pub(crate) aud: String,
    pub(crate) signer: Arc<dyn Signer>,
    pub(crate) transport: SigningTransport<Arc<dyn Transport>>,
    /// Clock for the rotate proof: the proof ts must equal the header ts
    /// (spec 03 section 3.1), so rotate_key pins the transport clock to the
    /// value read here.
    pub(crate) now: Clock,
    /// Monotonic JSON-RPC id counter starting at 1 (Go: mutex-guarded
    /// nextID). Relaxed is sufficient: the value is returned and used
    /// directly, nothing is published through it.
    pub(crate) next_id: AtomicI64,
    /// The era this client's requests are built in; default
    /// [`ClientEra::Legacy`].
    pub(crate) era: ClientEra,
    /// The era flow state (spec 04 section 6 `C9`): the resolved era, the
    /// negotiated legacy version and session, and the one `-32022` retry
    /// budget. Private.
    pub(crate) flow: Mutex<FlowState>,
    /// Single-flight guard around the handshake and the auto probe, so
    /// concurrent callers never run two of them at once.
    pub(crate) era_lock: Mutex<()>,
}

// Manual impl: Debug must never expose signer or key material (spec 01
// section 6); only public configuration data is rendered.
impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Client {{ base_url: {}, aud: {} }}",
            self.base_url, self.aud
        )
    }
}

// The JSON-RPC request body is assembled by hand: declaration order is wire
// order and the argument bytes are embedded exactly as given (matching the
// fixtures' byte order, e.g. admin-vectors enroll-ok). serde_json's RawValue
// needs the feature-gated raw_value module, which the crate does not enable.

#[derive(serde::Deserialize)]
struct JsonRpcResponse {
    // Decoded to mirror the Go struct's full wire shape; not read by the
    // happy/error paths.
    #[allow(dead_code)]
    #[serde(default)]
    jsonrpc: String,
    #[allow(dead_code)]
    #[serde(default)]
    id: i64,
    #[serde(default)]
    result: Option<JsonRpcResult>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

#[derive(serde::Deserialize)]
struct JsonRpcResult {
    #[serde(default)]
    content: Vec<JsonRpcContent>,
    #[serde(rename = "isError", default)]
    is_error: bool,
    #[serde(rename = "structuredContent", default)]
    structured_content: Option<serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct JsonRpcContent {
    // Decoded to mirror the Go struct's full wire shape; only `text` is read.
    #[allow(dead_code)]
    #[serde(rename = "type", default)]
    content_type: String,
    #[serde(default)]
    text: String,
}

#[derive(serde::Deserialize)]
struct JsonRpcError {
    code: i64,
    #[serde(default)]
    message: String,
    data: Option<serde_json::Value>,
}

/// The first non-empty content text, or "" (Go's loop over Result.Content).
fn first_text(contents: &[JsonRpcContent]) -> String {
    contents
        .iter()
        .map(|c| c.text.as_str())
        .find(|t| !t.is_empty())
        .unwrap_or("")
        .to_string()
}

/// Decodes a verified 2xx `tools/call` body into its structuredContent (Go:
/// Client.call's result handling). A JSON-RPC `error` member, an `isError`
/// result and a missing or null `structuredContent` all fail the call.
pub(crate) fn decode_tool_result(body: &[u8]) -> Result<serde_json::Value, ClientError> {
    let wire: JsonRpcResponse = serde_json::from_slice(body).map_err(|e| {
        ClientError::Client(format!("jack client: decoding json-rpc response: {e}"))
    })?;
    if let Some(err) = wire.error {
        return Err(ClientError::Rpc(RpcError {
            code: err.code,
            message: err.message,
            data: err.data,
        }));
    }
    let Some(result) = wire.result else {
        return Err(ClientError::Client(
            "jack client: json-rpc response has neither result nor error".to_string(),
        ));
    };
    if result.is_error {
        return Err(ClientError::Tool(ToolError {
            message: first_text(&result.content),
            structured: result.structured_content.clone(),
        }));
    }
    // Go treats an explicit null as a present-but-empty raw message
    // (decode no-op); this port treats it as missing — a documented,
    // harmless divergence for every tool result shape in the spec.
    match result.structured_content {
        None | Some(serde_json::Value::Null) => Err(ClientError::Client(
            "jack client: missing structuredContent".to_string(),
        )),
        Some(v) => Ok(v),
    }
}

impl Client {
    /// Validates cfg and returns a Client (Go: NewClient; validations in the
    /// same order).
    pub fn new(cfg: Config) -> Result<Self, ClientError> {
        crate::client::url::validate_base_url(&cfg.base_url)?;
        if cfg.aud.is_empty() {
            return Err(ClientError::Client(
                "jack client: aud must be non-empty".to_string(),
            ));
        }
        if crate::client::auth::has_control(&cfg.aud) {
            return Err(ClientError::Client(
                "jack client: aud must not contain control characters".to_string(),
            ));
        }
        // Go's nil-signer and server-key-length checks are unrepresentable:
        // Arc<dyn Signer> is non-null and [u8; 32] fixes the length.
        // Local validation never becomes an HTTP response: the validator's
        // server-side admission status (400) is zeroed for the client-side
        // surface (spec 01 section 5: client-side failures carry no status).
        crate::ed25519::validate_public_key(&cfg.server_key).map_err(|mut e| {
            e.http_status = 0;
            ClientError::Protocol(e)
        })?;
        let now = cfg
            .now
            .unwrap_or_else(crate::client::transport::system_clock);
        let transport = SigningTransport {
            transport: cfg.transport,
            aud: cfg.aud.clone(),
            signer: Arc::clone(&cfg.signer),
            server_key: cfg.server_key,
            now: Arc::clone(&now),
            nonce: cfg
                .nonce
                .unwrap_or_else(crate::client::transport::random_nonce_source),
            window_seconds: cfg.window_seconds,
        };
        Ok(Self {
            base_url: cfg.base_url,
            aud: cfg.aud,
            signer: cfg.signer,
            transport,
            now,
            next_id: AtomicI64::new(0),
            era: ClientEra::default(),
            flow: Mutex::new(FlowState::default()),
            era_lock: Mutex::new(()),
        })
    }

    /// Selects the era this client builds its requests in (spec 04 section 6).
    /// The default [`ClientEra::Legacy`] keeps every 0.1.x byte of the request
    /// unchanged and issues exactly one request per call; [`ClientEra::Modern`]
    /// adds `params._meta` and the `MCP-Protocol-Version`, `Mcp-Method` and
    /// `Mcp-Name` headers, also one request per call; [`ClientEra::Auto`] is the
    /// only era that resolves anything — it probes once with `server/discover`
    /// and follows the verified verdict (`C9`).
    pub fn with_era(mut self, era: ClientEra) -> Self {
        self.era = era;
        self
    }

    /// The era this client builds its requests in.
    pub fn era(&self) -> ClientEra {
        self.era
    }

    /// Forgets the resolved era, the negotiated legacy version and the legacy
    /// session, so the next call of an [`ClientEra::Auto`] client probes again
    /// (spec 04 `C9`).
    pub fn reset_era(&self) {
        crate::client::modern::flow::reset_era(self);
    }

    /// Builds the legacy JSON-RPC `tools/call` body: fields in wire order and
    /// the argument bytes embedded exactly as given (matches the fixtures' byte
    /// order, the 0.1.x shape). `args_json` must already be valid JSON.
    pub(crate) fn build_request_body(id: i64, tool: &str, args_json: Option<&str>) -> String {
        // serde_json::to_string of a &str cannot fail (it is infallible for
        // strings), so only the format! allocation remains.
        let name = serde_json::to_string(tool).expect("string serialization is infallible");
        let args_json = args_json.unwrap_or("{}");
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":{name},\"arguments\":{args_json}}}}}"
        )
    }

    /// One signed, verified tool call returning the raw structuredContent
    /// (Go: Client.call). The configured era decides the request: the default
    /// legacy era is the 0.1.x one-shot request, the modern era mirrors `_meta`,
    /// and only `Auto` resolves the era first (spec 04 section 6, `C9`) by
    /// probing once with `server/discover`; a legacy verdict then runs the
    /// `initialize` handshake once and carries the session and the negotiated
    /// version. Neither fixed era adds a request. A per-request signer override
    /// is a self-authenticating one-off and skips the flow (`enroll` signs with
    /// the new key, which may not be registered yet).
    pub(crate) fn call_raw(
        &self,
        signer: Option<&dyn Signer>,
        pinned_ts: Option<i64>,
        tool: &str,
        arguments_json: Option<&str>,
    ) -> Result<serde_json::Value, ClientError> {
        // Go always marshals valid JSON; the raw path is new API surface, so
        // it validates.
        let args_json = match arguments_json {
            None => None,
            Some(s) => {
                serde_json::from_str::<serde::de::IgnoredAny>(s).map_err(|e| {
                    ClientError::Client(format!("jack client: arguments are not valid JSON: {e}"))
                })?;
                Some(s)
            }
        };
        crate::client::modern::flow::tool_call(self, signer, pinned_ts, tool, args_json)
    }

    /// Calls a tool and returns the raw structuredContent. A
    /// serde_json::Value object serializes in its map order (alphabetical by
    /// default); callers who need Go-compatible wire byte order (fixtures,
    /// interop) use `call_tool_raw_str` with pre-serialized structs.
    pub fn call_tool_raw(
        &self,
        tool: &str,
        arguments: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value, ClientError> {
        match arguments {
            None => self.call_tool_raw_str(tool, None),
            Some(v) => {
                let s = serde_json::to_string(v).map_err(|e| {
                    ClientError::Client(format!("jack client: marshal arguments: {e}"))
                })?;
                self.call_tool_raw_str(tool, Some(&s))
            }
        }
    }

    /// `call_tool_raw` with pre-serialized argument JSON: raw-byte control
    /// for interop replay/tamper scenarios (design doc interop.md section 8).
    pub fn call_tool_raw_str(
        &self,
        tool: &str,
        arguments_json: Option<&str>,
    ) -> Result<serde_json::Value, ClientError> {
        self.call_raw(None, None, tool, arguments_json)
    }

    /// Calls a tool and decodes structuredContent into T (Go:
    /// json.Unmarshal into out).
    pub fn call_tool<T: serde::de::DeserializeOwned>(
        &self,
        tool: &str,
        arguments: Option<&serde_json::Value>,
    ) -> Result<T, ClientError> {
        let v = self.call_tool_raw(tool, arguments)?;
        serde_json::from_value(v).map_err(|e| {
            ClientError::Client(format!("jack client: decoding structuredContent: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_header::{format_response_auth, parse_request_auth, ResponseAuth};
    use crate::client::signer::InMemorySigner;
    use crate::client::transport::{HttpRequest, HttpResponse, TransportError};
    use crate::encoding::{decode_b64url_fixed, encode_b64url, key_id};
    use crate::signing::{request_signing_string, response_signing_string};
    use ed25519_dalek::{Signer as DalekSigner, SigningKey};
    use std::sync::Mutex;

    // keys.json seeds, the conformance fixture is the oracle.
    const ALICE_SEED_HEX: &str = "15949421ee8241acde219c4cff93cc346a0488e049deff61da312798b758d28f";
    const SVC_SEED_HEX: &str = "cc9e39e830a43e09c6372b14852ef80a2bb8e7b1aa4c04bf076f33e0aad2c901";

    const AUD: &str = "https://svc.example.test";
    const BASE_URL: &str = "https://svc.example.test/mcp";
    const FIXED_TS: i64 = 1767225600;

    fn hex_bytes(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(pair).expect("valid"), 16)
                .expect("hex digit");
        }
        out
    }

    fn alice() -> Arc<dyn Signer> {
        Arc::new(InMemorySigner::from_seed(&hex_bytes(ALICE_SEED_HEX)).expect("32-byte seed"))
    }

    fn svc_key() -> [u8; 32] {
        *SigningKey::from_bytes(&hex_bytes(SVC_SEED_HEX))
            .verifying_key()
            .as_bytes()
    }

    fn svc_signing_key() -> SigningKey {
        SigningKey::from_bytes(&hex_bytes(SVC_SEED_HEX))
    }

    struct UnreachableTransport;

    impl Transport for UnreachableTransport {
        fn round_trip(&self, _req: HttpRequest) -> Result<HttpResponse, TransportError> {
            unreachable!("config validation must fail first");
        }
    }

    fn signed_response(
        server: &SigningKey,
        request_sig_b64: &str,
        status: u16,
        body: &[u8],
        ts: i64,
    ) -> (String, Vec<u8>) {
        let kid = key_id(server.verifying_key().as_bytes());
        let msg = response_signing_string(status as i64, request_sig_b64, &kid, ts, body);
        let sig = server.sign(msg.as_bytes());
        let header = format_response_auth(&ResponseAuth {
            kid,
            ts,
            sig: encode_b64url(&sig.to_bytes()),
        });
        (header, body.to_vec())
    }

    #[test]
    fn jsonrpc_request_wire_order() {
        let body = Client::build_request_body(
            1,
            "jack.enroll",
            Some(r#"{"code":"c","name":"newbie","public_key":"p"}"#),
        );
        assert_eq!(
            body,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.enroll","arguments":{"code":"c","name":"newbie","public_key":"p"}}}"#
        );
        let empty = Client::build_request_body(2, "jack.whoami", None);
        assert_eq!(
            empty,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"jack.whoami","arguments":{}}}"#
        );
    }

    /// Renders headers as a vector of `&str` pairs for compact assertions.
    fn pairs(headers: &[(String, String)]) -> Vec<(&str, &str)> {
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect()
    }

    #[test]
    fn build_call_legacy_and_modern_shapes() {
        // The default era is the 0.1.x shape: unchanged body, one header.
        let legacy = Client::new(Config {
            base_url: BASE_URL.to_string(),
            aud: AUD.to_string(),
            signer: alice(),
            server_key: svc_key(),
            transport: Arc::new(UnreachableTransport),
            now: None,
            nonce: None,
            window_seconds: 30,
        })
        .expect("valid config");
        assert_eq!(legacy.era(), ClientEra::Legacy);
        assert_eq!(
            Client::build_request_body(1, "jack.whoami", None),
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jack.whoami","arguments":{}}}"#
        );

        // The modern era: `params._meta` plus the `C2` mirror headers.
        let (params_text, headers) = crate::client::modern::flow::build_modern_parts(
            "tools/call",
            &serde_json::json!({"name": "get_weather", "arguments": {"region": "eu"}}),
            crate::modern::MODERN_MIN,
        )
        .expect("modern build");
        let body = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{params_text}}}"
        );
        let wire: serde_json::Value = serde_json::from_str(&body).expect("body is JSON");
        assert_eq!(wire["jsonrpc"], "2.0");
        assert_eq!(wire["id"], 1);
        assert_eq!(wire["method"], "tools/call");
        let params = wire["params"].as_object().expect("params object");
        assert_eq!(params["name"], "get_weather");
        assert_eq!(params["arguments"], serde_json::json!({"region": "eu"}));
        assert_eq!(
            params["_meta"],
            serde_json::json!({
                "io.modelcontextprotocol/protocolVersion": crate::modern::MODERN_MIN,
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": crate::modern::IMPLEMENTATION_NAME,
                    "version": crate::modern::IMPLEMENTATION_VERSION,
                },
            })
        );
        assert_eq!(
            pairs(&headers),
            [
                ("MCP-Protocol-Version", crate::modern::MODERN_MIN),
                ("Mcp-Method", "tools/call"),
                ("Mcp-Name", "get_weather"),
            ]
        );
    }

    #[test]
    fn jsonrpc_result_wire_names() {
        // The wire names are the Go tags exactly: content, isError,
        // structuredContent (Go: client/rpc.go jsonrpcResult). A snake_case
        // `is_error` field without the rename silently decodes as false.
        let w: JsonRpcResult = serde_json::from_str(
            r#"{"content":[{"type":"text","text":"boom"}],"isError":true,"structuredContent":{"x":1}}"#,
        )
        .expect("wire names must decode");
        assert!(w.is_error, "isError must land in is_error");
        assert_eq!(w.content.len(), 1);
        assert_eq!(w.content[0].text, "boom");
        assert_eq!(w.structured_content, Some(serde_json::json!({ "x": 1 })));
    }

    #[test]
    fn call_raw_rejects_invalid_arguments_json() {
        let cfg = Config {
            base_url: BASE_URL.to_string(),
            aud: AUD.to_string(),
            signer: alice(),
            server_key: svc_key(),
            transport: Arc::new(UnreachableTransport),
            now: None,
            nonce: None,
            window_seconds: 30,
        };
        let client = Client::new(cfg).expect("valid config");
        let err = client
            .call_tool_raw_str("jack.whoami", Some("not json"))
            .expect_err("invalid arguments JSON");
        assert!(
            err.to_string()
                .starts_with("jack client: arguments are not valid JSON"),
            "got {err}"
        );
    }

    #[test]
    fn config_validation() {
        let mk = |base_url: &str, aud: &str, key: [u8; 32]| Config {
            base_url: base_url.to_string(),
            aud: aud.to_string(),
            signer: alice(),
            server_key: key,
            transport: Arc::new(UnreachableTransport),
            now: None,
            nonce: None,
            window_seconds: 30,
        };

        let err = Client::new(mk("ftp://h", AUD, svc_key())).expect_err("bad scheme");
        assert_eq!(
            err.to_string(),
            "jack client: base url must be an absolute http/https URL with a host"
        );
        let err = Client::new(mk("", AUD, svc_key())).expect_err("empty base url");
        assert_eq!(
            err.to_string(),
            "jack client: base url must be an absolute http/https URL with a host"
        );
        let err = Client::new(mk(BASE_URL, "", svc_key())).expect_err("empty aud");
        assert_eq!(err.to_string(), "jack client: aud must be non-empty");

        // The signing string is LF-joined lines including the audience, so an
        // aud with control characters would make it ambiguous (Go:
        // audHasControl in NewClient).
        for bad in ["a\nb", "a\rb", "a\0b", "a\tb", "a\u{7f}b"] {
            let err = Client::new(mk(BASE_URL, bad, svc_key()))
                .expect_err("control-character aud must be rejected");
            assert_eq!(
                err.to_string(),
                "jack client: aud must not contain control characters",
                "aud {bad:?}"
            );
        }
        // An ordinary value is still accepted (covered by the valid build
        // below and the existing happy-path tests).

        // The identity encoding fails spec 03 section 2; the validator's 400
        // admission status must be zeroed on the client side.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let err = Client::new(mk(BASE_URL, AUD, identity)).expect_err("identity key");
        match err {
            ClientError::Protocol(j) => {
                assert_eq!(j.code, crate::error::codes::KEY_REJECTED);
                assert_eq!(j.http_status, 0, "local validation carries no HTTP status");
            }
            other => panic!("expected Protocol, got {other:?}"),
        }

        // A fully valid config builds.
        Client::new(mk(BASE_URL, AUD, svc_key())).expect("valid config must build");
    }

    #[test]
    fn call_tool_raw_happy_path_over_canned_transport() {
        let alice_signing = SigningKey::from_bytes(&hex_bytes(ALICE_SEED_HEX));
        let alice_pub = *alice_signing.verifying_key().as_bytes();
        let svc = svc_signing_key();
        let captured_id: Arc<Mutex<Option<i64>>> = Arc::new(Mutex::new(None));
        let captured_clone = Arc::clone(&captured_id);

        let handler = move |req: &HttpRequest| -> Result<HttpResponse, TransportError> {
            // Verify the incoming request signature like the server would.
            let raw = req.header("Jack-Auth").expect("signed request header");
            let auth = parse_request_auth(&[raw]).expect("canonical request header");
            let sig = decode_b64url_fixed(&auth.sig, 64).expect("canonical sig");
            let target = crate::client::url::request_target(&req.url).expect("absolute url");
            let msg = request_signing_string(
                &req.method,
                &target,
                AUD,
                &auth.kid,
                auth.ts,
                &auth.nonce,
                &req.body,
            );
            assert_eq!(auth.kid, key_id(&alice_pub));
            assert!(
                crate::ed25519::verify(&alice_pub, msg.as_bytes(), &sig),
                "request signature must verify"
            );

            let wire: serde_json::Value =
                serde_json::from_slice(&req.body).expect("json-rpc request body");
            *captured_clone.lock().expect("mutex") = wire.get("id").and_then(|v| v.as_i64());
            let req_sig = &auth.sig;
            let body = br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}],"isError":false,"structuredContent":{"ok":true}}}"#;
            let (header, body) = signed_response(&svc, req_sig, 200, body, FIXED_TS);
            Ok(HttpResponse {
                status: 200,
                headers: vec![
                    ("Jack-Auth".to_string(), header),
                    ("Content-Type".to_string(), "application/json".to_string()),
                ],
                body,
            })
        };

        let now: Clock = Arc::new(|| FIXED_TS);
        let nonce: NonceSource = Arc::new(|| Ok(vec![7u8; 16]));
        let cfg = Config {
            base_url: BASE_URL.to_string(),
            aud: AUD.to_string(),
            signer: Arc::new(InMemorySigner::from_seed(&hex_bytes(ALICE_SEED_HEX)).expect("seed")),
            server_key: svc_key(),
            transport: Arc::new(FakeHandlerTransport {
                handler: Box::new(handler),
            }),
            now: Some(now),
            nonce: Some(nonce),
            window_seconds: 30,
        };
        let client = Client::new(cfg).expect("valid config");

        let result = client
            .call_tool_raw("jack.whoami", None)
            .expect("happy path call");
        assert_eq!(result, serde_json::json!({"ok": true}));
        assert_eq!(*captured_id.lock().expect("mutex"), Some(1));

        // The id counter is monotonic across calls.
        client
            .call_tool_raw("jack.whoami", None)
            .expect("second call");
        assert_eq!(*captured_id.lock().expect("mutex"), Some(2));
    }

    /// Test-only request handler closure type.
    type Handler = Box<dyn Fn(&HttpRequest) -> Result<HttpResponse, TransportError> + Send + Sync>;

    /// Test-only Transport wrapper over a boxed closure.
    struct FakeHandlerTransport {
        handler: Handler,
    }

    impl Transport for FakeHandlerTransport {
        fn round_trip(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
            (self.handler)(&req)
        }
    }

    #[test]
    fn response_decode_shapes() {
        // (a) error only.
        let wire: JsonRpcResponse = serde_json::from_str(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}"#,
        )
        .expect("error body decodes");
        assert!(wire.result.is_none());
        let err = wire.error.expect("error present");
        assert_eq!(err.code, -32601);
        assert_eq!(err.message, "nope");
        assert!(err.data.is_none());

        // (b) first non-empty text wins.
        let contents = [
            JsonRpcContent {
                content_type: "text".to_string(),
                text: "boom".to_string(),
            },
            JsonRpcContent {
                content_type: "text".to_string(),
                text: String::new(),
            },
        ];
        assert_eq!(first_text(&contents), "boom");
        let empty = [JsonRpcContent {
            content_type: "text".to_string(),
            text: String::new(),
        }];
        assert_eq!(first_text(&empty), "");

        // (c) neither result nor error.
        let wire: JsonRpcResponse =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":1}"#).expect("bare body decodes");
        assert!(wire.result.is_none());
        assert!(wire.error.is_none());
    }
}
