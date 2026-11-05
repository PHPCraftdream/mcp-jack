//! The JSON-RPC client of the SDK (Go: client/rpc.go). Client performs
//! signed, response-verified MCP tool calls over JSON-RPC.

use std::fmt;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use crate::client::error::{parse_error_body, ClientError, HttpError, RpcError, ToolError};
use crate::client::signer::Signer;
use crate::client::transport::{Clock, HttpRequest, NonceSource, SigningTransport, Transport};

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
    base_url: String,
    pub(crate) aud: String,
    pub(crate) signer: Arc<dyn Signer>,
    transport: SigningTransport<Arc<dyn Transport>>,
    /// Clock for the rotate proof: the proof ts must equal the header ts
    /// (spec 03 section 3.1), so rotate_key pins the transport clock to the
    /// value read here.
    pub(crate) now: Clock,
    /// Monotonic JSON-RPC id counter starting at 1 (Go: mutex-guarded
    /// nextID). Relaxed is sufficient: the value is returned and used
    /// directly, nothing is published through it.
    next_id: AtomicI64,
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
        })
    }

    /// Builds the JSON-RPC request body: fields in wire order and the
    /// argument bytes embedded exactly as given (matches the fixtures' byte
    /// order). `args_json` must already be valid JSON.
    fn build_request_body(id: i64, tool: &str, args_json: Option<&str>) -> String {
        // serde_json::to_string of a &str cannot fail (it is infallible for
        // strings), so only the format! allocation remains.
        let name = serde_json::to_string(tool).expect("string serialization is infallible");
        let args_json = args_json.unwrap_or("{}");
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{\"name\":{name},\"arguments\":{args_json}}}}}"
        )
    }

    /// One signed, verified tool call returning the raw structuredContent
    /// (Go: Client.call).
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

        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let req_json = Self::build_request_body(id, tool, args_json);

        let req = HttpRequest {
            method: "POST".to_string(),
            url: self.base_url.clone(),
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
            body: req_json.into_bytes(),
        };
        // From<TransportError> for ClientError does the mapping: transport
        // errors pass through unchanged (Go client.call).
        let resp =
            self.transport
                .round_trip_as(signer.unwrap_or(self.signer.as_ref()), pinned_ts, req)?;

        if !(200..=299).contains(&resp.status) {
            let (code, message) = parse_error_body(&resp.body);
            return Err(ClientError::Http(HttpError {
                status: resp.status,
                code,
                message,
            }));
        }

        let wire: JsonRpcResponse = serde_json::from_slice(&resp.body).map_err(|e| {
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
    use crate::client::transport::{HttpResponse, TransportError};
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
