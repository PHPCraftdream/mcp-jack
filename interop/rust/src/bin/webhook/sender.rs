use crate::interop::hex_decode_32;
use ed25519_dalek::SigningKey;
use mcp_jack::{
    encoding::key_id,
    webhook::{
        self,
        http::{
            Clock, HostResolver, HttpsTransport, OutgoingMessage, SendAction, Sender, SenderConfig,
            SystemResolver, TransportFailure, TransportRequest, TransportResponse,
            WebhookTransport,
        },
        ssrf::{
            delivery::{delivery_decision, DeliveryDecision, DeliveryInput},
            url::check_url,
        },
        verification::EndpointGate,
        MessageKind,
    },
};
use serde::Serialize;
use std::{
    collections::HashMap,
    fs,
    net::IpAddr,
    sync::{Arc, Mutex},
};
fn usage(s: impl std::fmt::Display) -> ! {
    eprintln!("interop-client: {s}");
    std::process::exit(2)
}
fn tls_ca_pem(text: &str) -> Result<Vec<Vec<u8>>, &'static str> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut rest = text.trim();
    let mut certificates = Vec::new();
    while !rest.is_empty() {
        let Some(after_begin) = rest.strip_prefix(BEGIN) else {
            return Err("invalid TLS CA PEM");
        };
        let Some((encoded, after_end)) = after_begin.split_once(END) else {
            return Err("invalid TLS CA PEM");
        };
        let der = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            encoded.split_whitespace().collect::<String>(),
        )
        .map_err(|_| "invalid TLS CA PEM")?;
        if der.is_empty() {
            return Err("invalid TLS CA PEM");
        }
        certificates.push(der);
        rest = after_end.trim();
    }
    if certificates.is_empty() {
        return Err("invalid TLS CA PEM: no certificates");
    }
    Ok(certificates)
}
fn fail(s: impl std::fmt::Display) -> ! {
    eprintln!("interop-client: {s}");
    std::process::exit(1)
}
#[derive(Default)]
struct Args(HashMap<String, Vec<String>>);
impl Args {
    fn parse() -> Self {
        let mut a = Self::default();
        let mut i = {
            let mut raw = std::env::args().skip(1);
            let mut rest = Vec::new();
            while let Some(x) = raw.next() {
                if x == "--mode" {
                    raw.next();
                } else if !x.starts_with("--mode=") {
                    rest.push(x);
                }
            }
            rest.into_iter()
        };
        let allowed = [
            "scenario",
            "url",
            "aud",
            "clock-file",
            "secret-seed",
            "messages",
            "subscription-id",
            "signing-seed-hex",
            "jack-seed-hex",
            "allowlist",
            "allowed-range",
            "resolver-file",
            "rebind-address",
            "body-file",
            "tls-ca",
            "tls-ca-der",
        ];
        while let Some(x) = i.next() {
            let Some(x) = x.strip_prefix("--") else {
                usage("unexpected positional argument")
            };
            let (k, v) = x
                .split_once('=')
                .map(|(k, v)| (k.to_owned(), Some(v.to_owned())))
                .unwrap_or((x.to_owned(), None));
            if !allowed.contains(&k.as_str()) {
                usage(format!("unsupported flag --{k}"));
            }
            let value = match v {
                Some(v) => v,
                None => match i.next() {
                    Some(v) if !v.starts_with("--") => v,
                    _ => usage(format!("missing --{k}")),
                },
            };
            a.0.entry(k).or_default().push(value);
        }
        a
    }
    fn one(&self, k: &str) -> Option<&str> {
        self.0.get(k).and_then(|v| v.last()).map(String::as_str)
    }
    fn req(&self, k: &str) -> String {
        self.one(k)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| usage(format!("--{k} required")))
            .to_owned()
    }
    fn all(&self, k: &str) -> Vec<String> {
        self.0.get(k).cloned().unwrap_or_default()
    }
    fn has(&self, k: &str) -> bool {
        self.0.contains_key(k)
    }
}
fn clock(p: &str) -> i64 {
    fs::read_to_string(p)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| fail("invalid clock file"))
}
struct VClock(String);
impl Clock for VClock {
    fn now_ms(&self) -> i64 {
        clock(&self.0) * 1000
    }
    fn sleep_until_ms(&self, t: i64) {
        fs::write(&self.0, format!("{}\n", t.div_euclid(1000)))
            .unwrap_or_else(|e| fail(format!("clock write: {e}")))
    }
}
struct Resolver {
    map: HashMap<String, Vec<IpAddr>>,
    rebind: Option<IpAddr>,
    count: Mutex<HashMap<String, usize>>,
}
impl HostResolver for Resolver {
    fn resolve(&self, h: &str, _: u16) -> Result<Vec<IpAddr>, webhook::WebhookError> {
        let mut c = self.count.lock().unwrap();
        let n = c.entry(h.to_ascii_lowercase()).or_default();
        *n += 1;
        if (*n).is_multiple_of(2) {
            if let Some(ip) = self.rebind {
                return Ok(vec![ip]);
            }
        }
        self.map
            .get(&h.to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| {
                webhook::WebhookError::new(500, "connection_refused", "resolver failure")
            })
    }
}
struct Capture {
    inner: HttpsTransport,
    ids: Mutex<Vec<String>>,
    challenge: Mutex<Vec<String>>,
}
impl WebhookTransport for Capture {
    fn send(&self, r: &TransportRequest) -> Result<TransportResponse, TransportFailure> {
        if let Some((_, v)) = r
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("webhook-id"))
        {
            if v.starts_with("msg_verification_") {
                self.challenge.lock().unwrap().push(v.clone())
            } else {
                self.ids.lock().unwrap().push(v.clone())
            }
        }
        self.inner.send(r)
    }
}
#[derive(Serialize)]
struct Ready<'a> {
    ready: bool,
    role: &'static str,
    callback_url: &'a str,
    derived_subscription_id: String,
}
#[derive(Serialize)]
struct Item {
    message: usize,
    kind: String,
    webhook_id: String,
    attempts: u32,
    accepted: bool,
    http_status: Option<u16>,
    last_error: Option<String>,
}
#[derive(Serialize)]
struct ResultLine<'a> {
    event: &'static str,
    scenario: &'a str,
    role: &'static str,
    callback_url: &'a str,
    derived_subscription_id: String,
    results: Vec<Item>,
}
fn kind(k: &str) -> MessageKind {
    match k {
        "gap" => MessageKind::Gap,
        "terminated" => MessageKind::Terminated,
        _ => MessageKind::Event,
    }
}
fn body(k: &str, a: &Args) -> Vec<u8> {
    match k{"event"=>br#"{"eventId":"evt_1","name":"incident.created","timestamp":"2026-11-22T09:00:00Z","data":{"incidentId":"INC-1234","severity":"P1"},"cursor":"cursor_xyz"}"#.to_vec(),"gap"=>br#"{"type":"gap","cursor":"cursor_7f3a"}"#.to_vec(),"terminated"=>br#"{"type":"terminated","error":{"code":-32024,"message":"Forbidden","data":{"reason":"Access revoked"}}}"#.to_vec(),"raw"=>fs::read(a.one("body-file").unwrap_or_else(||fail("raw requires body file"))).unwrap_or_else(|e|fail(format!("body file: {e}"))),_=>fail("invalid kind")}
}
fn run() {
    let a = Args::parse();
    let scenario = a.req("scenario");
    let url = a.req("url");
    let aud = a.req("aud");
    let cp = a.req("clock-file");
    let derived = webhook::subscription::subscription_key(
        "alice",
        &url,
        "incident.created",
        Some(&serde_json::json!({"severity":"P1"})),
    )
    .unwrap_or_else(|e| fail(e))
    .id;
    let sub = a.one("subscription-id").unwrap_or(&derived).to_owned();
    let secret = webhook::encoding::WebhookSecret::from_bytes(
        webhook::encoding::sha256(a.req("secret-seed").as_bytes()).to_vec(),
    );
    let map = if let Some(p) = a.one("resolver-file") {
        serde_json::from_slice::<HashMap<String, Vec<String>>>(
            &fs::read(p).unwrap_or_else(|e| fail(format!("resolver file: {e}"))),
        )
        .unwrap_or_else(|e| fail(format!("resolver JSON: {e}")))
        .into_iter()
        .map(|(k, v)| {
            (
                k.to_ascii_lowercase(),
                v.into_iter()
                    .map(|s| s.parse().unwrap_or_else(|_| fail("bad resolver IP")))
                    .collect(),
            )
        })
        .collect()
    } else {
        HashMap::new()
    };
    let resolver: Arc<dyn HostResolver> = if a.has("resolver-file") {
        Arc::new(Resolver {
            map: map.clone(),
            rebind: a
                .one("rebind-address")
                .map(|s| s.parse().unwrap_or_else(|_| fail("bad rebind IP"))),
            count: Mutex::new(HashMap::new()),
        })
    } else {
        Arc::new(SystemResolver::new().unwrap_or_else(|e| fail(e)))
    };
    let ca_pem = a.one("tls-ca").map(|p| {
        let text = fs::read_to_string(p).unwrap_or_else(|e| fail(format!("TLS CA: {e}")));
        let certs = tls_ca_pem(&text).unwrap_or_else(|e| fail(e));
        HttpsTransport::with_roots(certs).unwrap_or_else(|e| fail(format!("TLS CA: {e}")))
    });
    let ca_der = a.one("tls-ca-der").map(|p| {
        let der = fs::read(p).unwrap_or_else(|e| fail(format!("TLS CA: {e}")));
        HttpsTransport::with_roots(vec![der]).unwrap_or_else(|e| fail(format!("TLS CA: {e}")))
    });
    let transport = ca_der
        .or(ca_pem)
        .unwrap_or_else(|| HttpsTransport::new().unwrap_or_else(|e| fail(e)));
    let capture = Arc::new(Capture {
        inner: transport,
        ids: Mutex::new(vec![]),
        challenge: Mutex::new(vec![]),
    });
    let sender = Sender::new(
        capture.clone(),
        resolver,
        Arc::new(VClock(cp.clone())),
        SenderConfig {
            allowed_ranges: a.all("allowed-range"),
            max_body_bytes: 262144,
            verification_ttl_ms: Some(3600000),
        },
        Arc::new(EndpointGate::new(a.all("allowlist"), Some(3600000))),
    );
    let sign = a.one("signing-seed-hex").map(|s| {
        let k =
            SigningKey::from_bytes(&hex_decode_32(s).unwrap_or_else(|_| fail("bad signing seed")));
        (key_id(k.verifying_key().as_bytes()), k)
    });
    let jack = a.one("jack-seed-hex").map(|s| {
        let k = SigningKey::from_bytes(&hex_decode_32(s).unwrap_or_else(|_| fail("bad jack seed")));
        (key_id(k.verifying_key().as_bytes()), k)
    });
    let messages = a
        .one("messages")
        .unwrap_or("event")
        .split(',')
        .collect::<Vec<_>>();
    if messages
        .iter()
        .any(|k| k.trim().is_empty() || !["event", "gap", "terminated", "raw"].contains(k))
    {
        fail("invalid message list");
    }
    println!(
        "{}",
        serde_json::to_string(&Ready {
            ready: true,
            role: "sender",
            callback_url: &url,
            derived_subscription_id: derived.clone()
        })
        .unwrap()
    );
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    let mut results = Vec::new();
    for (i, k) in messages.iter().enumerate() {
        let m = OutgoingMessage {
            principal: "alice".into(),
            url: url.clone(),
            subscription_id: sub.clone(),
            kind: kind(k),
            body: body(k, &a),
            secrets: vec![secret.clone()],
            signing_keys: sign.clone().into_iter().collect(),
            aud: Some(aud.clone()),
            jack_signing: jack.clone(),
            expires_at_ms: Some(clock(&cp).saturating_add(3600) * 1000),
        };
        let pre = check_url(&url).ok().and_then(|u| {
            map.get(&u.host_value.to_ascii_lowercase())
                .and_then(|answers| {
                    let first = answers.iter().map(ToString::to_string).collect::<Vec<_>>();
                    let second = a
                        .one("rebind-address")
                        .map(|x| vec![x.into()])
                        .unwrap_or_else(|| first.clone());
                    match delivery_decision(&DeliveryInput {
                        url: &url,
                        answers: &first,
                        recheck: &second,
                        allowed_ranges: &a.all("allowed-range"),
                        redirect_status: None,
                    }) {
                        DeliveryDecision::Reject {
                            code: "blocked_address",
                            ..
                        } => Some("ssrf_blocked_address"),
                        DeliveryDecision::Reject {
                            code: "dns_rebinding",
                            ..
                        } => Some("ssrf_rebinding_blocked"),
                        _ => None,
                    }
                })
        });
        capture.ids.lock().unwrap().clear();
        let out = sender.deliver(&m);
        let observed = capture
            .ids
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_else(|| {
                // This valid SDK-generated fallback fills the required field but is not claimed on wire.
                webhook::subscription::random_webhook_id(kind(k)).unwrap_or_else(|e| fail(e))
            });
        let (last, attempts) = if let Some(e) = pre {
            (Some(e.to_owned()), 0)
        } else {
            (
                match out.action {
                    SendAction::Accepted => None,
                    SendAction::Final { last_error } | SendAction::Abandoned { last_error } => {
                        Some(last_error.as_str().to_owned())
                    }
                },
                out.attempts,
            )
        };
        results.push(Item {
            message: i,
            kind: (*k).into(),
            webhook_id: observed,
            attempts,
            accepted: matches!(out.action, SendAction::Accepted),
            http_status: out.last_status,
            last_error: last,
        })
    }
    println!(
        "{}",
        serde_json::to_string(&ResultLine {
            event: "result",
            scenario: &scenario,
            role: "sender",
            callback_url: &url,
            derived_subscription_id: derived,
            results
        })
        .unwrap()
    )
}
pub fn mode_from_args() -> Option<String> {
    let mut i = std::env::args().skip(1);
    let mut selected: Option<String> = None;
    while let Some(x) = i.next() {
        let value = if let Some(v) = x.strip_prefix("--mode=") {
            Some(v.to_owned())
        } else if x == "--mode" {
            i.next()
        } else {
            None
        };
        if let Some(value) = value {
            if selected.as_ref().is_some_and(|previous| previous != &value) {
                return None;
            }
            selected = Some(value);
        }
    }
    selected
}
pub fn run_mode() {
    run()
}
