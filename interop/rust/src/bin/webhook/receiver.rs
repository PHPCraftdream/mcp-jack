//! HTTPS receiver interop mode; all delivery decisions are made by the SDK Receiver.
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use mcp_jack::{
    encoding::encode_b64url,
    webhook::{
        self,
        card::{fetch_decision, CardFetchInput},
        receiver::{JackConfig, Receiver, ReceiverConfig, ReceiverSecret},
    },
};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
fn usage(s: impl std::fmt::Display) -> ! {
    eprintln!("interop-server: {s}");
    std::process::exit(2)
}
fn fail(s: impl std::fmt::Display) -> ! {
    eprintln!("interop-server: {s}");
    std::process::exit(1)
}
#[derive(Default)]
struct Args(BTreeMap<String, Vec<String>>);
impl Args {
    fn parse() -> Self {
        const VALUES: &[&str] = &[
            "port",
            "tls-cert",
            "tls-key",
            "clock-file",
            "secret-seed",
            "subscription-id",
            "callback-url",
            "aud",
            "card-file",
            "card-mcp-url",
            "mcp-server-kid",
            "enqueue-fail",
        ];
        const FLAGS: &[&str] = &["pending-secret", "require-jack", "enforce-server-identity"];
        let mut a = Self::default();
        let mut i = std::env::args().skip(2);
        while let Some(x) = i.next() {
            let Some(x) = x.strip_prefix("--") else {
                usage("unexpected positional argument")
            };
            let (k, inline) = x
                .split_once('=')
                .map(|(k, v)| (k, Some(v)))
                .unwrap_or((x, None));
            if FLAGS.contains(&k) {
                if inline.is_some() {
                    usage(format!("--{k} does not take a value"))
                }
                a.0.entry(k.to_owned()).or_default();
            } else if VALUES.contains(&k) {
                let value = match inline {
                    Some(value) if !value.is_empty() => value.to_owned(),
                    Some(_) => usage(format!("missing --{k} value")),
                    None => match i.next() {
                        Some(value) if !value.starts_with('-') => value,
                        _ => usage(format!("missing --{k} value")),
                    },
                };
                a.0.entry(k.to_owned()).or_default().push(value);
            } else {
                usage(format!("unknown option --{k}"))
            }
        }
        a
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.0.get(k).and_then(|v| v.last()).map(String::as_str)
    }
    fn req(&self, k: &str) -> String {
        self.get(k)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| usage(format!("--{k} required")))
            .to_owned()
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
fn pem(t: &str, l: &str) -> Vec<u8> {
    let b = format!("-----BEGIN {l}-----");
    let e = format!("-----END {l}-----");
    let x = t
        .split(&b)
        .nth(1)
        .and_then(|s| s.split(&e).next())
        .unwrap_or_else(|| fail("invalid TLS PEM"));
    base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        x.split_whitespace().collect::<String>(),
    )
    .unwrap_or_else(|_| fail("invalid TLS PEM"))
}
#[derive(Serialize)]
struct Ready {
    ready: bool,
    role: &'static str,
    port: u16,
    subscription_id: String,
    subscription_known: bool,
}
#[derive(Serialize)]
struct Line {
    event: &'static str,
    seq: usize,
    status: u16,
    code: Option<String>,
    body_status: Option<String>,
    kind: Option<String>,
    webhook_id: String,
    subscription_id: String,
    webhook_timestamp: String,
    challenge: Option<String>,
    enqueued: usize,
    forwarded: Vec<String>,
    headers: Vec<(String, String)>,
    body_b64u: String,
}
fn header(h: &[(String, String)], n: &str) -> String {
    h.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(n))
        .map(|x| x.1.clone())
        .unwrap_or_default()
}
fn response(status: u16, body: Vec<u8>, auth: bool) -> Response<Full<Bytes>> {
    let len = body.len();
    let mut r = Response::new(Full::new(Bytes::from(body)));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    r.headers_mut().insert(
        http::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    r.headers_mut().insert(
        http::header::CONTENT_LENGTH,
        len.to_string().parse().unwrap(),
    );
    r.headers_mut()
        .insert(http::header::CONNECTION, "close".parse().unwrap());
    if auth {
        r.headers_mut().insert(
            http::header::WWW_AUTHENTICATE,
            "Webhook-Signature".parse().unwrap(),
        );
    }
    r
}
#[allow(clippy::too_many_arguments)]
async fn serve(
    req: Request<hyper::body::Incoming>,
    receiver: Arc<Receiver>,
    cp: String,
    _sub: String,
    path: String,
    seq: Arc<AtomicUsize>,
    failures: Arc<AtomicUsize>,
    enqueued: Arc<AtomicUsize>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    if req.method() != http::Method::POST || req.uri().path() != path {
        return Ok(response(
            404,
            br#"{"error":{"code":"no_route","message":"not a delivery endpoint"}}"#.to_vec(),
            false,
        ));
    }
    let n = seq.fetch_add(1, Ordering::SeqCst);
    let (parts, body) = req.into_parts();
    let headers = parts
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_owned()))
        .collect::<Vec<_>>();
    let declared = parts
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u128>().ok());
    let mut raw = Vec::new();
    if !declared.is_some_and(|n| n > 262144) {
        let mut body = body;
        while let Some(frame) = body.frame().await {
            if let Ok(frame) = frame {
                if let Ok(data) = frame.into_data() {
                    let remaining = 262145usize.saturating_sub(raw.len());
                    raw.extend_from_slice(&data[..data.len().min(remaining)]);
                    if raw.len() > 262144 {
                        break;
                    }
                }
            }
        }
    }
    let forwarded = Arc::new(std::sync::Mutex::new(Vec::new()));
    let callback_messages = Arc::clone(&forwarded);
    let dispatched_kinds = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let callback_kinds = Arc::clone(&dispatched_kinds);
    let f = failures.clone();
    let e = enqueued.clone();
    let outcome = receiver.handle(clock(&cp), &headers, &raw, move |messages| {
        *callback_kinds.lock().unwrap() = messages
            .iter()
            .map(|message| {
                message
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("event")
                    .to_owned()
            })
            .collect();
        if f.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
            .is_ok()
        {
            return Err(webhook::WebhookError::new(
                503,
                "enqueue_failed",
                "durable enqueue failed",
            ));
        }
        let canonical = messages
            .iter()
            .map(webhook::subscription::canonical_json)
            .collect::<Result<Vec<_>, _>>()?;
        *callback_messages.lock().unwrap() = canonical
            .iter()
            .map(|value| encode_b64url(value.as_bytes()))
            .collect();
        e.fetch_add(messages.len(), Ordering::SeqCst);
        Ok(())
    });
    let body_bytes = serde_json::to_vec(&outcome.body).unwrap();
    let status = outcome.status;
    let answer = outcome.body;
    let forwarded = std::mem::take(&mut *forwarded.lock().unwrap());
    let dispatched_kind = std::mem::take(&mut *dispatched_kinds.lock().unwrap())
        .into_iter()
        .next();
    let line = Line {
        event: "delivery",
        seq: n,
        status,
        code: outcome.code,
        body_status: answer
            .get("status")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                answer
                    .get("challenge")
                    .is_some()
                    .then(|| "challenge".into())
            }),
        kind: dispatched_kind.or_else(|| {
            answer
                .get("challenge")
                .is_some()
                .then(|| "verification".to_owned())
        }),
        webhook_id: header(&headers, "webhook-id"),
        subscription_id: header(&headers, "x-mcp-subscription-id"),
        webhook_timestamp: header(&headers, "webhook-timestamp"),
        challenge: answer
            .get("challenge")
            .and_then(Value::as_str)
            .map(str::to_owned),
        enqueued: enqueued.load(Ordering::SeqCst),
        forwarded,
        headers,
        body_b64u: encode_b64url(&raw),
    };
    println!("{}", serde_json::to_string(&line).unwrap());
    Ok(response(status, body_bytes, status == 401))
}
fn run() {
    let a = Args::parse();
    let port = a
        .req("port")
        .parse::<u16>()
        .unwrap_or_else(|_| fail("invalid port"));
    let text =
        fs::read_to_string(a.req("tls-cert")).unwrap_or_else(|e| fail(format!("TLS cert: {e}")));
    let certs = text
        .split("-----BEGIN CERTIFICATE-----")
        .skip(1)
        .filter_map(|s| s.split("-----END CERTIFICATE-----").next())
        .map(|s| {
            tokio_rustls::rustls::pki_types::CertificateDer::from(pem(
                &format!("-----BEGIN CERTIFICATE-----{s}-----END CERTIFICATE-----"),
                "CERTIFICATE",
            ))
        })
        .collect::<Vec<_>>();
    if certs.is_empty() {
        fail("no certificates")
    };
    let kt = fs::read_to_string(a.req("tls-key")).unwrap_or_else(|e| fail(format!("TLS key: {e}")));
    let key = ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"]
        .iter()
        .find_map(|l| {
            kt.contains(&format!("-----BEGIN {l}-----"))
                .then(|| pem(&kt, l))
        })
        .unwrap_or_else(|| fail("invalid TLS key"));
    let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::try_from(key)
        .unwrap_or_else(|_| fail("invalid TLS key"));
    let mut tls = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap_or_else(|e| fail(format!("TLS: {e}")));
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = Arc::new(tls);
    let cp = a.req("clock-file");
    let sub = a.req("subscription-id");
    let callback = a.req("callback-url");
    let aud = a.req("aud");
    let pending = a.has("pending-secret");
    let secret = webhook::encoding::WebhookSecret::from_bytes(
        webhook::encoding::sha256(a.req("secret-seed").as_bytes()).to_vec(),
    );
    let mut c = ReceiverConfig::default();
    c.secrets.push(ReceiverSecret {
        secret,
        subscription_id: (!pending).then(|| sub.clone()),
        callback_url: pending.then(|| callback.clone()),
    });
    if !pending {
        c.routed.push(sub.clone())
    }
    if a.has("require-jack") {
        c.jack = Some(JackConfig {
            aud: aud.clone(),
            window: 30,
            callback_urls: BTreeMap::from([(sub.clone(), callback.clone())]),
        })
    }
    if let Some(file) = a.get("card-file") {
        let body = fs::read(file).unwrap_or_else(|e| fail(format!("card: {e}")));
        let url = a
            .get("card-mcp-url")
            .unwrap_or_else(|| fail("missing card MCP URL"));
        let kid = a.get("mcp-server-kid");
        let card = fetch_decision(&CardFetchInput {
            mcp_url: url,
            card_url: url,
            status: Some(200),
            redirect: false,
            body: &body,
            overflow: false,
            elapsed_ms: Some(0),
            cache_control: None,
            mcp_server_kid: kid,
            mcp_server_public_key: None,
        })
        .unwrap_or_else(|e| fail(format!("card: {e}")));
        c.keys = card.keys;
        if let Some(k) = kid {
            c.mcp_server_kid = Some(k.into())
        }
    }
    c.enforce_server_identity = a.has("enforce-server-identity");
    let receiver = Arc::new(Receiver::new(c).unwrap_or_else(|e| fail(format!("receiver: {e}"))));
    let known = receiver.snapshot().routed.contains(&sub);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| fail(format!("runtime: {e}")));
    let _rt_guard = rt.enter();
    let listener = std::net::TcpListener::bind(("127.0.0.1", port))
        .unwrap_or_else(|e| fail(format!("bind: {e}")));
    listener
        .set_nonblocking(true)
        .unwrap_or_else(|e| fail(format!("nonblocking: {e}")));
    let actual = listener.local_addr().unwrap().port();
    let listener = tokio::net::TcpListener::from_std(listener)
        .unwrap_or_else(|e| fail(format!("listener: {e}")));
    println!(
        "{}",
        serde_json::to_string(&Ready {
            ready: true,
            role: "receiver",
            port: actual,
            subscription_id: sub.clone(),
            subscription_known: known
        })
        .unwrap()
    );
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    let failures = Arc::new(AtomicUsize::new(
        a.get("enqueue-fail")
            .unwrap_or("0")
            .parse()
            .unwrap_or_else(|_| fail("invalid enqueue-fail")),
    ));
    let enqueued = Arc::new(AtomicUsize::new(0));
    let seq = Arc::new(AtomicUsize::new(0));
    let path = http::Uri::try_from(callback.as_str())
        .ok()
        .map(|u| u.path().to_owned())
        .unwrap_or_else(|| fail("invalid callback URL"));
    rt.block_on(async move {
        let mut tasks = tokio::task::JoinSet::new();
        let (eof_tx, mut eof_rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::BufRead::read_line(
                &mut std::io::BufReader::new(std::io::stdin()),
                &mut line,
            );
            let _ = eof_tx.send(());
        });
        let terminate = async {
            #[cfg(unix)]
            {
                let mut terminate = tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::terminate(),
                )
                .unwrap_or_else(|e| fail(format!("SIGTERM handler: {e}")));
                terminate.recv().await;
            }
            #[cfg(not(unix))]
            std::future::pending::<()>().await;
        };
        tokio::pin!(terminate);
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = &mut eof_rx => break,
                _ = &mut terminate => break,
                accepted = listener.accept() => {
                    let (stream, _) = match accepted {
                        Ok(value) => value,
                        Err(error) => fail(format!("accept: {error}")),
                    };
                    while tasks.try_join_next().is_some() {}
                    if tasks.len() >= 64 {
                        drop(stream);
                        continue;
                    }
                    let (receiver, cp, sub, path, seq, failures, enqueued, tls) = (
                        receiver.clone(), cp.clone(), sub.clone(), path.clone(), seq.clone(),
                        failures.clone(), enqueued.clone(), tls.clone(),
                    );
                    tasks.spawn(async move {
                        if let Ok(stream) = tokio_rustls::TlsAcceptor::from(tls).accept(stream).await {
                            let service = hyper::service::service_fn(move |req| {
                                serve(req, receiver.clone(), cp.clone(), sub.clone(), path.clone(),
                                    seq.clone(), failures.clone(), enqueued.clone())
                            });
                            let io = hyper_util::rt::TokioIo::new(stream);
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, service).await;
                        }
                    });
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    })
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
