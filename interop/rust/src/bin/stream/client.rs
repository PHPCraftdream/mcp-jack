use super::*;
use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};

const MAX_HEAD: usize = 32 * 1024;
const MAX_EVENT: usize = 1024 * 1024;

pub fn run() -> ! {
    let mut request_sig = None;
    if let Err(_e) = run_inner(&mut request_sig) {
        let a = args();
        let scenario = flag(&a, "--scenario").unwrap_or_default();
        emit(
            &serde_json::json!({"type":"terminal","scenario":scenario,"outcome":"error","code":"client_error","http_status":null,"http_code":null,"frames_verified":0,"request_id":null,"mcp_complete":false,"terminal_frame":null,"request_sig":request_sig,"v1_evidence":null,"open":null,"frames":[],"failure_frame":null,"successor_activation":null}),
        );
    }
    std::process::exit(0)
}

fn run_inner(request_sig_out: &mut Option<String>) -> Result<(), String> {
    let a = args();
    let get = |k: &str| flag(&a, k).ok_or_else(|| format!("missing {k}"));
    let scenario = get("--scenario")?;
    let _profile = get("--profile")?;
    let matrix = get("--matrix")?;
    if matrix.is_empty() {
        return Err("empty --matrix".into());
    }
    let idle_timeout_ms = flag(&a, "--idle-timeout-ms")
        .unwrap_or_else(|| "90000".into())
        .parse::<u64>()
        .map_err(|_| "invalid --idle-timeout-ms")?;
    let frame_max_bytes = flag(&a, "--frame-max-bytes")
        .unwrap_or_else(|| "1048576".into())
        .parse::<usize>()
        .map_err(|_| "invalid --frame-max-bytes")?;
    let max_stream_duration_ms = flag(&a, "--max-stream-duration-ms")
        .unwrap_or_else(|| "3600000".into())
        .parse::<u64>()
        .map_err(|_| "invalid --max-stream-duration-ms")?;
    let request_log = Some(get("--request-log")?);
    let _sid = get("--sid")?;
    let _modern_version = get("--modern-version")?;
    let body = get("--request-body-json")?.into_bytes();
    let url = get("--url")?;
    let ts = read_clock(&get("--clock-file")?)?;
    let seed =
        crate::interop::hex_decode_32(&get("--seed-hex")?).map_err(|_| "invalid --seed-hex")?;
    let signer =
        mcp_jack::client::signer::InMemorySigner::from_seed(&seed).map_err(|e| e.to_string())?;
    let nonce = get("--nonce")?;
    let nonce_bytes =
        mcp_jack::encoding::decode_b64url_fixed(&nonce, 16).map_err(|e| e.to_string())?;
    let signed = mcp_jack::client::sign_request(
        &signer,
        &get("--aud")?,
        "POST",
        "/mcp",
        &body,
        &nonce_bytes,
        ts,
    )
    .map_err(|e| e.to_string())?;
    let request_sig = b64(&signed.signature);
    *request_sig_out = Some(request_sig.clone());
    let mirrors: Vec<(String, String)> = serde_json::from_str(&get("--mirror-headers-json")?)
        .map_err(|e| format!("invalid mirror headers: {e}"))?;
    let mut headers = vec![
        ("content-type".to_owned(), "application/json".to_owned()),
        ("content-length".to_owned(), body.len().to_string()),
        ("Jack-Auth".to_owned(), signed.header_value),
    ];
    headers.extend(mirrors);
    let accept = get("--jack-accept")?;
    if !accept.is_empty() {
        headers.push(("Jack-Accept".into(), accept));
    }
    let request: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    let request_id = request
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let evidence = serde_json::json!({"scenario":scenario,"request_sig":request_sig,"request_ts":ts,"nonce":nonce,"request_method":"POST","request_target":"/mcp","request_body_b64u":b64(&body),"request_headers":headers.iter().map(|(k,v)| serde_json::json!([k,v])).collect::<Vec<_>>()});
    let (host, port) = parse_origin(&url)?;
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or("URL has no address")?;
    let mut sock =
        TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_secs(90)))
        .map_err(|e| e.to_string())?;
    sock.set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut wire = format!("POST /mcp HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n");
    for (k, v) in &headers {
        wire.push_str(k);
        wire.push_str(": ");
        wire.push_str(v);
        wire.push_str("\r\n");
    }
    wire.push_str("\r\n");
    sock.write_all(wire.as_bytes())
        .and_then(|_| sock.write_all(&body))
        .map_err(|e| format!("request write: {e}"))?;
    let (status, rh, response_headers, mut reader) = read_head(sock)?;
    let pkbytes = mcp_jack::encoding::decode_b64url_fixed(&get("--server-public-key")?, 32)
        .map_err(|e| e.to_string())?;
    let pk: [u8; 32] = pkbytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid server key")?;
    let is_sse = status == 200
        && response_headers
            .get("content-type")
            .is_some_and(|v| v.to_ascii_lowercase().starts_with("text/event-stream"));
    if !is_sse {
        let payload = read_body_bounded(&mut reader, &response_headers, 2 * 1024 * 1024)?;
        let parsed: serde_json::Value =
            serde_json::from_slice(&payload).unwrap_or(serde_json::Value::Null);
        let actual = parsed
            .pointer("/error/code")
            .and_then(|x| x.as_str())
            .unwrap_or("http_error");
        let auth = response_headers
            .get("jack-auth")
            .cloned()
            .unwrap_or_default();
        let has_auth = response_headers.contains_key("jack-auth");
        let now = read_clock(&get("--clock-file")?).unwrap_or(0);
        let valid = mcp_jack::signing::verify_response(
            &pk,
            status as i64,
            &[auth.as_str()],
            &request_sig,
            &payload,
            now,
            0,
        )
        .is_ok();
        let signed_refusal = valid
            && ((status == 501 && actual == "streaming_unsupported")
                || (status == 429 && actual == "stream_limit_exceeded"));
        let unsigned_replay = status == 401 && !has_auth && actual == "replayed_nonce";
        if !signed_refusal && !unsigned_replay {
            return Err("unclassified HTTP response".into());
        }
        let v1 = if signed_refusal {
            response_auth_evidence(status, &auth, &request_sig, &payload)
        } else {
            serde_json::Value::Null
        };
        let mut terminal = serde_json::json!({"type":"terminal","scenario":scenario,"outcome":"refused","code":actual,"http_status":status,"http_code":actual,"frames_verified":0,"request_id":request_id,"mcp_complete":false,"terminal_frame":null,"request_sig":request_sig,"v1_evidence":v1,"open":null,"frames":[],"failure_frame":null,"successor_activation":null});
        if unsigned_replay {
            terminal["code"] = serde_json::json!("replayed_nonce");
            terminal["http_code"] = serde_json::json!("replayed_nonce");
            terminal["http_body_b64u"] = serde_json::json!(b64(&payload));
        }
        emit(&terminal);
        return Ok(());
    }
    let clock_path = get("--clock-file")?;
    let now_path = clock_path.clone();
    let mut cfg =
        StreamVerifierConfig::pinned(mcp_jack::encoding::key_id(&pk), pk, request_sig.clone());
    cfg.now = Arc::new(move || read_clock(&now_path).unwrap_or(0));
    cfg.frame_max_bytes = frame_max_bytes;
    cfg.stream_idle_ms = idle_timeout_ms.min(i64::MAX as u64) as i64;
    let mut verifier = StreamVerifier::new(cfg);
    let open = match verifier.open(status, &rh) {
        Ok(open) => open.clone(),
        Err(e) => {
            emit(
                &serde_json::json!({"type":"terminal","scenario":scenario,"outcome":"error","code":code(e.code),"http_status":status,"http_code":null,"frames_verified":0,"request_id":request_id,"mcp_complete":false,"terminal_frame":null,"request_sig":request_sig,"v1_evidence":null,"open":null,"frames":[],"failure_frame":null,"successor_activation":null}),
            );
            return Ok(());
        }
    };
    let open_json = serde_json::json!({"sid":open.sid,"kid":open.kid,"ts":open.ts,"sig":open.sig});
    let mut sse = mcp_jack::stream::SseReader::with_max_pending_bytes(
        frame_max_bytes.saturating_add(16 * 1024),
    );
    let mut frames = Vec::<mcp_jack::stream::JackFrame>::new();
    let mut delivered = 0usize;
    let mut last_message = serde_json::Value::Null;
    let mut failure_frame = serde_json::Value::Null;
    let mut terminal: Option<mcp_jack::stream::StreamFailure> = None;
    let cancel = flag(&a, "--action").unwrap_or_else(|| scenario.clone()) == "cancel";
    let opened_at = Instant::now();
    let loop_deadline_ms = max_stream_duration_ms
        .saturating_add(5_000)
        .min(idle_timeout_ms)
        .clamp(1, 90_000);
    let deadline = opened_at + Duration::from_millis(loop_deadline_ms);
    let mut chunk = [0u8; 8192];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            terminal = Some(mcp_jack::stream::StreamFailure::new(
                mcp_jack::stream::StreamCode::Truncated,
                verifier.frames_verified(),
            ));
            break;
        }
        if reader.sock.set_read_timeout(Some(remaining)).is_err() {
            terminal = Some(mcp_jack::stream::StreamFailure::new(
                mcp_jack::stream::StreamCode::Truncated,
                verifier.frames_verified(),
            ));
            break;
        }
        let n = match reader.read_body(&mut chunk, &response_headers) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => {
                terminal = Some(mcp_jack::stream::StreamFailure::new(
                    mcp_jack::stream::StreamCode::Truncated,
                    verifier.frames_verified(),
                ));
                let _ = e;
                break;
            }
        };
        if n == 0 {
            break;
        }
        let before = verifier.frames_verified();
        let arrived_at_ms = opened_at.elapsed().as_millis().min(i64::MAX as u128) as i64;
        let events = sse.push(&chunk[..n], arrived_at_ms);
        let step = verifier.push(&chunk[..n], arrived_at_ms);
        terminal = step.terminal;
        let verified = verifier.frames_verified().saturating_sub(before);
        if terminal.is_some_and(|f| {
            matches!(
                f.code,
                mcp_jack::stream::StreamCode::OutOfOrder
                    | mcp_jack::stream::StreamCode::BadSignature
            )
        }) {
            if let Some(ev) = events.get(verified) {
                if let Ok(f) = mcp_jack::stream::parse_frame(&ev.lines) {
                    failure_frame = frame_json(&f, &open);
                }
            }
        }
        for ev in events.into_iter().take(verified) {
            if let Ok(f) = mcp_jack::stream::parse_frame(&ev.lines) {
                frames.push(f);
            }
        }
        for data in step.messages {
            let message: serde_json::Value =
                serde_json::from_str(&data).unwrap_or(serde_json::Value::Null);
            last_message = message.clone();
            let matching = frames.iter().position(|f| f.data == data);
            let prefix_len = matching.map(|index| index + 1).unwrap_or(frames.len());
            let mut row = evidence.clone();
            row["type"] = "message".into();
            row["stream_index"] = delivered.into();
            row["data"] = data.clone().into();
            row["message"] = message;
            row["open"] = open_json.clone();
            row["frames"] = serde_json::Value::Array(
                frames
                    .iter()
                    .take(prefix_len)
                    .map(|f| frame_json(f, &open))
                    .collect(),
            );
            emit(&row);
            delivered += 1;
            if cancel {
                let _ = reader.sock.shutdown(std::net::Shutdown::Both);
                terminal = None;
                break;
            }
        }
        if cancel && delivered > 0 {
            break;
        }
        if terminal.is_some() {
            break;
        }
        if sse.too_large() {
            terminal = Some(mcp_jack::stream::StreamFailure::new(
                mcp_jack::stream::StreamCode::FrameTooLarge,
                verifier.frames_verified(),
            ));
            break;
        }
    }
    if (!cancel || delivered == 0) && terminal.is_none() {
        let step = verifier.finish(None);
        terminal = step.terminal;
    }
    let fs: Vec<_> = frames.iter().map(|f| frame_json(f, &open)).collect();
    let end = frames
        .last()
        .filter(|f| f.kind == mcp_jack::stream::FrameKind::End);
    let complete = end.is_some()
        && request_id != serde_json::Value::Null
        && delivered > 0
        && last_message.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0")
        && last_message.get("id") == Some(&request_id)
        && (last_message.get("result").is_some() ^ last_message.get("error").is_some())
        && last_message.get("method").is_none();
    if cancel && delivered > 0 {
        wait_cancel_log(request_log.as_deref(), &request_sig);
    }
    let outcome = if cancel && delivered > 0 {
        "cancelled"
    } else if terminal.is_none() {
        "complete"
    } else {
        "error"
    };
    let row = serde_json::json!({"type":"terminal","scenario":scenario,"outcome":outcome,"code":if cancel && delivered > 0 { serde_json::Value::Null } else { terminal.map(|f| serde_json::json!(code(f.code))).unwrap_or(serde_json::Value::Null) },"http_status":status,"http_code":null,"frames_verified":verifier.frames_verified(),"request_id":request_id,"mcp_complete":complete,"terminal_frame":end.map(|f| serde_json::json!({"kind":"end","sig":f.sig})),"request_sig":request_sig,"v1_evidence":null,"open":open_json,"frames":fs,"failure_frame":failure_frame,"successor_activation":null});
    emit(&row);
    Ok(())
}

fn wait_cancel_log(path: Option<&str>, request_sig: &str) {
    let Some(path) = path else {
        return;
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let rows: Vec<serde_json::Value> = contents
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect();
            let found = rows.iter().any(|row| {
                row.get("event").and_then(|v| v.as_str()) == Some("handler_cancelled")
                    && row.get("request_sig").and_then(|v| v.as_str()) == Some(request_sig)
            });
            if found {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn parse_origin(url: &str) -> Result<(String, u16), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("only http:// origins are supported")?;
    if rest.contains('/') || rest.contains('?') || rest.contains('#') {
        return Err("--url must be a bare origin".into());
    }
    let (host, port) = rest
        .rsplit_once(':')
        .ok_or("origin requires an explicit port")?;
    let port = port.parse::<u16>().map_err(|_| "invalid URL port")?;
    if host.is_empty() {
        return Err("empty URL host".into());
    }
    Ok((host.to_owned(), port))
}
type ResponseHeaders = std::collections::HashMap<String, String>;
type ResponseHead = (u16, Vec<(String, String)>, ResponseHeaders, BodyReader);

fn read_head(mut sock: TcpStream) -> Result<ResponseHead, String> {
    let mut bytes = Vec::new();
    let mut b = [0u8; 2048];
    let end = loop {
        if bytes.len() > MAX_HEAD {
            return Err("HTTP response head too large".into());
        }
        let n = sock.read(&mut b).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("incomplete HTTP response head".into());
        }
        bytes.extend_from_slice(&b[..n]);
        if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = std::str::from_utf8(&bytes[..end]).map_err(|_| "invalid HTTP response head")?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|x| x.split_whitespace().nth(1))
        .and_then(|x| x.parse().ok())
        .ok_or("invalid HTTP status")?;
    let mut hs = Vec::new();
    let mut map = std::collections::HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let value = v.trim().to_owned();
            hs.push((k.trim().to_owned(), value.clone()));
            map.insert(key, value);
        }
    }
    Ok((
        status,
        hs,
        map,
        BodyReader {
            sock,
            pending: bytes[end..].to_vec(),
            chunked: false,
            remaining: None,
            done: false,
        },
    ))
}
struct BodyReader {
    sock: TcpStream,
    pending: Vec<u8>,
    chunked: bool,
    remaining: Option<usize>,
    done: bool,
}
impl BodyReader {
    fn fill(&mut self) -> std::io::Result<bool> {
        let mut b = [0; 8192];
        let n = self.sock.read(&mut b)?;
        if n == 0 {
            return Ok(false);
        }
        self.pending.extend_from_slice(&b[..n]);
        Ok(true)
    }
    fn read_body(&mut self, out: &mut [u8], headers: &ResponseHeaders) -> std::io::Result<usize> {
        if self.done {
            return Ok(0);
        }
        if headers
            .get("transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
        {
            self.chunked = true;
            loop {
                if let Some(n) = self.remaining {
                    if n == 0 {
                        while self.pending.len() < 2 {
                            if !self.fill()? {
                                self.done = true;
                                return Ok(0);
                            }
                        }
                        if self.pending.get(..2) != Some(b"\r\n") {
                            self.done = true;
                            return Ok(0);
                        }
                        self.pending.drain(..2);
                        self.remaining = None;
                        continue;
                    }
                    while self.pending.is_empty() {
                        if !self.fill()? {
                            self.done = true;
                            return Ok(0);
                        }
                    }
                    let take = n.min(out.len()).min(self.pending.len());
                    out[..take].copy_from_slice(&self.pending[..take]);
                    self.pending.drain(..take);
                    self.remaining = Some(n - take);
                    return Ok(take);
                }
                loop {
                    if let Some(i) = self.pending.windows(2).position(|x| x == b"\r\n") {
                        let line = String::from_utf8_lossy(&self.pending[..i]);
                        let size = usize::from_str_radix(line.split(';').next().unwrap_or(""), 16)
                            .map_err(|_| {
                                std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "invalid chunk size",
                                )
                            })?;
                        self.pending.drain(..i + 2);
                        if size == 0 {
                            self.done = true;
                            return Ok(0);
                        } else {
                            self.remaining = Some(size);
                            break;
                        }
                    } else if self.pending.len() > 128 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "chunk header too large",
                        ));
                    } else if !self.fill()? {
                        self.done = true;
                        return Ok(0);
                    }
                }
            }
        }
        if let Some(n) = headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
        {
            if n == 0 {
                self.done = true;
                return Ok(0);
            }
            while self.pending.is_empty() {
                if !self.fill()? {
                    self.done = true;
                    return Ok(0);
                }
            }
            let take = n.min(out.len()).min(self.pending.len());
            out[..take].copy_from_slice(&self.pending[..take]);
            self.pending.drain(..take);
            return Ok(take);
        }
        while self.pending.is_empty() {
            if !self.fill()? {
                self.done = true;
                return Ok(0);
            }
        }
        let take = out.len().min(self.pending.len());
        out[..take].copy_from_slice(&self.pending[..take]);
        self.pending.drain(..take);
        Ok(take)
    }
}
fn read_body_bounded(
    reader: &mut BodyReader,
    headers: &std::collections::HashMap<String, String>,
    max: usize,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        let n = reader
            .read_body(&mut buffer, headers)
            .map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        } else if out.len().saturating_add(n) > max {
            return Err("HTTP body too large".into());
        } else {
            out.extend_from_slice(&buffer[..n]);
        }
    }
    Ok(out)
}
fn frame_json(
    f: &mcp_jack::stream::JackFrame,
    o: &mcp_jack::stream::OpenAuth,
) -> serde_json::Value {
    serde_json::json!({"kind":if f.kind==mcp_jack::stream::FrameKind::End{"end"}else{"message"},"sid":o.sid,"kid":o.kid,"seq":f.seq,"ts":f.ts,"data":f.data,"sig":f.sig})
}
fn response_auth_evidence(
    status: u16,
    auth: &str,
    request_sig: &str,
    body: &[u8],
) -> serde_json::Value {
    let mut kid = "";
    let mut ts = "";
    let mut sig = "";
    for p in auth.split(',') {
        let p = p.trim();
        if let Some(v) = p.strip_prefix("v1 kid=") {
            kid = v
        } else if let Some(v) = p.strip_prefix("ts=") {
            ts = v
        } else if let Some(v) = p.strip_prefix("sig=") {
            sig = v
        }
    }
    serde_json::json!({"status":status,"ts":ts.parse::<i64>().unwrap_or(0),"kid":kid,"request_sig":request_sig,"body_b64u":b64(body),"sig":sig})
}
