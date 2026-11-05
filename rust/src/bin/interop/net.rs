//! Minimal blocking HTTP/1.1 client transport for the interop client, built
//! directly on std::net::TcpStream (no HTTP crate: keeping the interop
//! feature's dependency graph within the crate's 1.85 MSRV). Design doc
//! interop.md section 8: blocking, small, no async runtime.

use std::io::{BufRead, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::Duration;

use mcp_jack::client::transport::{
    HttpRequest, HttpResponse, Transport, TransportError, MAX_BODY_BYTES,
};

/// Mirrors Go's 15 s http.Client timeout: applied to connect, read and write.
const TIMEOUT: Duration = Duration::from_secs(15);

/// Cap on the total response head (status line + headers), so a hostile peer
/// cannot exhaust memory before the body cap applies.
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Cap for a single header or chunk-size line.
const MAX_LINE: usize = 16 * 1024;

/// Cap for the assembled body; the +1 headroom mirrors the SDK's
/// MAX_BODY_BYTES+1 limit-reader so oversize is detectable.
const MAX_BUDGET: usize = MAX_BODY_BYTES + 1;

/// The blocking HTTP transport of interop-client (Go: the 15 s http.Client).
pub struct TcpTransport {
    /// The last completed wire response, kept so the scenario layer can read
    /// the unsigned 401 body code the SDK deliberately never parses.
    last: Mutex<Option<HttpResponse>>,
}

impl TcpTransport {
    pub fn new() -> Self {
        Self {
            last: Mutex::new(None),
        }
    }

    /// Stashes a completed response for unauth_result's last_response peek.
    fn stash(&self, resp: &HttpResponse) {
        let mut slot = self.last.lock().unwrap_or_else(|p| p.into_inner());
        *slot = Some(resp.clone());
    }

    /// The most recent completed wire response (clone out; recover from a
    /// poisoned mutex like the SDK does).
    pub fn last_response(&self) -> Option<HttpResponse> {
        self.last.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self::new()
    }
}

/// Rejects characters that would let a URL inject into the request line or
/// the Host header.
fn has_injectable_chars(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7f || b == b' ')
}

/// Splits an `http://` URL into (host_header, addr, path). Only plain http is
/// accepted — the client only ever addresses the local interop-server. All
/// failures map to a short Err reason.
fn split_url(url: &str) -> Result<(String, SocketAddr, String), String> {
    let Some(rest) = url.strip_prefix("http://") else {
        return Err("url: only http:// is supported".into());
    };
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return Err("url: empty host".into());
    }
    if has_injectable_chars(authority) || has_injectable_chars(&path) {
        return Err("url: control character or space in authority/path".into());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>().map_err(|_| "url: bad port".to_string())?,
        ),
        None => (authority, 80),
    };
    if host.is_empty() {
        return Err("url: empty host".into());
    }
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("url: resolve: {e}"))?
        .next()
        .ok_or_else(|| "url: resolve returned no address".to_string())?;
    // Host header value: host only on the default port, host:port otherwise.
    let host_header = if port == 80 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    Ok((host_header, addr, path))
}

/// Validates a caller-supplied header name/value: no CR/LF/NUL (defense
/// against header injection even though the values are self-produced).
fn valid_header(name: &str, value: &str) -> bool {
    let bad = |s: &str| s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0);
    !name.is_empty() && !bad(name) && !bad(value)
}

/// Validates the request method: non-empty, no control chars or spaces (the
/// request line must stay injection-free).
fn valid_method(method: &str) -> bool {
    !method.is_empty() && method.bytes().all(|b| b > 0x20 && b != 0x7f)
}

/// Serializes the request wire bytes: request line, Host, Connection: close,
/// caller headers in order, Content-Length only for a non-empty body, then
/// the body (so a GET sends no Content-Length, like Go's net/http).
fn build_request(
    method: &str,
    host_header: &str,
    path: &str,
    extra_headers: &[(&str, String)],
    body: &[u8],
) -> Result<Vec<u8>, String> {
    if !valid_method(method) {
        return Err("request: invalid method".into());
    }
    let mut head =
        format!("{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n");
    for (name, value) in extra_headers {
        if !valid_header(name, value) {
            return Err(format!("request: invalid header {name}"));
        }
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty() {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    Ok(out)
}

/// Reads one `\n`-terminated line, capped at MAX_LINE. A line that ends
/// without `\n` (cap hit) is an error.
fn read_line_capped(reader: &mut impl BufRead, line: &mut Vec<u8>) -> Result<(), String> {
    line.clear();
    let mut taken = reader.by_ref().take(MAX_LINE as u64);
    taken
        .read_until(b'\n', line)
        .map_err(|e| format!("reading response: {e}"))?;
    if line.last() != Some(&b'\n') {
        return Err("response head: line exceeds cap or stream ended mid-line".into());
    }
    Ok(())
}

/// Parses the status line: `HTTP/1.x` followed by a 3-digit code.
fn parse_status_line(line: &[u8]) -> Result<u16, String> {
    let text = std::str::from_utf8(line).map_err(|_| "status line: not UTF-8".to_string())?;
    let text = text.trim_end_matches(['\r', '\n']);
    let mut parts = text.split_whitespace();
    let version = parts.next().ok_or("status line: empty")?;
    if !version.starts_with("HTTP/1.") {
        return Err("status line: not HTTP/1.x".into());
    }
    let code = parts.next().ok_or("status line: missing code")?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err("status line: bad status code".into());
    }
    code.parse::<u16>()
        .map_err(|_| "status line: bad status code".into())
}

/// Reads the head (status line + headers) with per-line and total caps.
/// Headers keep duplicates in order (Go Header.Values parity; the SDK's
/// HttpResponse lookups are case-insensitive).
fn read_head(reader: &mut BufReader<TcpStream>) -> Result<(u16, Vec<(String, String)>), String> {
    let mut total = 0usize;
    let mut line = Vec::new();
    read_line_capped(reader.by_ref(), &mut line)?;
    total += line.len();
    let status = parse_status_line(&line)?;
    let mut headers = Vec::new();
    loop {
        read_line_capped(reader.by_ref(), &mut line)?;
        if line == b"\r\n" || line == b"\n" {
            return Ok((status, headers));
        }
        total += line.len();
        if total > MAX_HEAD_BYTES {
            return Err("response head exceeds cap".into());
        }
        let text = std::str::from_utf8(&line).map_err(|_| "header: not UTF-8".to_string())?;
        let text = text.trim_end_matches(['\r', '\n']);
        let Some((name, value)) = text.split_once(':') else {
            return Err("header: missing colon".into());
        };
        headers.push((name.to_string(), value.trim().to_string()));
    }
}

/// Case-insensitive header lookup (returns the first value).
fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Reads the body with the MAX_BODY_BYTES+1 budget: once exhausted, STOP
/// reading and return the truncated body (mirrors the Go LimitReader
/// truncation; the signing layer then fails verification naturally).
fn read_body(
    reader: &mut BufReader<TcpStream>,
    headers: &[(String, String)],
) -> Result<Vec<u8>, String> {
    let chunked = header_value(headers, "Transfer-Encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);
    let mut body = Vec::new();
    if chunked {
        let mut line = Vec::new();
        loop {
            read_line_capped(reader.by_ref(), &mut line)?;
            let text = std::str::from_utf8(&line)
                .map_err(|_| "chunk size: not UTF-8".to_string())?
                .trim_end_matches(['\r', '\n']);
            let size_hex = text.split(';').next().unwrap_or("");
            let size = usize::from_str_radix(size_hex, 16)
                .map_err(|_| "chunk size: invalid hex".to_string())?;
            if size == 0 {
                // Trailers until an empty line; an early close here is
                // tolerated because the body is already complete.
                while read_line_capped(reader.by_ref(), &mut line).is_ok() {
                    if line == b"\r\n" || line == b"\n" {
                        break;
                    }
                }
                break;
            }
            // Read in bounded slices; NEVER allocate a network-sized buffer.
            let mut remaining = size;
            while remaining > 0 {
                if body.len() >= MAX_BUDGET {
                    return Ok(body); // truncated on purpose
                }
                let take = remaining.min(16 * 1024).min(MAX_BUDGET - body.len());
                let mut chunk = vec![0u8; take];
                reader
                    .by_ref()
                    .read_exact(&mut chunk)
                    .map_err(|e| format!("reading response: {e}"))?;
                body.extend_from_slice(&chunk);
                remaining -= take;
            }
            if body.len() >= MAX_BUDGET {
                return Ok(body); // truncated on purpose
            }
            // The CRLF after each chunk payload.
            read_line_capped(reader.by_ref(), &mut line)?;
            if line != b"\r\n" && line != b"\n" {
                return Err("chunk: missing terminator".into());
            }
        }
    } else if let Some(cl) = header_value(headers, "Content-Length") {
        let n = cl
            .trim()
            .parse::<u64>()
            .map_err(|_| "content-length: invalid".to_string())?;
        // A short body (early close) is NOT an error; verification fails on
        // it naturally, matching Go.
        let _ = reader
            .by_ref()
            .take(n.min(MAX_BUDGET as u64))
            .read_to_end(&mut body)
            .map_err(|e| format!("reading response: {e}"))?;
    } else {
        // Connection: close: read until EOF.
        reader
            .by_ref()
            .take(MAX_BUDGET as u64)
            .read_to_end(&mut body)
            .map_err(|e| format!("reading response: {e}"))?;
    }
    Ok(body)
}

/// One request/response exchange over a fresh connection (Connection: close
/// means exactly one response per connection). Transport-level failures map
/// to Err(reason); the caller (round_trip / send_exact) classifies them.
fn exchange(
    method: &str,
    url: &str,
    extra_headers: &[(&str, String)],
    body: &[u8],
) -> Result<HttpResponse, String> {
    let (host_header, addr, path) = split_url(url)?;
    let wire = build_request(method, &host_header, &path, extra_headers, body)?;

    let stream =
        TcpStream::connect_timeout(&addr, TIMEOUT).map_err(|e| format!("cannot connect: {e}"))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| format!("cannot connect: {e}"))?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| format!("cannot connect: {e}"))?;
    // Write the whole request; &TcpStream implements Write.
    (&stream)
        .write_all(&wire)
        .map_err(|e| format!("writing request: {e}"))?;

    let mut reader = BufReader::new(stream);
    let (status, headers) = read_head(&mut reader)?;
    let resp_body = read_body(&mut reader, &headers)?;
    Ok(HttpResponse {
        status,
        headers,
        body: resp_body,
    })
}

impl Transport for TcpTransport {
    fn round_trip(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        // The harness never sends an empty POST — raw scenarios and typed
        // calls all have bodies; empty means the GET /sse stream probe.
        let owned: Vec<(&str, String)> = req
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.clone()))
            .collect();
        match exchange(&req.method, &req.url, &owned, &req.body) {
            Ok(out) => {
                // Stash BEFORE returning so a subsequent unauth_result sees it.
                self.stash(&out);
                Ok(out)
            }
            // Only connect/timeout/IO/parse failures reach here (4xx/5xx are
            // wire answers, not errors); connect failures carry the
            // `cannot connect: ` prefix the contract requires.
            Err(msg) => Err(TransportError::Transport(msg)),
        }
    }
}

/// The RAW path used by replay/tamper scenarios: exact pre-signed bytes with
/// an exact Jack-Auth value (mirror of Go sendWithHeader); Content-Type is
/// set only for POST. Transport errors become Err(message); the caller
/// fatals.
pub fn send_exact(
    t: &TcpTransport,
    method: &str,
    url: &str,
    jack_auth: &str,
    content_type_json: bool,
    body: &[u8],
) -> Result<HttpResponse, String> {
    let mut headers: Vec<(&str, String)> = vec![("Jack-Auth", jack_auth.to_string())];
    if content_type_json {
        headers.push(("Content-Type", "application/json".to_string()));
    }
    let out = exchange(method, url, &headers, body)?;
    t.stash(&out);
    Ok(out)
}
