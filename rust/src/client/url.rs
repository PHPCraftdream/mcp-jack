//! URL handling of the client SDK. The client library defines Transport over
//! plain structs, so URL handling is a minimal, explicit helper instead of a
//! dependency. Spec 01 section 3.1 requires the origin-form target
//! byte-for-byte (path plus ?query, no fragment, no normalisation) — a
//! substring of the configured URL string gives exactly that.
//!
//! The client URL policy (spec 01 section 1, docs/design/interop.md section 9)
//! is a pure function of the raw URL string: it only accepts or refuses.

use crate::client::error::ClientError;

const BAD_URL: &str = "jack client: base url must be an absolute http/https URL with a host";
const HTTPS_REQUIRED: &str = "jack client: https required for non-loopback host (plain http is allowed only for 127.x.y.z or [::1])";

/// Why the client URL policy refused a URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UrlRefusal {
    /// Malformed, or a form the policy never accepts (userinfo, a percent
    /// escape in the authority, backslash, bad host/port, other scheme).
    Malformed,
    /// Well-formed `http` URL whose host is not a literal loopback address.
    HttpsRequired,
}

impl UrlRefusal {
    pub(crate) fn message(self) -> &'static str {
        match self {
            UrlRefusal::Malformed => BAD_URL,
            UrlRefusal::HttpsRequired => HTTPS_REQUIRED,
        }
    }
}

impl From<UrlRefusal> for ClientError {
    fn from(r: UrlRefusal) -> Self {
        ClientError::Client(r.message().to_string())
    }
}

/// Applies the client URL policy to the raw URL string: `https` for any host
/// that passes the syntax rules, `http` only for a literal canonical
/// 127.x.y.z or `[::1]` host. Pure byte scan: no DNS, no normalisation, never
/// rewrites the URL. Refuses userinfo, percent escapes in the authority only
/// (which also refuses zone IDs; percent-encoded path/query bytes are
/// accepted untouched),
/// backslashes, bytes outside 0x21..=0x7e, and every non-canonical loopback
/// spelling (`localhost`, `127.1`, `0x7f.0.0.1`, `[::ffff:127.0.0.1]`, ...).
pub fn validate_base_url(url: &str) -> Result<(), ClientError> {
    check(url).map(|_| ()).map_err(ClientError::from)
}

/// Extracts the origin-form request target (path plus ?query, no fragment)
/// from a URL accepted by the policy, byte-for-byte as configured (spec 01
/// section 3.1). An empty path becomes "/". The policy is applied first, so a
/// refused URL never yields a target.
pub fn request_target(url: &str) -> Result<String, ClientError> {
    let remainder = check(url)?;
    // The request target is path?query with the fragment cut. An empty path
    // becomes "/"; a query-only URL becomes "/?query".
    let path_and_query = match remainder.find('#') {
        Some(i) => &remainder[..i],
        None => remainder,
    };
    Ok(match path_and_query {
        "" => "/".to_string(),
        r if r.starts_with('/') => r.to_string(),
        r => format!("/{r}"),
    })
}

/// Runs the policy; returns the text after the authority (path, query and
/// fragment, untouched) on success.
pub(crate) fn check(url: &str) -> Result<&str, UrlRefusal> {
    use UrlRefusal::{HttpsRequired, Malformed};

    // Rule 1: empty, space/controls/DEL, non-ASCII bytes, backslash anywhere.
    if url.is_empty()
        || url
            .bytes()
            .any(|b| b <= 0x20 || b == 0x7f || b >= 0x80 || b == b'\\')
    {
        return Err(Malformed);
    }
    // Rule 2: scheme http|https (ASCII case-insensitive) then "://". Every
    // byte is ASCII from here on, so byte-index slicing is char-safe.
    let Some(pos) = url.find("://") else {
        return Err(Malformed);
    };
    let scheme = &url[..pos];
    let is_https = if scheme.eq_ignore_ascii_case("https") {
        true
    } else if scheme.eq_ignore_ascii_case("http") {
        false
    } else {
        return Err(Malformed);
    };
    // Rule 3: authority up to the first '/', '?' or '#'; no userinfo, no '%'.
    let rest = &url[pos + 3..];
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    if authority.is_empty() || authority.contains(['@', '%']) {
        return Err(Malformed);
    }
    // Rule 4: host and port.
    let (host, port, bracketed) = if let Some(inner) = authority.strip_prefix('[') {
        let Some(close) = inner.find(']') else {
            return Err(Malformed);
        };
        let literal = &inner[..close];
        // The charset also excludes any further '[' inside the literal.
        if literal.is_empty()
            || !literal
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        {
            return Err(Malformed);
        }
        let after = &inner[close + 1..];
        // Anything after ']' must be ":port"; a second ']' fails the port
        // digit check below.
        let port = if after.is_empty() {
            None
        } else {
            Some(after.strip_prefix(':').ok_or(Malformed)?)
        };
        (literal, port, true)
    } else {
        if authority.contains(['[', ']']) {
            return Err(Malformed);
        }
        let (host, port) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        // A second ':' is an unbracketed IPv6 literal.
        if port.is_some_and(|p| p.contains(':')) {
            return Err(Malformed);
        }
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
        {
            return Err(Malformed);
        }
        (host, port, false)
    };
    if let Some(p) = port {
        let valid = (1..=5).contains(&p.len())
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u32>().is_ok_and(|v| (1..=65535).contains(&v));
        if !valid {
            return Err(Malformed);
        }
    }
    // Rules 5-6: https for any host; http only for a literal loopback host.
    if !is_https {
        let loopback = if bracketed {
            host.eq_ignore_ascii_case("::1")
        } else {
            is_canonical_loopback_ipv4(host)
        };
        if !loopback {
            return Err(HttpsRequired);
        }
    }
    Ok(&rest[auth_end..])
}

/// Canonical dotted-decimal IPv4 with first octet exactly 127: four decimal
/// octets 0..=255 of 1-3 digits, no leading zeros. Hand-rolled because the
/// policy defines its own spelling rule (std's parser is not equivalent).
fn is_canonical_loopback_ipv4(host: &str) -> bool {
    let mut count = 0;
    for (i, part) in host.split('.').enumerate() {
        count += 1;
        let b = part.as_bytes();
        if b.is_empty() || b.len() > 3 || !b.iter().all(u8::is_ascii_digit) {
            return false;
        }
        if b.len() > 1 && b[0] == b'0' {
            return false;
        }
        let Ok(v) = part.parse::<u16>() else {
            return false;
        };
        if v > 255 || (i == 0 && v != 127) {
            return false;
        }
    }
    count == 4
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expect_bad(url: &str) {
        let err = validate_base_url(url).expect_err("must be rejected");
        assert_eq!(err.to_string(), BAD_URL, "{url:?}");
        assert!(
            request_target(url).is_err(),
            "request_target must fail too: {url:?}"
        );
    }

    fn expect_https_required(url: &str) {
        let err = validate_base_url(url).expect_err("must be rejected");
        assert_eq!(err.to_string(), HTTPS_REQUIRED, "{url:?}");
        assert!(
            request_target(url).is_err(),
            "request_target must fail too: {url:?}"
        );
    }

    #[test]
    fn validate_accepts() {
        for url in [
            "http://127.0.0.1",
            "https://h:8080/mcp?x=1",
            "HTTP://127.0.0.1/mcp",
            "https://svc.example.test/mcp",
            "https://h",
            "http://127.0.0.1:80/",
            "https://h:00080/",
            "http://[::1]:8080/p",
            "http://127.0.0.1#frag",
            "https://h/a@b?c=%20#%",
        ] {
            validate_base_url(url).unwrap_or_else(|e| panic!("{url} must be accepted: {e}"));
        }
    }

    #[test]
    fn validate_rejects() {
        for url in [
            "",
            "/mcp",
            "//h/mcp",
            "ftp://h/mcp",
            "http:///mcp",
            "http://",
            "https://h/\nx",
            "http://127.0.0.1/\u{7f}x",
            "http://user@/mcp",
            "http://@/x",
            "https://@h/",
            "https://h:99999/",
            "https://h:0/",
            "https://h\\x",
            "https://h%2e/",
            "https://[::1",
            "https://a:1:2/",
        ] {
            expect_bad(url);
        }
    }

    #[test]
    fn http_requires_loopback_literal() {
        for url in [
            "http://h",
            "HTTP://Host/mcp",
            "http://h:8080",
            "http://localhost/",
            "http://127.1/",
            "http://127.0.0.01/",
            "http://127.0.0.1./",
            "http://0.0.0.0/",
            "http://[::]/",
            "http://[0:0:0:0:0:0:0:1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://127.0.0.1.nip.io/",
        ] {
            expect_https_required(url);
        }
        // https is allowed for the same kind of hosts.
        for url in ["https://h", "https://localhost/", "https://127.1/"] {
            validate_base_url(url).unwrap_or_else(|e| panic!("{url}: {e}"));
        }
        // Loopback spellings accepted over http.
        for url in [
            "http://127.255.255.254/",
            "http://[::1]/",
            "Http://[::1]:1/",
        ] {
            validate_base_url(url).unwrap_or_else(|e| panic!("{url}: {e}"));
        }
    }

    #[test]
    fn percent_in_path_and_query_is_accepted_verbatim() {
        let url = "https://svc.example.test/a%20b?x=%2F";
        validate_base_url(url).expect("accepted");
        assert_eq!(request_target(url).expect("target"), "/a%20b?x=%2F");
        expect_bad("https://svc.example.test%2e/a");
    }

    #[test]
    fn userinfo_is_refused_for_every_scheme() {
        for url in [
            "http://u@127.0.0.1/mcp",
            "https://u@h/mcp",
            "https://u:p@h/mcp",
        ] {
            expect_bad(url);
        }
    }

    #[test]
    fn request_target_cases() {
        let cases = [
            ("https://svc.example.test/mcp", "/mcp"),
            ("http://127.0.0.1:8080/mcp?x=1", "/mcp?x=1"),
            ("https://h:8080/mcp?x=1", "/mcp?x=1"),
            ("http://127.0.0.1", "/"),
            ("http://127.0.0.1?a=1", "/?a=1"),
            ("https://h?a=1", "/?a=1"),
            ("http://127.0.0.1/mcp#frag", "/mcp"),
            ("https://h/mcp@x/%20?q=a@b", "/mcp@x/%20?q=a@b"),
            ("http://127.0.0.1/mcp/a?b=c#d", "/mcp/a?b=c"),
            ("http://127.0.0.1#frag", "/"),
            ("http://[::1]:8080/p", "/p"),
        ];
        for (url, want) in cases {
            assert_eq!(
                request_target(url).unwrap_or_else(|e| panic!("{url} must work: {e}")),
                want
            );
        }
    }

    #[test]
    fn ipv4_loopback_spelling() {
        assert!(is_canonical_loopback_ipv4("127.0.0.0"));
        assert!(is_canonical_loopback_ipv4("127.10.200.255"));
        for h in [
            "127.0.0",
            "127.0.0.1.1",
            "127.0.0.256",
            "127.0.0.001",
            "127.0.0.-1",
            "127..0.1",
            "128.0.0.1",
            "0127.0.0.1",
            "",
        ] {
            assert!(!is_canonical_loopback_ipv4(h), "{h:?}");
        }
    }
}
