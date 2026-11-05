//! URL handling of the client SDK. The client library defines Transport over
//! plain structs, so URL handling is a minimal, explicit helper instead of a
//! dependency. Spec 01 section 3.1 requires the origin-form target
//! byte-for-byte (path plus ?query, no fragment, no normalisation) — a
//! substring of the configured URL string gives exactly that.

use crate::client::error::ClientError;

const BAD_URL: &str = "jack client: base url must be an absolute http/https URL with a host";

/// Validates an absolute http/https URL with a host (Go: url.Parse + IsAbs +
/// scheme + Host checks in client/rpc.go NewClient and client/profile.go
/// validateProfile). Scheme comparison is case-insensitive like Go; control
/// characters anywhere in the URL are rejected (Go: url.Parse errors on
/// them).
pub fn validate_base_url(url: &str) -> Result<(), ClientError> {
    split(url).map(|_| ())
}

/// Extracts the origin-form request target (path plus ?query, no fragment)
/// from an absolute http/https URL, byte-for-byte as configured (spec 01
/// section 3.1; Go: req.URL.RequestURI()). An empty path becomes "/". User
/// info in the authority is dropped, like Go's RequestURI.
pub fn request_target(url: &str) -> Result<String, ClientError> {
    split(url).map(|(_, _, path_query)| path_query)
}

/// Splits url into (scheme, host, path?query). Everything is a plain byte
/// scan so the target stays byte-for-byte as configured.
fn split(url: &str) -> Result<(&str, &str, String), ClientError> {
    // Control characters anywhere: Go's url.Parse errors on them.
    if url.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(ClientError::Client(BAD_URL.to_string()));
    }
    let Some(pos) = url.find("://") else {
        return Err(ClientError::Client(BAD_URL.to_string()));
    };
    let scheme = &url[..pos];
    // Case-insensitive scheme compare without allocation (Go's url.Parse
    // lowercases the scheme).
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(ClientError::Client(BAD_URL.to_string()));
    }
    let rest = &url[pos + 3..];
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    // The host is the authority minus its "@..." userinfo part: the userinfo
    // spans up to the LAST '@' (Go: net/url). "http://user@/mcp" therefore
    // has an EMPTY host and is rejected although the authority is not.
    let host = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    if host.is_empty() {
        return Err(ClientError::Client(BAD_URL.to_string()));
    }
    let remainder = &rest[auth_end..];
    // The request target is path?query with the fragment cut. An empty path
    // becomes "/"; a query-only URL becomes "/?query" (Go: RequestURI).
    let path_and_query = match remainder.find('#') {
        Some(i) => &remainder[..i],
        None => remainder,
    };
    let path_query = match path_and_query {
        "" => "/".to_string(),
        r if r.starts_with('/') => r.to_string(),
        // Query without a path: Go's RequestURI yields "/?query".
        r => format!("/{r}"),
    };
    Ok((scheme, host, path_query))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expect_bad(url: &str) {
        let err = validate_base_url(url).expect_err("must be rejected");
        assert_eq!(err.to_string(), BAD_URL);
        assert!(
            request_target(url).is_err(),
            "request_target must fail too: {url:?}"
        );
    }

    #[test]
    fn validate_accepts() {
        for url in [
            "http://h",
            "https://h:8080/mcp?x=1",
            "HTTP://Host/mcp",
            "https://svc.example.test/mcp",
            "http://@h/",
            "http://h:99999/",
            "http://[::1]:8080/p",
            "http://h#frag",
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
            "http://h/\u{7f}x",
            "http://user@/mcp",
            "http://@/x",
        ] {
            expect_bad(url);
        }
    }

    #[test]
    fn request_target_cases() {
        let cases = [
            ("https://svc.example.test/mcp", "/mcp"),
            ("http://h:8080/mcp?x=1", "/mcp?x=1"),
            ("http://h", "/"),
            ("http://h?a=1", "/?a=1"),
            ("http://h/mcp#frag", "/mcp"),
            ("http://u@h/mcp", "/mcp"),
            ("http://h/mcp/a?b=c#d", "/mcp/a?b=c"),
            ("http://h#frag", "/"),
            ("http://[::1]:8080/p", "/p"),
        ];
        for (url, want) in cases {
            assert_eq!(
                request_target(url).unwrap_or_else(|e| panic!("{url} must work: {e}")),
                want
            );
        }
    }
}
