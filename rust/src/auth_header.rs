//! Jack-Auth header grammar of spec 01 sections 3 and 5, parsed strictly
//! (Go: authheader.go). RequestAuth and ResponseAuth hold the parameter
//! values as sent.

use crate::encoding::decode_b64url_fixed;
use crate::error::{codes, JackError};

/// Parsed parameters of a v1 request Jack-Auth header; values as sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestAuth {
    pub kid: String,
    pub ts: i64,
    pub nonce: String,
    pub sig: String,
}

/// Parsed parameters of a v1 response Jack-Auth header (spec 01 section 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseAuth {
    pub kid: String,
    pub ts: i64,
    pub sig: String,
}

// Byte lengths required by spec 01 section 2 (sizes of kid, nonce, sig).
const KID_LEN: usize = 32;
const NONCE_LEN: usize = 16;
const SIG_LEN: usize = 64;

/// One parsed header: (name, value) pairs in header order. `ts` is kept as
/// the canonical raw string until the caller reads it back as i64.
struct AuthParams(Vec<(String, String)>);

impl AuthParams {
    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
    fn insert_dup_check(&mut self, name: &str, val: &str) -> bool {
        if self.get(name).is_some() {
            return false;
        }
        self.0.push((name.to_string(), val.to_string()));
        true
    }
}

fn malformed(message: impl Into<String>) -> JackError {
    JackError::new(401, codes::MALFORMED_AUTH, message)
}

/// Parses the shared grammar shared by request and response headers. Any
/// violation is a JackError with HTTP status 401: missing_auth,
/// malformed_auth or unsupported_version. `allowed` is the exact parameter
/// set; `lengths` lists the names that must decode via decode_b64url_fixed
/// to a fixed number of bytes.
fn parse_auth_values(
    values: &[&str],
    allowed: &[&str],
    lengths: &[(&str, usize)],
) -> Result<(AuthParams, i64), JackError> {
    if values.is_empty() {
        return Err(JackError::new(
            401,
            codes::MISSING_AUTH,
            "missing Jack-Auth header",
        ));
    }
    // Spec 01 section 4 step 2: a header may appear at most once.
    if values.len() > 1 {
        return Err(malformed("Jack-Auth header present more than once"));
    }
    let value = values[0];

    // Scheme: the value up to the first space (spec 01 section 3).
    let sp = value.find(' ');
    let scheme = match sp {
        Some(i) => &value[..i],
        None => value,
    };
    // The scheme is examined first: a v2 header is unsupported_version even
    // with malformed parameters, because the grammar of other versions is
    // unknown (spec 01 section 3).
    if scheme != "v1" {
        if is_version_scheme(scheme) {
            return Err(JackError::new(
                401,
                codes::UNSUPPORTED_VERSION,
                "unsupported Jack-Auth version",
            ));
        }
        return Err(malformed("malformed Jack-Auth scheme"));
    }
    let Some(sp) = sp else {
        return Err(malformed("missing Jack-Auth parameters"));
    };

    // Parameters: comma-separated name=value, no whitespace anywhere
    // (spec 01 section 3 grammar). Byte-index slices are panic-safe because
    // ' ' and '=' are ASCII, so every slice point is a char boundary.
    let rest = &value[sp + 1..];
    let mut params = AuthParams(Vec::with_capacity(allowed.len()));
    for part in rest.split(',') {
        let Some(eq) = part.find('=') else {
            return Err(malformed("malformed Jack-Auth parameter"));
        };
        // The grammar name=value allows exactly one '='.
        if eq == 0 || eq == part.len() - 1 || part[eq + 1..].contains('=') {
            return Err(malformed("malformed Jack-Auth parameter"));
        }
        let (name, val) = (&part[..eq], &part[eq + 1..]);
        if !lower_alpha(name) || !param_value_charset(val) {
            return Err(malformed("malformed Jack-Auth parameter"));
        }
        if !allowed.contains(&name) {
            return Err(malformed("unknown Jack-Auth parameter"));
        }
        if !params.insert_dup_check(name, val) {
            return Err(malformed("repeated Jack-Auth parameter"));
        }
    }
    for name in allowed {
        if params.get(name).is_none() {
            return Err(malformed(format!("missing Jack-Auth parameter {name}")));
        }
    }

    // ts: whole seconds, no sign, no leading zeros, at most 12 digits
    // (spec 01 section 3).
    let raw_ts = params
        .get("ts")
        .expect("allowed contains ts and presence was checked");
    if !valid_ts(raw_ts) {
        return Err(malformed("malformed ts"));
    }
    // Unreachable failure: valid_ts guarantees at most 12 canonical digits.
    // The guard is kept to mirror Go and to be robust against refactors.
    let ts: i64 = raw_ts.parse().map_err(|_| malformed("malformed ts"))?;

    // Fixed-length base64url values: kid 32, nonce 16, sig 64 bytes
    // (spec 01 sections 2 and 3).
    for (name, size) in lengths {
        if let Some(v) = params.get(name) {
            if decode_b64url_fixed(v, *size).is_err() {
                return Err(malformed(format!("malformed {name}")));
            }
        }
    }

    Ok((params, ts))
}

/// Reports whether s is exactly "v" plus one or more ASCII digits (spec 01
/// section 3: such a scheme is unsupported_version, any other is malformed_auth).
fn is_version_scheme(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 2 || b[0] != b'v' {
        return false;
    }
    b[1..].iter().all(u8::is_ascii_digit)
}

/// Reports whether s matches ^[a-z]+$ (parameter names, spec 01 section 3).
fn lower_alpha(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.iter().all(u8::is_ascii_lowercase)
}

/// Reports whether s is non-empty and only A-Za-z0-9_- (spec 01 section 3).
fn param_value_charset(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.iter()
            .all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// Reports whether s matches ^(0|[1-9][0-9]{0,11})$ (spec 01 section 3).
fn valid_ts(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 12 {
        return false;
    }
    if b[0] == b'0' {
        return b.len() == 1;
    }
    b.iter().all(u8::is_ascii_digit)
}

/// Parses the Jack-Auth header values of one HTTP request (the caller
/// collects the values of all headers named Jack-Auth case-insensitively,
/// in order) and returns MISSING_AUTH, MALFORMED_AUTH or UNSUPPORTED_VERSION.
pub fn parse_request_auth(values: &[&str]) -> Result<RequestAuth, JackError> {
    let (p, ts) = parse_auth_values(
        values,
        &["kid", "ts", "nonce", "sig"],
        &[("kid", KID_LEN), ("nonce", NONCE_LEN), ("sig", SIG_LEN)],
    )?;
    Ok(RequestAuth {
        kid: p.get("kid").expect("kid present").to_string(),
        ts,
        nonce: p.get("nonce").expect("nonce present").to_string(),
        sig: p.get("sig").expect("sig present").to_string(),
    })
}

/// parse_request_auth for response headers, whose parameter set is exactly
/// kid, ts, sig (spec 01 section 5).
pub fn parse_response_auth(values: &[&str]) -> Result<ResponseAuth, JackError> {
    let (p, ts) = parse_auth_values(
        values,
        &["kid", "ts", "sig"],
        &[("kid", KID_LEN), ("sig", SIG_LEN)],
    )?;
    Ok(ResponseAuth {
        kid: p.get("kid").expect("kid present").to_string(),
        ts,
        sig: p.get("sig").expect("sig present").to_string(),
    })
}

/// Renders the canonical request header value
/// "v1 kid=...,ts=...,nonce=...,sig=..." (spec 01 section 3).
pub fn format_request_auth(auth: &RequestAuth) -> String {
    format!(
        "v1 kid={},ts={},nonce={},sig={}",
        auth.kid, auth.ts, auth.nonce, auth.sig
    )
}

/// Renders the canonical response header value "v1 kid=...,ts=...,sig=..."
/// (spec 01 section 5).
pub fn format_response_auth(auth: &ResponseAuth) -> String {
    format!("v1 kid={},ts={},sig={}", auth.kid, auth.ts, auth.sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::encode_b64url;

    fn kid_value() -> String {
        encode_b64url(&[1u8; 32])
    }

    fn nonce_value() -> String {
        encode_b64url(&[2u8; 16])
    }

    fn sig_value() -> String {
        encode_b64url(&[3u8; 64])
    }

    fn expect_parse_error(values: &[&str], code: &str) {
        let err = parse_request_auth(values).expect_err("expected a parse error");
        assert_eq!(err.code, code);
        assert_eq!(err.http_status, 401);
    }

    fn expect_response_parse_error(values: &[&str], code: &str) {
        let err = parse_response_auth(values).expect_err("expected a parse error");
        assert_eq!(err.code, code);
        assert_eq!(err.http_status, 401);
    }

    fn canonical() -> String {
        format_request_auth(&RequestAuth {
            kid: kid_value(),
            ts: 1,
            nonce: nonce_value(),
            sig: sig_value(),
        })
    }

    fn canonical_response() -> String {
        format_response_auth(&ResponseAuth {
            kid: kid_value(),
            ts: 1,
            sig: sig_value(),
        })
    }

    #[test]
    fn missing_and_duplicate() {
        expect_parse_error(&[], codes::MISSING_AUTH);
        let v = canonical();
        expect_parse_error(&[v.as_str(), v.as_str()], codes::MALFORMED_AUTH);
    }

    #[test]
    fn version_scheme() {
        let v = canonical();
        expect_parse_error(
            &[v.replacen("v1", "v2", 1).as_str()],
            codes::UNSUPPORTED_VERSION,
        );
        expect_parse_error(&[v.replacen("v1", "V1", 1).as_str()], codes::MALFORMED_AUTH);
        expect_parse_error(&["v1"], codes::MALFORMED_AUTH);
        expect_parse_error(&["v2"], codes::UNSUPPORTED_VERSION);
        expect_parse_error(&["v"], codes::MALFORMED_AUTH);
        expect_parse_error(&["v10"], codes::UNSUPPORTED_VERSION);
    }

    #[test]
    fn grammar_rejects() {
        let v = canonical();
        // Unknown parameter.
        expect_parse_error(&[format!("{v},x=1").as_str()], codes::MALFORMED_AUTH);
        // Repeated parameter.
        expect_parse_error(&[format!("{v},ts=2").as_str()], codes::MALFORMED_AUTH);
        // Missing parameter: drop the nonce segment.
        let no_nonce = format!("v1 kid={},ts=1,sig={}", kid_value(), sig_value());
        expect_parse_error(&[no_nonce.as_str()], codes::MALFORMED_AUTH);
        // Empty part between commas.
        expect_parse_error(&[format!("{v},,").as_str()], codes::MALFORMED_AUTH);
        // No '=' in the part.
        expect_parse_error(&[format!("{v},kid").as_str()], codes::MALFORMED_AUTH);
        // '=' at index 0.
        expect_parse_error(&[format!("{v},=x").as_str()], codes::MALFORMED_AUTH);
        // '=' at the last byte.
        expect_parse_error(&[format!("{v},x=").as_str()], codes::MALFORMED_AUTH);
        // Second '=' in the value.
        expect_parse_error(&[format!("{v},x==y").as_str()], codes::MALFORMED_AUTH);
        // Uppercase parameter name.
        expect_parse_error(&[format!("{v},KID=x").as_str()], codes::MALFORMED_AUTH);
        // Space inside a value.
        expect_parse_error(&[format!("{v},x=a b").as_str()], codes::MALFORMED_AUTH);
    }

    #[test]
    fn ts_rules() {
        let v = canonical();
        expect_parse_error(
            &[v.replacen("ts=1", "ts=01", 1).as_str()],
            codes::MALFORMED_AUTH,
        );
        expect_parse_error(
            &[v.replacen("ts=1,", "ts=1234567890123,", 1).as_str()],
            codes::MALFORMED_AUTH,
        );
        expect_parse_error(
            &[v.replacen("ts=1,", "ts=-1,", 1).as_str()],
            codes::MALFORMED_AUTH,
        );
        expect_parse_error(
            &[v.replacen("ts=1,", "ts=+1,", 1).as_str()],
            codes::MALFORMED_AUTH,
        );
        // "0" alone is valid.
        let zero = v.replacen("ts=1,", "ts=0,", 1);
        let parsed = parse_request_auth(&[zero.as_str()]).expect("ts=0 must be accepted");
        assert_eq!(parsed.ts, 0);
    }

    #[test]
    fn fixed_length_fields() {
        let v = canonical();
        let parts: Vec<&str> = v
            .split_once(' ')
            .expect("space present")
            .1
            .split(',')
            .collect();
        // Drop one character from each fixed-length value (kid index 0,
        // nonce 2, sig 3; ts at index 1 keeps its length).
        for i in [0usize, 2, 3] {
            let (name, val) = parts[i].split_once('=').expect("= present");
            let mut rebuilt: Vec<String> = parts.iter().map(|s| s.to_string()).collect();
            rebuilt[i] = format!("{name}={}", &val[..val.len() - 1]);
            let value = format!("v1 {}", rebuilt.join(","));
            expect_parse_error(&[value.as_str()], codes::MALFORMED_AUTH);
        }
    }

    #[test]
    fn order_independent() {
        let parts = [
            format!("kid={}", kid_value()),
            "ts=1".to_string(),
            format!("nonce={}", nonce_value()),
            format!("sig={}", sig_value()),
        ];
        let perms: [&[String]; 4] = [
            &parts,
            &[
                parts[3].clone(),
                parts[2].clone(),
                parts[1].clone(),
                parts[0].clone(),
            ],
            &[
                parts[1].clone(),
                parts[0].clone(),
                parts[3].clone(),
                parts[2].clone(),
            ],
            &[
                parts[2].clone(),
                parts[3].clone(),
                parts[0].clone(),
                parts[1].clone(),
            ],
        ];
        let want = RequestAuth {
            kid: kid_value(),
            ts: 1,
            nonce: nonce_value(),
            sig: sig_value(),
        };
        for p in perms {
            let value = format!("v1 {}", p.join(","));
            let parsed = parse_request_auth(&[value.as_str()]).expect("any order must parse");
            assert_eq!(parsed, want);
        }
    }

    #[test]
    fn request_round_trip() {
        let want = RequestAuth {
            kid: kid_value(),
            ts: 1,
            nonce: nonce_value(),
            sig: sig_value(),
        };
        let v = format_request_auth(&want);
        let parsed = parse_request_auth(&[v.as_str()]).expect("canonical value must parse");
        assert_eq!(parsed, want);
        assert_eq!(format_request_auth(&parsed), v);
    }

    #[test]
    fn response_round_trip_and_rules() {
        let want = ResponseAuth {
            kid: kid_value(),
            ts: 1,
            sig: sig_value(),
        };
        let v = canonical_response();
        let parsed = parse_response_auth(&[v.as_str()]).expect("canonical response must parse");
        assert_eq!(parsed, want);
        assert_eq!(format_response_auth(&parsed), v);

        // A nonce parameter is not part of the response grammar.
        expect_response_parse_error(
            &[format!("{v},nonce={}", nonce_value()).as_str()],
            codes::MALFORMED_AUTH,
        );
        // Missing sig.
        let no_sig = format!("v1 kid={},ts=1", kid_value());
        let err = parse_response_auth(&[no_sig.as_str()]).expect_err("missing sig must fail");
        assert_eq!(err.code, codes::MALFORMED_AUTH);
        assert_eq!(err.http_status, 401);
        // Missing header.
        expect_response_parse_error(&[], codes::MISSING_AUTH);
    }
}
