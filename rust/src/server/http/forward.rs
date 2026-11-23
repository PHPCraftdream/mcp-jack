//! Forwarding of an authorized request to the wrapped service (Go: forward):
//! the modern-era header rebuild of spec 04 `S8`/`S9` and the signing of the
//! buffered answer.

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::HeaderValue;
use http_body_util::{BodyExt, Full};
use tower_service::Service;

use super::wire::error_body;
use super::{BodyReadError, BoxError, JackService};
use crate::server::verify::VerifyResult;

impl<S, ResBody> JackService<S>
where
    S: Service<http::Request<Full<Bytes>>, Response = http::Response<ResBody>>
        + Clone
        + Send
        + 'static,
    S::Error: Send + 'static,
    S::Future: Send + 'static,
    ResBody: BodyExt + Send + 'static,
    ResBody::Error: Into<BoxError>,
{
    /// Hands an authorized request to the wrapped service and signs what it
    /// answers (Go: forward).
    ///
    /// With `modern` set (the modern era of spec 04), the inner request's
    /// header list is rebuilt from the request's ORIGINAL ordered entries: the
    /// headers for which [`crate::modern::is_session_header`] holds are removed
    /// (`S8`) and every other `(name, value)` pair is appended in received
    /// order, so a repeated name keeps every instance and opaque value bytes
    /// (0x80..) reach the wrapped service untouched. The engine's
    /// `HeaderField` list is consulted for validation only, never for
    /// forwarding: its `String` copy is lossy UTF-8 and would rewrite exactly
    /// those bytes. A legacy-era forward, and the [`crate::server::modern::Profile::Legacy`]
    /// profile,
    /// pass the received map through unchanged, keeping 0.1.x byte identity.
    pub(super) async fn forward(
        &mut self,
        mut parts: http::request::Parts,
        body: Bytes,
        res: &VerifyResult,
        modern: bool,
        head: bool,
    ) -> Result<http::Response<Full<Bytes>>, S::Error> {
        // Typed request extension carrying the verified caller identity
        // snapshot (spec 02 section 3): the verifier derives it exclusively
        // from signature verification and the registry, and the extension
        // type has no public constructor, so the wrapped service cannot read
        // it from any header/query/body nor fabricate one. It is Some on
        // every forwarded accept; None here is a verifier bug, answered like
        // the other unreachable paths with the signed 500.
        let identity = match res.identity.clone() {
            Some(identity) => identity,
            None => return Ok(self.internal(res, head)),
        };
        if modern {
            // `S8` removes exactly the session headers and nothing else: `S7`
            // and `S9` add, rewrite and reorder nothing, so the surviving
            // original pairs are appended in received order.
            let headers: Vec<(http::HeaderName, HeaderValue)> = parts
                .headers
                .iter()
                .filter(|(name, _)| !crate::modern::is_session_header(name.as_str()))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect();
            parts.headers.clear();
            for (name, value) in headers {
                parts.headers.append(name, value);
            }
        }
        let mut inner_req = http::Request::from_parts(parts, Full::new(body));
        inner_req.extensions_mut().insert(identity);
        // Clone-and-swap so the future owns the inner instance and self stays
        // usable for the next call.
        let inner = {
            let inner_clone = self.inner.clone();
            let mut inner_svc = std::mem::replace(&mut self.inner, inner_clone);
            match inner_svc.call(inner_req).await {
                Ok(inner) => inner,
                // Inner errors propagate unchanged: ServeHTTP has no error path
                // in Go and propagation is the direct analogue.
                Err(err) => return Err(err),
            }
        };

        let (inner_parts, inner_body) = inner.into_parts();
        // Go parses the media type and compares the type before ';'; a missing
        // or non-UTF-8 header means NOT streaming (its error path).
        let streaming = inner_parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/event-stream"));
        if streaming {
            // Refuse BEFORE buffering: dropping the body unread is the point —
            // an endless SSE stream must not be pulled into memory. Fresh
            // headers, discarding all inner ones (Go builds a new header).
            let body = error_body(
                "streaming_unsupported",
                "streaming responses cannot be signed in v0.1",
            );
            return Ok(self.signed(head, 501, res, body.into_bytes().into()));
        }
        // Bounded by response_limit (default 1 MiB): the inner body is moved
        // into buffer_body, which stops polling and drops it on overflow, and
        // never appends an oversized frame. Overflow is a signed 502 with a
        // fresh header set, so no upstream header or partial byte survives.
        // A read error cannot be mapped into S::Error generically, so it is
        // answered as a signed 500 instead of propagating (request binding
        // preserved) — Go cannot hit this path at all.
        let buffered = match Self::buffer_body(inner_body, self.response_limit).await {
            Ok(bytes) => bytes,
            Err(BodyReadError::TooLarge) => {
                let body = error_body(
                    "response_too_large",
                    "upstream response exceeds the configured limit",
                );
                return Ok(self.signed(head, 502, res, body.into_bytes().into()));
            }
            Err(BodyReadError::Read) => return Ok(self.internal(res, head)),
        };

        // Content-Length: the buffered length decides (Go: header.Del).
        // Transfer-Encoding described the inner transport, not this buffered
        // body. Jack-Auth is REPLACED, not appended (Go: header.Set); the
        // parser rejects a repeated header. Content-Type keeps append
        // semantics: Go header.Clone() keeps the inner values, including
        // multi-value headers.
        let mut headers = inner_parts.headers;
        headers.remove(CONTENT_LENGTH);
        headers.remove(http::header::TRANSFER_ENCODING);
        headers.remove("Jack-Auth");
        let status = inner_parts.status;
        Ok(self.signed_with_headers(head, status.as_u16(), res, headers, buffered))
    }
}
