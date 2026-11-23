//! Modern-profile responses of the HTTP adapter: the signed JSON-RPC refusal of
//! spec 04 `S10` and the header helpers of `S1`/`S8`.

use bytes::Bytes;
use http::header::HeaderValue;
use http_body_util::{BodyExt, Full};
use serde_json::value::RawValue;
use tower_service::Service;

use super::wire::error_body;
use super::{BoxError, JackService};
use crate::server::modern::HeaderField;
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
    /// Answers the era-neutral `400 invalid_request` refusal of spec 02 section
    /// 2 item 4 with the 01 section 4 envelope, signed like every response.
    pub(super) fn invalid_request(
        &self,
        res: &VerifyResult,
        message: &str,
    ) -> http::Response<Full<Bytes>> {
        self.signed(
            400,
            res,
            error_body("invalid_request", message).into_bytes().into(),
        )
    }

    /// Answers one refusal of spec 04 section 5 (`S10`): a signed JSON-RPC
    /// error `{"jsonrpc":"2.0","id":<id>,"error":{"code":<code>,"message":<message>}}`
    /// with `Content-Type: application/json`. `S2` additionally carries
    /// `Allow: POST`.
    pub(super) fn refuse_modern(
        &self,
        res: &VerifyResult,
        refusal: &crate::server::modern::Refusal,
    ) -> http::Response<Full<Bytes>> {
        let id = match refusal.id.as_deref() {
            None => None,
            Some(raw) => match RawValue::from_string(raw.to_owned()) {
                Ok(id) => Some(id),
                Err(_) => return self.internal(res),
            },
        };
        let payload = JsonRpcErrorResponse {
            jsonrpc: "2.0",
            id,
            error: JsonRpcErrorDetail {
                code: refusal.reason.code(),
                message: refusal.reason.message(),
            },
        };
        let body = serde_json::to_string(&payload).expect("static JSON-RPC shape serializes");
        let response = self.signed(refusal.reason.http_status(), res, body.into_bytes().into());
        if refusal.reason == crate::server::modern::RefusalReason::MethodNotAllowed {
            let mut response = response;
            response
                .headers_mut()
                .insert("Allow", HeaderValue::from_static("POST"));
            return response;
        }
        response
    }
}

/// One received header list as the rules of spec 04 section 5 see it: name and
/// value in received order. A value that is not valid UTF-8 is mapped lossily,
/// so it still fails the field-value syntax of `S1` instead of disappearing.
pub(super) fn header_fields(headers: &http::HeaderMap) -> Vec<HeaderField> {
    headers
        .iter()
        .map(|(name, value)| {
            HeaderField::new(
                name.as_str(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

#[derive(serde::Serialize)]
pub(super) struct JsonRpcErrorDetail<'a> {
    code: i64,
    message: &'a str,
}

/// Field declaration order is load-bearing: it fixes the JSON key order of a
/// refusal body (spec 04 `S10`).
#[derive(serde::Serialize)]
pub(super) struct JsonRpcErrorResponse<'a> {
    jsonrpc: &'a str,
    /// None serializes as null, matching a non-`POST` or notification refusal.
    id: Option<Box<RawValue>>,
    error: JsonRpcErrorDetail<'a>,
}
