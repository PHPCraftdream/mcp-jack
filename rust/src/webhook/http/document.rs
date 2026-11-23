//! The well-known document fetcher of spec 06 R5.9 and R5.12: route 4 over
//! the same hardened path as a delivery (section 6).
//!
//! The fetcher is pure orchestration: the URL is [`well_known_url`] of the
//! canonical url, the host is resolved twice — validation and the R6.9
//! recheck — the section 6 decision runs in
//! [`prepare`](crate::webhook::http::transport::prepare), one request is sent
//! and the response is judged by
//! [`document_verdict`](crate::webhook::verification::document::document_verdict).
//! Nothing is retried (R5.9, R5.12, R6.10).

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::webhook::http::transport::{
    prepare, resolve_answers, HostResolver, TransportFailure, WebhookTransport, MAX_DOCUMENT_BYTES,
};
use crate::webhook::ssrf::url::check_url;
use crate::webhook::verification::document::{
    document_verdict, well_known_url, DocumentFetcher, DocumentResponse, ReceiverDocument,
};
use crate::webhook::{codes, WebhookError};

/// The whole-attempt budget of one document fetch, in seconds (spec 06
/// R5.9, R5.12).
const DOCUMENT_TIMEOUT_SECONDS: u64 = 10;

/// The invalid-input status the profile uses for a rejected client value
/// (spec 06 section 3).
const BAD_REQUEST: u16 = 400;

/// The R6.2 code of a canonical url that does not parse (spec 06 R5.9).
const INVALID_CALLBACK_URL: &str = "invalid_callback_url";

/// The R6.2 reason of a canonical url that does not parse (spec 06 R6.2).
const REASON_URL: &str = "url";

/// The fixed reason of a document response that is a `3xx` (spec 06 R6.10).
const REASON_REDIRECT: &str = "redirect";

/// The `Accept` value of the well-known document fetch (spec 06 R5.9).
const ACCEPT_JSON: &str = "application/json";

/// The status of a verification-side refusal: the well-known fetch answers
/// the subscribe call, not a receiver request, so no wire status is reported
/// (spec 06 R5.9, R5.12).
const NO_HTTP_STATUS: u16 = 0;

/// Fetches the well-known receiver document over the hardened delivery path
/// (spec 06 R5.9, R5.12).
///
/// The transport and the resolver are the sender's own, so the fetch follows
/// the same R6.8-R6.10 decision and the same peer and body caps as a
/// delivery; only the method, the URL and the verdict differ (R5.9, R6.10).
pub struct WebhookDocumentFetcher {
    transport: Arc<dyn WebhookTransport>,
    resolver: Arc<dyn HostResolver>,
    allowed_ranges: Vec<String>,
}

impl WebhookDocumentFetcher {
    /// Builds a fetcher over the sender's transport and resolver and the
    /// operator override ranges of R6.11.
    pub fn new(
        transport: Arc<dyn WebhookTransport>,
        resolver: Arc<dyn HostResolver>,
        allowed_ranges: Vec<String>,
    ) -> Self {
        Self {
            transport,
            resolver,
            allowed_ranges,
        }
    }

    /// Fetches `/.well-known/mcp-webhook-receiver.json` of the canonical
    /// url's origin and judges it (spec 06 R5.9, R5.12, R6.10).
    ///
    /// The url is [`well_known_url`] of the canonical url; a canonical url
    /// that does not parse is `invalid_callback_url` (R5.9). The whole
    /// attempt — DNS, connect, TLS, write and read — is bounded by a 10 s
    /// budget, the host is resolved twice (validation and the R6.9 recheck),
    /// and the section 6 decision of [`prepare`] surfaces as its own
    /// [`WebhookError`], so a blocked, rebinding or redirect refusal keeps
    /// the decision's code (R6.8-R6.10). The request is a `GET` with
    /// `Accept: application/json`, one send is made and never retried, a
    /// transport failure maps to its R1.9 code, a `3xx` is `redirect_refused`
    /// and the body is judged by [`document_verdict`] (R5.9).
    pub fn fetch_receiver_document(
        &self,
        canonical_url: &str,
    ) -> Result<ReceiverDocument, WebhookError> {
        let Some(url) = well_known_url(canonical_url) else {
            return Err(invalid_canonical_url());
        };
        let endpoint = match check_url(&url) {
            Ok(endpoint) => endpoint,
            Err(_) => return Err(invalid_canonical_url()),
        };
        let budget = Duration::from_secs(DOCUMENT_TIMEOUT_SECONDS);
        let started = Instant::now();
        let (answers, recheck) = resolve_answers(&*self.resolver, &endpoint, budget)?;
        let remaining = budget.saturating_sub(started.elapsed());
        let prepared = prepare(
            &url,
            &answers,
            &recheck,
            &self.allowed_ranges,
            "GET",
            vec![("Accept".to_owned(), ACCEPT_JSON.to_owned())],
            Vec::new(),
            MAX_DOCUMENT_BYTES,
            remaining,
        )?;
        let response = match self.transport.send(&prepared.request) {
            Ok(response) => response,
            Err(failure) => return Err(network_error(&failure)),
        };
        if (300..=399).contains(&response.status) {
            return Err(WebhookError::with_reason(
                NO_HTTP_STATUS,
                codes::REDIRECT_REFUSED,
                REASON_REDIRECT,
                "the document response is a redirect",
            ));
        }
        document_verdict(&DocumentResponse {
            status: response.status,
            body: &response.body,
            declared_length: response.declared_length,
            overflow: response.overflow,
        })
    }
}

impl DocumentFetcher for WebhookDocumentFetcher {
    /// Fetches and judges the document of `canonical_url`'s origin
    /// (spec 06 R5.9, R5.12).
    fn fetch(&self, canonical_url: &str) -> Result<ReceiverDocument, WebhookError> {
        self.fetch_receiver_document(canonical_url)
    }
}

/// Builds the `invalid_callback_url` rejection of a canonical url that does
/// not parse (spec 06 R5.9, R6.2).
fn invalid_canonical_url() -> WebhookError {
    WebhookError::with_reason(
        BAD_REQUEST,
        INVALID_CALLBACK_URL,
        REASON_URL,
        "the canonical url is not acceptable",
    )
}

/// Maps one R1.9 transport category to its error code (spec 06 R1.9, R5.12).
fn network_error(failure: &TransportFailure) -> WebhookError {
    let last_error = failure.error;
    WebhookError::with_reason(
        NO_HTTP_STATUS,
        last_error.as_str(),
        last_error.as_str(),
        "the request failed before a response was read",
    )
}
