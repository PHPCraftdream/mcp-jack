use super::*;

/// Blocking bridge from the SDK's synchronous [`Transport`] to a tower
/// `Service` as produced by the packaged `JackLayer` (feature `server-http`).
struct LayerTransport<S> {
    service: Arc<std::sync::Mutex<S>>,
}

impl<S> Transport for LayerTransport<S>
where
    S: tower::Service<
            http::Request<http_body_util::Full<bytes::Bytes>>,
            Response = http::Response<http_body_util::Full<bytes::Bytes>>,
            Error = std::convert::Infallible,
        > + Send
        + 'static,
{
    fn round_trip(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
        use http_body_util::BodyExt as _;
        let target = mcp_jack::client::url::request_target(&req.url)
            .map_err(|e| TransportError::Client(e.to_string()))?;
        let mut builder = http::Request::builder()
            .method(req.method.as_str())
            .uri(target);
        for (name, value) in &req.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let http_req = builder
            .body(http_body_util::Full::new(bytes::Bytes::from(
                req.body.clone(),
            )))
            .map_err(|e| TransportError::Client(e.to_string()))?;

        let mut guard = match self.service.lock() {
            Ok(guard) => guard,
            Err(_) => {
                return Err(TransportError::Client(
                    "jack service lock poisoned".to_string(),
                ));
            }
        };
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        match tower::Service::poll_ready(&mut *guard, &mut cx) {
            std::task::Poll::Ready(Ok(())) => {}
            std::task::Poll::Ready(Err(e)) => match e {},
            std::task::Poll::Pending => {
                return Err(TransportError::Client("jack service not ready".to_string()));
            }
        }
        futures::executor::block_on(async {
            let response = tower::Service::call(&mut *guard, http_req).await;
            match response {
                Ok(res) => {
                    let status = res.status().as_u16();
                    let mut headers = Vec::new();
                    for (name, value) in res.headers() {
                        let value = value.to_str().map_err(|_| {
                            TransportError::Client("non-UTF-8 response header value".to_string())
                        })?;
                        headers.push((name.as_str().to_string(), value.to_string()));
                    }
                    let body = res
                        .into_body()
                        .collect()
                        .await
                        .map_err(|_| {
                            TransportError::Client("response body read failed".to_string())
                        })?
                        .to_bytes();
                    Ok(HttpResponse {
                        status,
                        headers,
                        body: body.to_vec(),
                    })
                }
                Err(e) => match e {},
            }
        })
    }
}

pub(super) fn section_e(
    client_signer: Arc<dyn Signer>,
    wrong_pin: &ClientSigningKey,
) -> Result<(), String> {
    use bytes::Bytes;
    use ed25519_dalek::SigningKey;
    use http_body_util::Full;
    use mcp_jack::server::http::{HandlerConfig, JackLayer};
    use std::convert::Infallible;
    use tower::Layer as _;

    eprintln!("smoke: server-http drives the real packaged adapter");
    // The SDK deliberately exposes no seed export, so the consumer's service
    // key must come from its own randomness source.
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("os seed failed: {e}"))?;
    let service_key = SigningKey::from_bytes(&seed);
    let service_pub = *service_key.verifying_key().as_bytes();

    let state = Arc::new(MemoryState::new());
    register(
        &state,
        RegistryEntry {
            kid: client_signer.kid().to_string(),
            public_key: encode_b64url(&client_signer.public_key()),
            name: "consumer-smoke".to_string(),
            ..Default::default()
        },
    )?;
    let admin_key = ClientSigningKey::generate()
        .map_err(|e| format!("admin client key generate failed: {e}"))?;
    register(
        &state,
        RegistryEntry {
            kid: admin_key.kid().to_string(),
            public_key: encode_b64url(&admin_key.public_key()),
            name: "consumer-admin".to_string(),
            admin: true,
            ..Default::default()
        },
    )?;
    let verifier = Arc::new(verifier_for(Arc::clone(&state))?);
    let layer = JackLayer::new(HandlerConfig {
        verifier,
        server_key: service_key,
        max_body_bytes: 0,
        max_response_bytes: 0,
    });
    // The layer verifies and forwards; the wrapped application owns ordinary
    // MCP authorization and reads the immutable verified identity extension.
    let expected_kid = client_signer.kid().to_string();
    let admin_kid = admin_key.kid().to_string();
    let service = layer.layer(tower::service_fn(
        move |req: http::Request<Full<Bytes>>| {
            let expected_kid = expected_kid.clone();
            let admin_kid = admin_kid.clone();
            async move {
                let (parts, _body) = req.into_parts();
                let identity = parts.extensions.get::<VerifiedIdentity>().cloned();
                let authorized = match (parts.uri.path(), identity.as_ref()) {
                    ("/mcp", Some(identity)) => {
                        identity.kid() == expected_kid.as_str()
                            && identity.name() == "consumer-smoke"
                            && !identity.admin()
                    }
                    ("/mcp/admin", Some(identity)) => {
                        identity.kid() == admin_kid.as_str()
                            && identity.name() == "consumer-admin"
                            && identity.admin()
                    }
                    _ => false,
                };
                let (status, response_body) = if authorized {
                    (
                        http::StatusCode::OK,
                        Bytes::from_static(
                            br#"{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"echoed":true}}}"#,
                        ),
                    )
                } else {
                    (
                        http::StatusCode::FORBIDDEN,
                        Bytes::from_static(
                            br#"{"error":{"code":"consumer_forbidden","message":"application authorization denied"}}"#,
                        ),
                    )
                };
                Ok::<_, Infallible>(
                    http::Response::builder()
                        .status(status)
                        .header("Content-Type", "application/json")
                        .body(Full::new(response_body))
                        .expect("static application response is valid"),
                )
            }
        },
    ));
    let layer_transport: Arc<dyn Transport> = Arc::new(LayerTransport {
        service: Arc::new(std::sync::Mutex::new(service)),
    });

    // Happy path: the signed request flows through the real adapter and the
    // signed response verifies against the service key.
    let cfg = rpc::Config {
        base_url: BASE_URL.to_string(),
        aud: AUD.to_string(),
        signer: Arc::clone(&client_signer),
        server_key: service_pub,
        transport: Arc::clone(&layer_transport),
        now: Some(Arc::new(|| NOW)),
        nonce: None,
        window_seconds: 0,
    };
    let client = rpc::Client::new(cfg).map_err(|e| format!("client build failed: {e}"))?;
    let value = client
        .call_tool_raw_str(TOOL, Some("{}"))
        .map_err(|e| format!("adapter call failed: {e}"))?;
    check(
        matches!(value.get("echoed"), Some(v) if v.as_bool() == Some(true)),
        "adapter structuredContent.echoed must be true",
    )?;

    // The application checks its protected route from the verifier's typed
    // extension, not from request-supplied identity fields. The POST body
    // claims admin=true but the non-admin identity is still refused.
    let admin_route_cfg = rpc::Config {
        base_url: ADMIN_URL.to_string(),
        aud: AUD.to_string(),
        signer: Arc::clone(&client_signer),
        server_key: service_pub,
        transport: Arc::clone(&layer_transport),
        now: Some(Arc::new(|| NOW)),
        nonce: None,
        window_seconds: 0,
    };
    let admin_route_client = rpc::Client::new(admin_route_cfg)
        .map_err(|e| format!("admin-route client build failed: {e}"))?;
    let err = expect_client_err(
        admin_route_client.call_tool_raw_str(TOOL, Some(r#"{"identity":{"admin":true}}"#)),
        "non-admin application route must be denied",
    )?;
    check(
        matches!(
            &err,
            ClientErr::Http(http)
                if http.status == 403 && http.code == "consumer_forbidden"
        ),
        "application-owned admin operation must be denied using verified identity",
    )?;

    // A separately registered administrator is allowed by the consumer's own
    // route policy; the same protected endpoint then reaches the application.
    let admin_signer: Arc<dyn Signer> = Arc::new(admin_key);
    let admin_cfg = rpc::Config {
        base_url: ADMIN_URL.to_string(),
        aud: AUD.to_string(),
        signer: admin_signer,
        server_key: service_pub,
        transport: Arc::clone(&layer_transport),
        now: Some(Arc::new(|| NOW)),
        nonce: None,
        window_seconds: 0,
    };
    let admin_client =
        rpc::Client::new(admin_cfg).map_err(|e| format!("admin client build failed: {e}"))?;
    let admin_value = admin_client
        .call_tool_raw_str(TOOL, Some("{}"))
        .map_err(|e| format!("application admin-route call failed: {e}"))?;
    check(
        matches!(admin_value.get("echoed"), Some(v) if v.as_bool() == Some(true)),
        "application admin operation must accept a verified administrator",
    )?;

    // Wrong server pin through the same adapter: response verification must
    // fail with unknown_server_key.
    let cfg_wrong = rpc::Config {
        base_url: BASE_URL.to_string(),
        aud: AUD.to_string(),
        signer: Arc::clone(&client_signer),
        server_key: wrong_pin.public_key(),
        transport: Arc::clone(&layer_transport),
        now: Some(Arc::new(|| NOW)),
        nonce: None,
        window_seconds: 0,
    };
    let client_wrong =
        rpc::Client::new(cfg_wrong).map_err(|e| format!("client build failed: {e}"))?;
    let err = expect_client_err(
        client_wrong.call_tool_raw_str(TOOL, Some("{}")),
        "adapter wrong-pinned call must fail",
    )?;
    check(
        matches!(&err, ClientErr::Protocol(j) if j.code == "unknown_server_key"),
        "adapter wrong-pinned client must fail with unknown_server_key",
    )?;

    // Tampered request body through the same adapter: verification rejects
    // with an unsigned 401, surfaced as Unauthenticated.
    let tamper_transport = Arc::new(BodyTamperTransport {
        inner: Arc::clone(&layer_transport),
    });
    let cfg_tamper = rpc::Config {
        base_url: BASE_URL.to_string(),
        aud: AUD.to_string(),
        signer: Arc::clone(&client_signer),
        server_key: service_pub,
        transport: tamper_transport,
        now: Some(Arc::new(|| NOW)),
        nonce: None,
        window_seconds: 0,
    };
    let client_tamper =
        rpc::Client::new(cfg_tamper).map_err(|e| format!("client build failed: {e}"))?;
    let err = expect_client_err(
        client_tamper.call_tool_raw_str(TOOL, Some("{}")),
        "adapter tampered call must fail",
    )?;
    check(
        matches!(err, ClientErr::Unauthenticated(_)),
        "adapter tampered call must fail with the Unauthenticated variant",
    )
}
