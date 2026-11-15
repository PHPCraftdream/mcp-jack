#![forbid(unsafe_code)]
//! Official rmcp MCP server for the jack e2e matrix: one `echo` tool served
//! over Streamable HTTP in stateless JSON-response mode on the Unix socket
//! (argv[1]) prepared by the e2e driver.

use std::io::Write;

use rmcp::schemars;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters, model::*, service::RequestContext, tool, tool_handler,
    tool_router,
};

/// Arguments for the `echo` tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct EchoArgs {
    /// Text echoed back verbatim.
    text: String,
}

/// Minimal MCP server hosting the single `echo` tool.
struct EchoServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl EchoServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Echo the given text back verbatim.")]
    fn echo(
        &self,
        Parameters(EchoArgs { text }): Parameters<EchoArgs>,
    ) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }
}

#[tool_handler]
impl ServerHandler for EchoServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_protocol_version(ProtocolVersion::V_2025_11_25)
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        log_parts(&context);
        context.peer.set_peer_info(request.clone());
        self.negotiate_initialize(&request)
    }
}

// Append one line describing the HTTP initialize request when E2E_SERVER_LOG
// is set; silently skip otherwise or on any write failure.
fn log_parts(context: &RequestContext<RoleServer>) {
    let Ok(path) = std::env::var("E2E_SERVER_LOG") else {
        return;
    };
    let Some(parts) = context.extensions.get::<axum::http::request::Parts>() else {
        return;
    };
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let accept = header("accept");
    let content_type = header("content-type");
    let mcp_protocol_version = header("mcp-protocol-version");
    let record = serde_json::json!({
        "kind": "initialize",
        "method": parts.method.as_str(),
        "path": parts.uri.path(),
        "accept": accept,
        "content_type": content_type,
        "mcp_protocol_version": mcp_protocol_version,
    });
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{record}");
    }
}

fn set_socket_mode(path: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("chmod {path}: {error}"))
}

async fn shutdown_signal() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let socket_path = std::env::args().nth(1).ok_or("usage: mcp-e2e-rust-server SOCKET_PATH")?;
    let service = StreamableHttpService::new(
        || Ok(EchoServer::new()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true)
            .with_allowed_hosts(["upstream"]),
    );
    let router = axum::Router::new().nest_service("/mcp", service);
    let listener = tokio::net::UnixListener::bind(&socket_path)
        .map_err(|error| format!("bind {socket_path}: {error}"))?;
    set_socket_mode(&socket_path)?;
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|error| format!("serve: {error}"))?;
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}
