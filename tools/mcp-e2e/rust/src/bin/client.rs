#![forbid(unsafe_code)]
//! Official rmcp MCP client for the jack e2e matrix. Spawns the jack bridge
//! over stdio, negotiates protocol 2025-11-25, lists tools, calls `echo`
//! with a marker and prints exactly one JSON result line on stdout.

use rmcp::model::{CallToolRequestParams, ClientConfig, JsonObject, ProtocolVersion};
use rmcp::service::{serve_client_with_lifecycle, ClientLifecycleMode};
use rmcp::transport::TokioChildProcess;

const USAGE: &str = "usage: mcp-e2e-rust-client JACK_BIN CONFIG_PATH MARKER";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let jack_bin = std::env::args().nth(1).ok_or(USAGE)?;
    let config_path = std::env::args().nth(2).ok_or(USAGE)?;
    let marker = std::env::args().nth(3).ok_or(USAGE)?;

    let mut command = tokio::process::Command::new(&jack_bin);
    command.args(["bridge", "--config", config_path.as_str()]);
    let transport =
        TokioChildProcess::new(command).map_err(|error| format!("spawn bridge: {error}"))?;

    let mut config = ClientConfig::default();
    config.protocol_version = ProtocolVersion::V_2025_11_25;
    let client = serve_client_with_lifecycle(config, transport, ClientLifecycleMode::Initialize)
        .await
        .map_err(|error| format!("initialize: {error}"))?;

    let tools = client
        .list_tools(Default::default())
        .await
        .map_err(|error| format!("tools/list: {error}"))?;
    if !tools.tools.iter().any(|tool| tool.name == "echo") {
        return Err("tools/list: echo tool missing".to_string());
    }

    let mut arguments = JsonObject::new();
    arguments.insert("text".to_string(), serde_json::json!(marker));
    let params = CallToolRequestParams::new("echo").with_arguments(arguments);
    let result = client
        .call_tool(params)
        .await
        .map_err(|error| format!("tools/call: {error}"))?;
    let body =
        serde_json::to_string(&result).map_err(|error| format!("serialize result: {error}"))?;
    if result.is_error.unwrap_or(false) {
        return Err(format!("tools/call: isError: {body}"));
    }
    if !body.contains(&marker) {
        return Err(format!("tools/call: echo marker missing: {body}"));
    }

    client
        .cancel()
        .await
        .map_err(|error| format!("shutdown: {error}"))?;
    println!(r#"{{"ok":true,"client":"rust","echo_listed":true,"marker_found":true}}"#);
    Ok(())
}
