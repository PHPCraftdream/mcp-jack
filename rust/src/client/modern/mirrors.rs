//! `_meta` and header mirrors of one modern request (spec 04 section 6, `C1`
//! and `C2`).
//!
//! `build_mirrors` produces the versioned `params._meta` object every modern
//! request carries and the mirror headers that repeat the version, the method
//! and the encoded target name, in the order `C2` fixes. The `Mcp-Param-*`
//! projection of `C6` is a separate step and never appears here.

use serde_json::{Map, Value};

use crate::modern::{
    encode_header_value, name_source, NameSource, META_CLIENT_CAPABILITIES_KEY,
    META_CLIENT_INFO_KEY, META_VERSION_KEY,
};

/// The request metadata of one modern request (spec 04 `C1`) and its mirror
/// headers in `C2` order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mirrors {
    /// `params._meta`: the protocol version and the client capabilities.
    pub meta: Value,
    /// `MCP-Protocol-Version`, `Mcp-Method`, then `Mcp-Name` when the method has
    /// a name source field — never `Mcp-Param-*` (that is `C6`).
    pub headers: Vec<(String, String)>,
}

/// Why a modern request could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorError {
    /// The method has a name source field but the body value is absent or not
    /// a JSON string, so there is nothing to mirror (spec 04 `S6`).
    NameSourceMissing {
        /// The request method.
        method: String,
        /// The source member, `"name"` or `"uri"`.
        field: &'static str,
    },
}

impl std::fmt::Display for MirrorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MirrorError::NameSourceMissing { method, field } => {
                write!(f, "jack client: {method} requires a string params.{field}")
            }
        }
    }
}

impl std::error::Error for MirrorError {}

/// Builds the `_meta` object and the mirror headers of one modern request:
/// the version and the empty client capabilities under their `_meta` keys,
/// then `MCP-Protocol-Version`, `Mcp-Method` and — for the methods with a name
/// source field — `Mcp-Name` carrying the encoded source value (spec 04 `C1`,
/// `C2`).
///
/// A `params` that is not a JSON object is treated as an empty one, so a
/// method with a source field fails with
/// [`MirrorError::NameSourceMissing`] and any other method simply adds no
/// name header.
pub fn build_mirrors(version: &str, method: &str, params: &Value) -> Result<Mirrors, MirrorError> {
    let empty = Map::new();
    let members = params.as_object().unwrap_or(&empty);

    let mut meta = Map::new();
    meta.insert(
        META_VERSION_KEY.to_owned(),
        Value::String(version.to_owned()),
    );
    meta.insert(
        META_CLIENT_CAPABILITIES_KEY.to_owned(),
        Value::Object(Map::new()),
    );

    let mut headers = vec![
        ("MCP-Protocol-Version".to_owned(), version.to_owned()),
        ("Mcp-Method".to_owned(), method.to_owned()),
    ];
    if let Some(source) = name_source(method) {
        let field = match source {
            NameSource::Name => "name",
            NameSource::Uri => "uri",
        };
        let text = members.get(field).and_then(Value::as_str).ok_or_else(|| {
            MirrorError::NameSourceMissing {
                method: method.to_owned(),
                field,
            }
        })?;
        headers.push(("Mcp-Name".to_owned(), encode_header_value(text)));
    }

    Ok(Mirrors {
        meta: Value::Object(meta),
        headers,
    })
}

/// Adds `io.modelcontextprotocol/clientInfo` = `{"name": name, "version": version}`
/// to a `_meta` object (spec 04 `C1`: the member SHOULD be present). Does
/// nothing when `meta` is not a JSON object.
pub fn add_client_info(meta: &mut Value, name: &str, version: &str) {
    let Some(members) = meta.as_object_mut() else {
        return;
    };
    let mut info = Map::new();
    info.insert("name".to_owned(), Value::String(name.to_owned()));
    info.insert("version".to_owned(), Value::String(version.to_owned()));
    members.insert(META_CLIENT_INFO_KEY.to_owned(), Value::Object(info));
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Renders headers as a vector of `&str` pairs for compact assertions.
    fn pairs(headers: &[(String, String)]) -> Vec<(&str, &str)> {
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect()
    }

    #[test]
    fn builds_meta_and_name_headers() {
        let built = build_mirrors("2026-07-28", "tools/call", &json!({"name": "get_weather"}))
            .expect("tools/call with a string name");
        assert_eq!(
            built.meta,
            json!({
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            })
        );
        assert_eq!(
            pairs(&built.headers),
            [
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "tools/call"),
                ("Mcp-Name", "get_weather"),
            ]
        );
    }

    #[test]
    fn name_header_uses_the_sentinel_codec() {
        for (name, want) in [
            ("get weather/日本", "=?base64?Z2V0IHdlYXRoZXIv5pel5pys?="),
            ("", ""),
            ("=?base64?literal?=", "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="),
        ] {
            let built = build_mirrors("2026-07-28", "tools/call", &json!({ "name": name }))
                .expect("tools/call with a string name");
            assert_eq!(
                pairs(&built.headers),
                [
                    ("MCP-Protocol-Version", "2026-07-28"),
                    ("Mcp-Method", "tools/call"),
                    ("Mcp-Name", want),
                ],
                "name {name:?}"
            );
        }
    }

    #[test]
    fn resource_and_prompt_sources() {
        let read = build_mirrors(
            "2026-07-28",
            "resources/read",
            &json!({"uri": "file:///a b.json"}),
        )
        .expect("resources/read with a string uri");
        assert_eq!(
            pairs(&read.headers),
            [
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "resources/read"),
                ("Mcp-Name", "file:///a b.json"),
            ]
        );

        let get = build_mirrors("2026-07-28", "prompts/get", &json!({"name": "summarize"}))
            .expect("prompts/get with a string name");
        assert_eq!(
            pairs(&get.headers),
            [
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "prompts/get"),
                ("Mcp-Name", "summarize"),
            ]
        );
    }

    #[test]
    fn methods_without_a_name_source() {
        for method in ["server/discover", "events/list"] {
            let built = build_mirrors("2026-07-28", method, &json!({"name": "incident.created"}))
                .expect("no name source");
            assert_eq!(
                pairs(&built.headers),
                [
                    ("MCP-Protocol-Version", "2026-07-28"),
                    ("Mcp-Method", method)
                ],
                "{method}"
            );
        }
        let built = build_mirrors("2026-07-28", "server/discover", &json!({}))
            .expect("no name source needs no member");
        assert_eq!(
            pairs(&built.headers),
            [
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "server/discover"),
            ]
        );

        let built = build_mirrors(
            "2026-07-28",
            "events/subscribe",
            &json!({"name": "incident.created"}),
        )
        .expect("events/subscribe with a string name");
        assert_eq!(
            pairs(&built.headers),
            [
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "events/subscribe"),
                ("Mcp-Name", "incident.created"),
            ]
        );
    }

    #[test]
    fn missing_name_source_errors() {
        for params in [json!({}), json!({"name": 7})] {
            assert_eq!(
                build_mirrors("2026-07-28", "tools/call", &params),
                Err(MirrorError::NameSourceMissing {
                    method: "tools/call".to_owned(),
                    field: "name",
                }),
                "params {params}"
            );
        }
        assert_eq!(
            build_mirrors("2026-07-28", "resources/read", &json!({"uri": null})),
            Err(MirrorError::NameSourceMissing {
                method: "resources/read".to_owned(),
                field: "uri",
            })
        );
    }

    #[test]
    fn add_client_info_inserts_member() {
        let mut meta = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        });
        add_client_info(&mut meta, "mcp-jack", "0.1.0");
        assert_eq!(
            meta,
            json!({
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {"name": "mcp-jack", "version": "0.1.0"},
            })
        );
    }

    #[test]
    fn add_client_info_leaves_non_objects_alone() {
        for mut meta in [json!(null), json!("_meta"), json!([1, 2]), json!(7)] {
            let before = meta.clone();
            add_client_info(&mut meta, "mcp-jack", "0.1.0");
            assert_eq!(meta, before, "meta {before}");
        }
    }
}
