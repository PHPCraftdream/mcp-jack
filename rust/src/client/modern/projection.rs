//! `Mcp-Param-*` projection of one call (spec 04 section 6, `C6`) and the
//! catalogs that apply `C5`/`C11` to a received result.
//!
//! [`text_of_value`] is the type-to-text conversion of section 4 and
//! [`project_arguments`] turns the arguments of one call into the headers its
//! annotations describe, refusing the request when a value does not match its
//! annotated type. [`ToolCatalog`] and [`EventCatalog`] keep the definitions
//! that passed validation and report the ones they dropped, so an invalid
//! definition never turns a `tools/list` or `events/list` result into an error
//! response.
//!
//! The projection order of `C6` is the order in which [`collect_annotations`]
//! reports the annotations, i.e. the key order of `serde_json`'s map: members
//! are alphabetical because the `preserve_order` feature is not enabled, so
//! the document order of the `inputSchema` text is only observable through
//! that map order. No projection vector distinguishes the two:
//! `ann-project-order` is the only one with more than one header and its
//! schema declares `region`, `tenant`, `zone`, already alphabetical. No
//! order-preserving parser of the raw text is therefore provided here; true
//! document order would have to be handed in at the [`ToolCatalog`] /
//! [`EventCatalog`] boundary.

use serde_json::Value;

use crate::modern::{encode_header_value, SAFE_INT_MAX};

use super::annotations::{collect_annotations, validate_annotations, Annotation, AnnotationError};

/// The wire token of a refused projection (spec 04 `C6`).
const PROJECTION_REASON: &str = "header_projection_invalid_value";

/// Type-to-text of spec 04 section 4: the header text of a value of the
/// annotated JSON type, or `None` when the value does not match that type.
pub fn text_of_value(value: &Value, ty: &str) -> Option<String> {
    match ty {
        "string" => value.as_str().map(str::to_owned),
        "integer" => integer_text(value),
        "boolean" => match value {
            Value::Bool(true) => Some("true".to_owned()),
            Value::Bool(false) => Some("false".to_owned()),
            _ => None,
        },
        _ => None,
    }
}

/// The decimal text of a JSON number that is an integer within
/// +/-(2^53-1): no `+`, no leading zeros, no fraction and `0` for zero
/// (spec 04 section 4).
fn integer_text(value: &Value) -> Option<String> {
    let number = value.as_number()?;
    if let Some(integer) = number.as_i64() {
        return (integer.unsigned_abs() <= SAFE_INT_MAX as u64).then(|| integer.to_string());
    }
    if let Some(integer) = number.as_u64() {
        return (integer <= SAFE_INT_MAX as u64).then(|| integer.to_string());
    }
    let float = number.as_f64()?;
    if !float.is_finite() || float.fract() != 0.0 || float.abs() > SAFE_INT_MAX as f64 {
        return None;
    }
    // `-0.0` has no sign in the text form, so zero is spelled out.
    if float == 0.0 {
        return Some("0".to_owned());
    }
    Some(format!("{float:.0}"))
}

/// Why a projection was refused (spec 04 `C6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionError {
    /// The argument does not match the annotated type, so the client MUST NOT
    /// send the request.
    InvalidValue,
}

impl ProjectionError {
    /// The wire token, `"header_projection_invalid_value"` (spec 04 `C6`).
    pub fn as_str(&self) -> &'static str {
        match self {
            ProjectionError::InvalidValue => PROJECTION_REASON,
        }
    }
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for ProjectionError {}

/// Projects the arguments of one call onto `Mcp-Param-*` headers (spec 04
/// `C6`), in the key order of the schema's `properties` members: the
/// `serde_json` map order, alphabetical without `preserve_order`, which is the
/// only observable form of `C6`'s document order.
///
/// An annotation without a static `properties` path, an argument that is
/// absent and an argument whose value is `null` omit the header; any header
/// that is emitted has its text encoded by `C3`.
pub fn project_arguments(
    input_schema: &Value,
    arguments: &Value,
) -> Result<Vec<(String, String)>, ProjectionError> {
    project_annotations(&collect_annotations(input_schema), arguments)
}

/// Projects the annotations of one already-validated schema.
fn project_annotations(
    annotations: &[Annotation],
    arguments: &Value,
) -> Result<Vec<(String, String)>, ProjectionError> {
    let mut headers = Vec::new();
    for annotation in annotations {
        let Some(property_path) = annotation.property_path.as_ref() else {
            continue;
        };
        let Some(value) = read_path(arguments, property_path) else {
            continue;
        };
        let ty = annotation
            .schema
            .get("type")
            .and_then(Value::as_str)
            .ok_or(ProjectionError::InvalidValue)?;
        let text = text_of_value(value, ty).ok_or(ProjectionError::InvalidValue)?;
        let name = annotation
            .name
            .as_str()
            .ok_or(ProjectionError::InvalidValue)?;
        headers.push((format!("Mcp-Param-{name}"), encode_header_value(&text)));
    }
    Ok(headers)
}

/// Walks `arguments` along `property_path`: `None` when a step is absent, its
/// container is not a JSON object, or the value found is `null` (spec 04
/// `C6`).
fn read_path<'a>(arguments: &'a Value, property_path: &[String]) -> Option<&'a Value> {
    let mut current = arguments;
    for name in property_path {
        current = current.as_object()?.get(name)?;
    }
    (!current.is_null()).then_some(current)
}

/// One tool definition that passed `C5`.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolEntry {
    /// The tool name exactly as received.
    pub name: String,
    /// The `inputSchema` that passed [`validate_annotations`]; `null` when the
    /// definition carries no such member.
    pub input_schema: Value,
    /// The whole tool definition as received.
    pub definition: Value,
}

/// One event type descriptor that passed `C11`.
#[derive(Debug, Clone, PartialEq)]
pub struct EventTypeEntry {
    /// The event type name exactly as received.
    pub name: String,
    /// The `inputSchema` that passed [`validate_annotations`]; `null` when the
    /// descriptor carries no such member.
    pub input_schema: Value,
    /// The whole descriptor as received.
    pub descriptor: Value,
}

/// One tool definition excluded from a `tools/list` result, with the reason.
#[derive(Debug, Clone, PartialEq)]
pub struct ExcludedTool {
    /// The tool name, or the event type name for an `events/list` result.
    pub name: String,
    /// The first `C5` violation of the definition.
    pub reason: AnnotationError,
}

/// One definition that passed validation, before it becomes a catalog entry.
struct ValidDefinition {
    name: String,
    input_schema: Value,
    definition: Value,
}

/// Filters one `tools` or `events` member of a result through
/// [`validate_annotations`]: keeps the valid definitions in received order and
/// reports the others.
fn filter_definitions(result: &Value, key: &str) -> (Vec<ValidDefinition>, Vec<ExcludedTool>) {
    let mut valid = Vec::new();
    let mut excluded = Vec::new();
    let Some(items) = result.get(key).and_then(Value::as_array) else {
        return (valid, excluded);
    };
    for item in items {
        // A definition without a string name can never be called, so it is
        // dropped without a reason.
        let Some(name) = item.get("name").and_then(Value::as_str) else {
            continue;
        };
        let input_schema = item.get("inputSchema").cloned().unwrap_or(Value::Null);
        match validate_annotations(&input_schema) {
            Ok(()) => valid.push(ValidDefinition {
                name: name.to_owned(),
                input_schema,
                definition: item.clone(),
            }),
            Err(reason) => excluded.push(ExcludedTool {
                name: name.to_owned(),
                reason,
            }),
        }
    }
    (valid, excluded)
}

/// The `tools/list` result after `C5`: valid definitions only, invalid ones
/// excluded (never an error response).
#[derive(Debug, Clone, Default)]
pub struct ToolCatalog {
    entries: Vec<ToolEntry>,
    excluded: Vec<ExcludedTool>,
}

impl ToolCatalog {
    /// Filters one `tools/list` result: reads its `tools` array (a missing or
    /// non-array member yields an empty catalog) and keeps the definitions whose
    /// `inputSchema` passes `validate_annotations`. A definition without a
    /// string `name` is dropped entirely (it can never be called).
    pub fn from_tools_list(result: &Value) -> Self {
        let (valid, excluded) = filter_definitions(result, "tools");
        let entries = valid
            .into_iter()
            .map(|valid| ToolEntry {
                name: valid.name,
                input_schema: valid.input_schema,
                definition: valid.definition,
            })
            .collect();
        ToolCatalog { entries, excluded }
    }

    /// The valid definitions in received order.
    pub fn entries(&self) -> &[ToolEntry] {
        &self.entries
    }

    /// The definitions dropped by `C5`, in received order.
    pub fn excluded(&self) -> &[ExcludedTool] {
        &self.excluded
    }

    /// The entry of one tool name, or `None` when it is unknown or excluded.
    pub fn find(&self, tool: &str) -> Option<&ToolEntry> {
        self.entries.iter().find(|entry| entry.name == tool)
    }

    /// `C6` for one call: the `Mcp-Param-*` headers of `arguments`. A tool that
    /// is not in the catalog (unknown or excluded) projects nothing.
    pub fn project(
        &self,
        tool: &str,
        arguments: &Value,
    ) -> Result<Vec<(String, String)>, ProjectionError> {
        match self.find(tool) {
            Some(entry) => project_arguments(&entry.input_schema, arguments),
            None => Ok(Vec::new()),
        }
    }

    /// The valid definitions in received order: what the MCP layer must see
    /// instead of the raw result.
    pub fn definitions(&self) -> Vec<Value> {
        self.entries
            .iter()
            .map(|entry| entry.definition.clone())
            .collect()
    }
}

/// The `events/list` result after `C11`: valid event type descriptors only.
#[derive(Debug, Clone, Default)]
pub struct EventCatalog {
    entries: Vec<EventTypeEntry>,
    excluded: Vec<ExcludedTool>,
}

impl EventCatalog {
    /// Filters one `events/list` result: reads its `events` array, keeps the
    /// descriptors whose `inputSchema` passes `validate_annotations`, reports the
    /// others. A descriptor without a string `name` is dropped entirely.
    pub fn from_events_list(result: &Value) -> Self {
        let (valid, excluded) = filter_definitions(result, "events");
        let entries = valid
            .into_iter()
            .map(|valid| EventTypeEntry {
                name: valid.name,
                input_schema: valid.input_schema,
                descriptor: valid.definition,
            })
            .collect();
        EventCatalog { entries, excluded }
    }

    /// The valid descriptors in received order.
    pub fn entries(&self) -> &[EventTypeEntry] {
        &self.entries
    }

    /// The descriptors dropped by `C11`, in received order.
    pub fn excluded(&self) -> &[ExcludedTool] {
        &self.excluded
    }

    /// The entry of one event type name, or `None` when it is unknown or
    /// excluded.
    pub fn find(&self, event: &str) -> Option<&EventTypeEntry> {
        self.entries.iter().find(|entry| entry.name == event)
    }

    /// `C6` for one event type's arguments: the `Mcp-Param-*` headers of
    /// `arguments`. An event type that is not in the catalog (unknown or
    /// excluded) projects nothing.
    pub fn project(
        &self,
        event: &str,
        arguments: &Value,
    ) -> Result<Vec<(String, String)>, ProjectionError> {
        match self.find(event) {
            Some(entry) => project_arguments(&entry.input_schema, arguments),
            None => Ok(Vec::new()),
        }
    }
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

    /// A schema with one annotated property of the given type.
    fn one_property(kind: &str, header: &str) -> Value {
        json!({"type": "object", "properties": {"a": {"type": kind, "x-mcp-header": header}}})
    }

    #[test]
    fn text_of_value_table() {
        for (ty, value, want) in [
            ("string", json!("us-west1"), Some("us-west1")),
            ("string", json!(""), Some("")),
            ("integer", json!(42), Some("42")),
            ("integer", json!(-7), Some("-7")),
            ("integer", json!(0), Some("0")),
            ("integer", json!(1e3), Some("1000")),
            (
                "integer",
                json!(9_007_199_254_740_991_i64),
                Some("9007199254740991"),
            ),
            (
                "integer",
                json!(-9_007_199_254_740_991_i64),
                Some("-9007199254740991"),
            ),
            ("boolean", json!(true), Some("true")),
            ("boolean", json!(false), Some("false")),
        ] {
            assert_eq!(text_of_value(&value, ty).as_deref(), want, "{ty} {value}");
        }
    }

    #[test]
    fn text_of_value_mismatches() {
        for (ty, value) in [
            ("integer", json!(1.5)),
            ("integer", json!(9_007_199_254_740_992_i64)),
            ("integer", json!(-9_007_199_254_740_992_i64)),
            ("integer", json!("42")),
            ("integer", json!(true)),
            ("integer", json!(null)),
            ("string", json!(7)),
            ("string", json!({"a": 1})),
            ("string", json!(["a"])),
            ("boolean", json!(0)),
            ("boolean", json!("true")),
            ("number", json!(1)),
            ("", json!("a")),
        ] {
            assert_eq!(text_of_value(&value, ty), None, "{ty} {value}");
        }
    }

    #[test]
    fn projects_a_present_string_argument() {
        let headers = project_arguments(&one_property("string", "X-A"), &json!({"a": "us-west1"}))
            .expect("valid string");
        assert_eq!(pairs(&headers), [("Mcp-Param-X-A", "us-west1")]);
    }

    #[test]
    fn projects_integer_and_boolean_arguments() {
        let headers = project_arguments(&one_property("integer", "X-A"), &json!({"a": 42}))
            .expect("valid integer");
        assert_eq!(pairs(&headers), [("Mcp-Param-X-A", "42")]);

        let headers = project_arguments(&one_property("integer", "X-A"), &json!({"a": -7}))
            .expect("valid negative integer");
        assert_eq!(pairs(&headers), [("Mcp-Param-X-A", "-7")]);

        let headers = project_arguments(&one_property("integer", "X-A"), &json!({"a": 0}))
            .expect("valid zero");
        assert_eq!(pairs(&headers), [("Mcp-Param-X-A", "0")]);

        let headers = project_arguments(&one_property("boolean", "X-A"), &json!({"a": false}))
            .expect("valid false");
        assert_eq!(pairs(&headers), [("Mcp-Param-X-A", "false")]);
    }

    #[test]
    fn encodes_empty_and_sentinel_values() {
        let headers = project_arguments(&one_property("string", "X-A"), &json!({"a": ""}))
            .expect("empty string");
        assert_eq!(pairs(&headers), [("Mcp-Param-X-A", "")]);

        let headers =
            project_arguments(&one_property("string", "X-A"), &json!({"a": "Hello, 世界"}))
                .expect("non-ASCII string");
        assert_eq!(
            pairs(&headers),
            [("Mcp-Param-X-A", "=?base64?SGVsbG8sIOS4lueVjA==?=")]
        );
    }

    #[test]
    fn projects_a_nested_property_path() {
        let schema = json!({
            "properties": {"a": {"properties": {"b": {"type": "string", "x-mcp-header": "X-B"}}}},
        });
        let headers =
            project_arguments(&schema, &json!({"a": {"b": "deep"}})).expect("nested string");
        assert_eq!(pairs(&headers), [("Mcp-Param-X-B", "deep")]);
    }

    #[test]
    fn omits_absent_null_and_null_intermediate_arguments() {
        let schema = one_property("string", "X-A");
        for arguments in [
            json!({}),
            json!({"a": null}),
            json!({"b": "x"}),
            json!([1]),
            json!(null),
        ] {
            let headers = project_arguments(&schema, &arguments).expect("nothing to project");
            assert!(headers.is_empty(), "{arguments}");
        }

        let nested = json!({
            "properties": {"a": {"properties": {"b": {"type": "string", "x-mcp-header": "X-B"}}}},
        });
        for arguments in [json!({"a": null}), json!({"a": "text"}), json!({"a": {}})] {
            let headers = project_arguments(&nested, &arguments).expect("nothing to project");
            assert!(headers.is_empty(), "{arguments}");
        }
    }

    #[test]
    fn projects_in_property_key_order() {
        let schema = json!({
            "properties": {
                "Tenant": {"type": "string", "x-mcp-header": "Tenant"},
                "Region": {"type": "string", "x-mcp-header": "Region"},
                "Zone": {"type": "boolean", "x-mcp-header": "Zone"},
            },
        });
        let arguments = json!({"Zone": true, "Tenant": "acme", "Region": "eu"});
        let headers = project_arguments(&schema, &arguments).expect("three values");
        assert_eq!(
            pairs(&headers),
            [
                ("Mcp-Param-Region", "eu"),
                ("Mcp-Param-Tenant", "acme"),
                ("Mcp-Param-Zone", "true"),
            ],
            "the order is the schema's serde_json property key order, not the \
             arguments' order: it is the only observable form of C6 document order"
        );
    }

    #[test]
    fn projects_only_the_annotations_whose_arguments_are_present() {
        let schema = json!({
            "properties": {
                "a": {"type": "string", "x-mcp-header": "X-A"},
                "b": {"type": "string", "x-mcp-header": "X-B"},
                "c": {"type": "string", "x-mcp-header": "X-C"},
            },
        });
        let headers = project_arguments(&schema, &json!({"a": "one", "c": "three"}))
            .expect("two present values");
        assert_eq!(
            pairs(&headers),
            [("Mcp-Param-X-A", "one"), ("Mcp-Param-X-C", "three")]
        );

        let headers = project_arguments(&schema, &json!({"b": null})).expect("nothing present");
        assert!(headers.is_empty());
    }

    #[test]
    fn refuses_values_that_do_not_match_the_annotated_type() {
        for (schema, arguments) in [
            (one_property("integer", "X-A"), json!({"a": "42"})),
            (one_property("integer", "X-A"), json!({"a": 1.5})),
            (
                one_property("integer", "X-A"),
                json!({"a": 9_007_199_254_740_992_i64}),
            ),
            (one_property("boolean", "X-A"), json!({"a": "true"})),
            (one_property("string", "X-A"), json!({"a": {"a": 1}})),
        ] {
            assert_eq!(
                project_arguments(&schema, &arguments),
                Err(ProjectionError::InvalidValue),
                "{arguments}"
            );
        }
    }

    #[test]
    fn refuses_a_missing_or_non_string_type_and_name() {
        let schemas = [
            json!({"properties": {"a": {"x-mcp-header": "X-A"}}}),
            json!({"properties": {"a": {"type": ["string"], "x-mcp-header": "X-A"}}}),
            json!({"properties": {"a": {"type": "string", "x-mcp-header": 7}}}),
        ];
        for schema in schemas {
            assert_eq!(
                project_arguments(&schema, &json!({"a": "text"})),
                Err(ProjectionError::InvalidValue),
                "{schema}"
            );
        }
    }

    #[test]
    fn never_produces_mirror_headers() {
        let schema = json!({
            "properties": {
                "a": {"type": "string", "x-mcp-header": "X-A"},
                "b": {"type": "string", "x-mcp-header": "X-B"},
            },
        });
        let headers =
            project_arguments(&schema, &json!({"a": "one", "b": "two"})).expect("two values");
        for (name, _) in &headers {
            assert!(name.starts_with("Mcp-Param-"), "{name}");
        }
    }

    #[test]
    fn error_token_and_display() {
        assert_eq!(
            ProjectionError::InvalidValue.as_str(),
            "header_projection_invalid_value"
        );
        assert_eq!(
            ProjectionError::InvalidValue.to_string(),
            "header_projection_invalid_value"
        );
    }

    #[test]
    fn tool_catalog_keeps_valid_tools_and_reports_the_rest() {
        let result = json!({
            "tools": [
                {
                    "name": "weather",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"region": {"type": "string", "x-mcp-header": "Region"}},
                    },
                },
                {
                    "name": "broken",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"count": {"type": "number", "x-mcp-header": "Count"}},
                    },
                },
                {
                    "name": "clock",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"ticks": {"type": "integer", "x-mcp-header": "Ticks"}},
                    },
                },
            ],
        });
        let catalog = ToolCatalog::from_tools_list(&result);
        assert_eq!(catalog.entries().len(), 2);
        assert_eq!(
            catalog.excluded(),
            [ExcludedTool {
                name: "broken".to_owned(),
                reason: AnnotationError::TypeNotPrimitive,
            }]
        );
        assert_eq!(catalog.definitions().len(), 2);
        assert!(catalog.find("broken").is_none());
        assert_eq!(
            catalog.project("broken", &json!({"count": 1})),
            Ok(Vec::new())
        );
        assert_eq!(
            catalog.project("weather", &json!({"region": "eu"})),
            Ok(vec![("Mcp-Param-Region".to_owned(), "eu".to_owned())])
        );
    }

    #[test]
    fn tool_catalog_ignores_malformed_results() {
        for result in [
            json!({}),
            json!({"tools": null}),
            json!({"tools": {}}),
            json!({"tools": [7, {"inputSchema": {}}, {"name": 7}]}),
            json!([]),
        ] {
            let catalog = ToolCatalog::from_tools_list(&result);
            assert!(catalog.entries().is_empty(), "{result}");
            assert!(catalog.excluded().is_empty(), "{result}");
            assert!(catalog.definitions().is_empty(), "{result}");
        }
    }

    #[test]
    fn event_catalog_projects_valid_descriptors_only() {
        let result = json!({
            "events": [
                {
                    "name": "incident.created",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"tenant": {"type": "string", "x-mcp-header": "Tenant"}},
                    },
                },
                {
                    "name": "incident.broken",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"payload": {"type": "object", "x-mcp-header": "Payload"}},
                    },
                },
                {"name": 7, "inputSchema": {}},
            ],
        });
        let catalog = EventCatalog::from_events_list(&result);
        assert_eq!(catalog.entries().len(), 1);
        assert_eq!(
            catalog.excluded(),
            [ExcludedTool {
                name: "incident.broken".to_owned(),
                reason: AnnotationError::TypeNotPrimitive,
            }]
        );

        let valid = catalog.find("incident.created").expect("valid descriptor");
        assert_eq!(valid.name, "incident.created");
        assert_eq!(
            catalog.project("incident.created", &json!({"tenant": "acme"})),
            Ok(vec![("Mcp-Param-Tenant".to_owned(), "acme".to_owned())])
        );
        assert_eq!(
            catalog.project("incident.broken", &json!({"payload": {}})),
            Ok(Vec::new())
        );
        assert!(catalog
            .project("incident.created", &json!({}))
            .expect("no argument")
            .is_empty());
    }
}
