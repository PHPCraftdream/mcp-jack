//! `x-mcp-header` annotations of one `inputSchema` and their validation
//! (spec 04 section 6, `C5`).
//!
//! [`collect_annotations`] is the structural traversal: it carries whether the
//! current node is a schema (its members are keywords) or a name map (its
//! members are property, pattern, definition or schema names), so a member
//! literally named `x-mcp-header` inside a name map is a property name and not
//! an annotation. [`validate_annotations`] applies the closed reason list of
//! `C5` in the fixed rule order of the reference implementation and reports the
//! first hit. Projection (`C6`) is a separate step and never appears here.

use serde_json::Value;

use crate::modern::{is_token, SAFE_INT_MAX};

/// The keyword that marks a property schema as an annotated argument.
const ANNOTATION_KEY: &str = "x-mcp-header";

/// One `x-mcp-header` annotation found by the structural traversal of an
/// `inputSchema` (spec 04 `C5`).
#[derive(Debug, Clone, PartialEq)]
pub struct Annotation {
    /// Member names from the schema root to the schema node that carries the
    /// `x-mcp-header` keyword.
    ///
    /// `serde_json` is built here without `preserve_order`, so members are
    /// visited in the alphabetical order of its map rather than in declaration
    /// order; that map order is what "document order" means for this module.
    pub path: Vec<String>,
    /// The property names along the path when the path is `properties`, name,
    /// `properties`, name, ...; `None` when the annotation is not statically
    /// reachable (spec 04 `C5`).
    pub property_path: Option<Vec<String>>,
    /// The annotation value exactly as written.
    pub name: Value,
    /// The annotated property schema (the node that carries the keyword).
    pub schema: Value,
}

/// The closed reason list of spec 04 `C5`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationError {
    /// The annotation value is not a JSON string.
    NameNotString,
    /// The annotation value is the empty string.
    NameEmpty,
    /// The annotation value contains a character below 0x20 or exactly U+007F,
    /// including CR and LF.
    NameControl,
    /// The annotation value fails `1*tchar` (RFC 9110 section 5.6.2).
    NameNotToken,
    /// The annotation value is case-insensitively equal to another
    /// `x-mcp-header` value in the same `inputSchema`.
    NameDuplicate,
    /// The annotation is not on a property reachable from the schema root
    /// through `properties` member names alone.
    NotStaticallyReachable,
    /// The annotated property's `type` is not exactly `string`, `integer` or
    /// `boolean`.
    TypeNotPrimitive,
    /// The annotated property is an `integer` with `minimum` below -(2^53-1) or
    /// `maximum` above 2^53-1.
    IntegerRangeInvalid,
}

impl AnnotationError {
    /// The wire token, e.g. `"annotation_name_not_token"` (spec 04 `C5`).
    pub fn as_str(&self) -> &'static str {
        match self {
            AnnotationError::NameNotString => "annotation_name_not_string",
            AnnotationError::NameEmpty => "annotation_name_empty",
            AnnotationError::NameControl => "annotation_name_control",
            AnnotationError::NameNotToken => "annotation_name_not_token",
            AnnotationError::NameDuplicate => "annotation_name_duplicate",
            AnnotationError::NotStaticallyReachable => "annotation_not_statically_reachable",
            AnnotationError::TypeNotPrimitive => "annotation_type_not_primitive",
            AnnotationError::IntegerRangeInvalid => "annotation_integer_range_invalid",
        }
    }
}

impl std::fmt::Display for AnnotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for AnnotationError {}

/// Reports whether `path` is a `properties` chain from the schema root and
/// returns the property names along it (spec 04 `C5`). An empty property name
/// is legal; the root itself, an odd length and any other segment are not.
fn static_property_path(path: &[String]) -> Option<Vec<String>> {
    if path.len() < 2 || !path.len().is_multiple_of(2) {
        return None;
    }
    if path.iter().step_by(2).any(|member| member != "properties") {
        return None;
    }
    Some(path.iter().skip(1).step_by(2).cloned().collect())
}

/// Records an annotation of `node` at `path`.
fn push_annotation(out: &mut Vec<Annotation>, node: &Value, path: &[String]) {
    out.push(Annotation {
        path: path.to_vec(),
        property_path: static_property_path(path),
        name: node.get(ANNOTATION_KEY).cloned().unwrap_or(Value::Null),
        schema: node.clone(),
    });
}

/// Collects every annotation of `input_schema` in depth-first document order:
/// `serde_json`'s map order, which is alphabetical here because the
/// `preserve_order` feature is not enabled.
pub fn collect_annotations(input_schema: &Value) -> Vec<Annotation> {
    let mut out = Vec::new();
    walk_schema(input_schema, &mut Vec::new(), &mut out);
    out
}

/// Walks a schema node: its members are keywords, and only here is a member
/// named `x-mcp-header` an annotation.
fn walk_schema(node: &Value, path: &mut Vec<String>, out: &mut Vec<Annotation>) {
    let Some(members) = node.as_object() else {
        return;
    };
    for (key, child) in members {
        match key.as_str() {
            ANNOTATION_KEY => push_annotation(out, node, path),
            keyword if is_name_map_keyword(keyword) => walk_name_map(child, path, out),
            keyword if is_schema_keyword(keyword) => walk_subschema(child, path, out),
            _ => walk_value(child, path, out),
        }
    }
}

/// Walks a name map: its members are property names, patterns, definition
/// names or schema keys, so each value is a schema again.
fn walk_name_map(node: &Value, path: &mut Vec<String>, out: &mut Vec<Annotation>) {
    let Some(members) = node.as_object() else {
        return;
    };
    for (name, child) in members {
        path.push(name.clone());
        walk_schema(child, path, out);
        path.pop();
    }
}

/// Walks the value of an applicator keyword: a schema, or an array of schemas.
fn walk_subschema(node: &Value, path: &mut Vec<String>, out: &mut Vec<Annotation>) {
    let Some(items) = node.as_array() else {
        walk_schema(node, path, out);
        return;
    };
    for (index, child) in items.iter().enumerate() {
        path.push(index.to_string());
        walk_subschema(child, path, out);
        path.pop();
    }
}

/// Walks the value of any other keyword: an array of values or an object whose
/// members are values, so a name inside it is never a keyword.
fn walk_value(node: &Value, path: &mut Vec<String>, out: &mut Vec<Annotation>) {
    if let Some(items) = node.as_array() {
        for (index, child) in items.iter().enumerate() {
            path.push(index.to_string());
            walk_value(child, path, out);
            path.pop();
        }
        return;
    }
    let Some(members) = node.as_object() else {
        return;
    };
    for (key, child) in members {
        if key.as_str() == ANNOTATION_KEY {
            push_annotation(out, node, path);
        } else {
            path.push(key.clone());
            walk_value(child, path, out);
            path.pop();
        }
    }
}

/// Reports whether `keyword` names a name map.
fn is_name_map_keyword(keyword: &str) -> bool {
    matches!(
        keyword,
        "properties" | "patternProperties" | "$defs" | "definitions" | "dependentSchemas"
    )
}

/// Reports whether `keyword` names a schema or an array of schemas.
fn is_schema_keyword(keyword: &str) -> bool {
    matches!(
        keyword,
        "allOf"
            | "anyOf"
            | "oneOf"
            | "not"
            | "if"
            | "then"
            | "else"
            | "items"
            | "prefixItems"
            | "contains"
            | "additionalProperties"
            | "additionalItems"
            | "propertyNames"
            | "unevaluatedProperties"
            | "unevaluatedItems"
    )
}

/// Validates every annotation of `input_schema` (spec 04 `C5`), reporting the
/// first failure in the fixed rule order of the reference implementation.
///
/// Each rule scans every annotation and the first hit of the first failing rule
/// wins: an annotation that violates several constraints reports the earliest
/// one.
pub fn validate_annotations(input_schema: &Value) -> Result<(), AnnotationError> {
    let annotations = collect_annotations(input_schema);

    if annotations.iter().any(|a| !a.name.is_string()) {
        return Err(AnnotationError::NameNotString);
    }
    if annotations.iter().any(|a| a.name.as_str() == Some("")) {
        return Err(AnnotationError::NameEmpty);
    }
    if annotations
        .iter()
        .any(|a| a.name.as_str().is_some_and(has_control))
    {
        return Err(AnnotationError::NameControl);
    }
    if annotations
        .iter()
        .any(|a| a.name.as_str().is_some_and(|name| !is_token(name)))
    {
        return Err(AnnotationError::NameNotToken);
    }

    let mut seen = std::collections::HashSet::new();
    for annotation in &annotations {
        let folded = annotation.name.as_str().unwrap_or_default().to_lowercase();
        if !seen.insert(folded) {
            return Err(AnnotationError::NameDuplicate);
        }
    }

    if annotations.iter().any(|a| a.property_path.is_none()) {
        return Err(AnnotationError::NotStaticallyReachable);
    }

    if annotations.iter().any(|a| !is_primitive_type(&a.schema)) {
        return Err(AnnotationError::TypeNotPrimitive);
    }

    if annotations.iter().any(|a| integer_range_invalid(&a.schema)) {
        return Err(AnnotationError::IntegerRangeInvalid);
    }

    Ok(())
}

/// Reports whether `name` contains a character below 0x20 or exactly U+007F
/// (spec 04 `C5`).
fn has_control(name: &str) -> bool {
    name.chars().any(|ch| ch < '\u{20}' || ch == '\u{7f}')
}

/// Reports whether the annotated schema's `type` is exactly `string`,
/// `integer` or `boolean` (spec 04 `C5`).
fn is_primitive_type(schema: &Value) -> bool {
    matches!(
        schema.get("type").and_then(Value::as_str),
        Some("string" | "integer" | "boolean")
    )
}

/// Reports whether an annotated `integer` bounds itself outside +/-(2^53-1):
/// `minimum` below the negative bound or `maximum` above the positive one,
/// absent bounds valid (spec 04 `C5`).
fn integer_range_invalid(schema: &Value) -> bool {
    if schema.get("type").and_then(Value::as_str) != Some("integer") {
        return false;
    }
    let bound = SAFE_INT_MAX as f64;
    let below_minimum = schema
        .get("minimum")
        .and_then(Value::as_f64)
        .is_some_and(|minimum| minimum < -bound);
    let above_maximum = schema
        .get("maximum")
        .and_then(Value::as_f64)
        .is_some_and(|maximum| maximum > bound);
    below_minimum || above_maximum
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// The property path of the single annotation of `schema`, for compact
    /// assertions.
    fn one_property_path(schema: &Value) -> Vec<String> {
        let mut annotations = collect_annotations(schema);
        assert_eq!(annotations.len(), 1, "exactly one annotation in {schema}");
        annotations
            .pop()
            .expect("one annotation")
            .property_path
            .expect("statically reachable")
    }

    /// The reason `schema` fails with, or `None` when it is valid.
    fn reason(schema: &Value) -> Option<AnnotationError> {
        validate_annotations(schema).err()
    }

    #[test]
    fn valid_primitive_property_annotations() {
        for kind in ["string", "integer", "boolean"] {
            let schema = json!({
                "type": "object",
                "properties": {"a": {"type": kind, "x-mcp-header": "X-A"}},
            });
            assert_eq!(reason(&schema), None, "{schema}");
            let annotations = collect_annotations(&schema);
            assert_eq!(annotations.len(), 1, "{schema}");
            assert_eq!(
                annotations[0],
                Annotation {
                    path: vec!["properties".to_owned(), "a".to_owned()],
                    property_path: Some(vec!["a".to_owned()]),
                    name: json!("X-A"),
                    schema: json!({"type": kind, "x-mcp-header": "X-A"}),
                },
                "{schema}"
            );
        }
    }

    #[test]
    fn valid_schema_without_annotations() {
        for schema in [
            json!({}),
            json!({"type": "object", "properties": {}}),
            json!({"properties": {"a": {"type": "string"}}}),
            json!([1, 2, 3]),
            json!(null),
        ] {
            assert!(collect_annotations(&schema).is_empty(), "{schema}");
            assert_eq!(reason(&schema), None, "{schema}");
        }
    }

    #[test]
    fn collects_nested_and_distinct_annotations() {
        let nested = json!({
            "properties": {"a": {"properties": {"b": {"type": "string", "x-mcp-header": "X-B"}}}},
        });
        assert_eq!(reason(&nested), None);
        assert_eq!(one_property_path(&nested), ["a", "b"]);

        let three = json!({
            "properties": {
                "a": {"type": "string", "x-mcp-header": "X-A"},
                "b": {"type": "integer", "x-mcp-header": "X-B"},
                "c": {"type": "boolean", "x-mcp-header": "X-C"},
            },
        });
        assert_eq!(reason(&three), None);
        let names: Vec<Value> = collect_annotations(&three)
            .into_iter()
            .map(|a| a.name)
            .collect();
        assert_eq!(names, [json!("X-A"), json!("X-B"), json!("X-C")]);
    }

    #[test]
    fn valid_annotation_beside_a_ref_sibling() {
        let schema = json!({
            "properties": {
                "a": {"$ref": "#/$defs/a", "type": "string", "x-mcp-header": "X-A"},
            },
            "$defs": {"a": {"type": "string"}},
        });
        assert_eq!(reason(&schema), None);
        assert_eq!(one_property_path(&schema), ["a"]);
    }

    #[test]
    fn x_mcp_header_member_of_a_name_map_is_a_property() {
        let bare = json!({
            "properties": {"x-mcp-header": {"type": "string"}},
        });
        assert!(collect_annotations(&bare).is_empty(), "{bare}");
        assert_eq!(reason(&bare), None, "{bare}");

        let annotated = json!({
            "properties": {"x-mcp-header": {"type": "string", "x-mcp-header": "X-Real"}},
        });
        assert_eq!(reason(&annotated), None);
        assert_eq!(one_property_path(&annotated), ["x-mcp-header"]);
    }

    #[test]
    fn empty_and_keyword_property_names() {
        let empty_name = json!({"properties": {"": {"type": "string", "x-mcp-header": "X-Empty"}}});
        assert_eq!(reason(&empty_name), None);
        assert_eq!(one_property_path(&empty_name), [""]);

        let properties_name = json!({
            "properties": {"properties": {"type": "string", "x-mcp-header": "X-Properties"}},
        });
        assert_eq!(reason(&properties_name), None);
        assert_eq!(one_property_path(&properties_name), ["properties"]);

        let nested_properties_name = json!({
            "properties": {
                "a": {"properties": {"properties": {"type": "string", "x-mcp-header": "X-P"}}},
            },
        });
        assert_eq!(reason(&nested_properties_name), None);
        assert_eq!(
            one_property_path(&nested_properties_name),
            ["a", "properties"]
        );
    }

    #[test]
    fn x_mcp_header_property_inside_an_all_of_subschema_annotates_nothing() {
        let schema = json!({
            "allOf": [{"properties": {"x-mcp-header": {"type": "string"}}}],
        });
        assert!(collect_annotations(&schema).is_empty(), "{schema}");
        assert_eq!(reason(&schema), None, "{schema}");
    }

    #[test]
    fn valid_integer_bounds_at_the_limit() {
        let schema = json!({
            "properties": {
                "a": {
                    "type": "integer",
                    "minimum": -9_007_199_254_740_991_i64,
                    "maximum": 9_007_199_254_740_991_i64,
                    "x-mcp-header": "X-A",
                },
            },
        });
        assert_eq!(reason(&schema), None);
    }

    #[test]
    fn non_string_names_are_rejected() {
        for value in [
            json!(7),
            json!(null),
            json!(["X-A"]),
            json!({"name": "X-A"}),
        ] {
            let schema = json!({"properties": {"a": {"type": "string", "x-mcp-header": value}}});
            assert_eq!(
                reason(&schema),
                Some(AnnotationError::NameNotString),
                "{value}"
            );
        }
    }

    #[test]
    fn empty_control_and_non_token_names_are_rejected() {
        assert_eq!(
            reason(&json!({"properties": {"a": {"type": "string", "x-mcp-header": ""}}})),
            Some(AnnotationError::NameEmpty)
        );
        for control in ["a\rb", "a\nb", "a\u{0}b", "a\u{7f}b"] {
            let schema = json!({"properties": {"a": {"type": "string", "x-mcp-header": control}}});
            assert_eq!(
                reason(&schema),
                Some(AnnotationError::NameControl),
                "{control:?}"
            );
        }
        for not_token in ["a b", "a:b", "a@b", "a\"b", "X-Ä"] {
            let schema =
                json!({"properties": {"a": {"type": "string", "x-mcp-header": not_token}}});
            assert_eq!(
                reason(&schema),
                Some(AnnotationError::NameNotToken),
                "{not_token:?}"
            );
        }
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let same = json!({
            "properties": {
                "a": {"type": "string", "x-mcp-header": "X-A"},
                "b": {"type": "string", "x-mcp-header": "X-A"},
            },
        });
        assert_eq!(reason(&same), Some(AnnotationError::NameDuplicate));

        let folded = json!({
            "properties": {
                "a": {"type": "string", "x-mcp-header": "X-A"},
                "b": {"type": "string", "x-mcp-header": "x-a"},
            },
        });
        assert_eq!(reason(&folded), Some(AnnotationError::NameDuplicate));

        let nested = json!({
            "properties": {
                "a": {
                    "type": "object",
                    "properties": {"b": {"type": "string", "x-mcp-header": "X-A"}},
                },
                "c": {"type": "string", "x-mcp-header": "X-A"},
            },
        });
        assert_eq!(reason(&nested), Some(AnnotationError::NameDuplicate));
    }

    #[test]
    fn non_primitive_types_are_rejected() {
        for property in [
            json!({"type": "number", "x-mcp-header": "X-A"}),
            json!({"type": "object", "x-mcp-header": "X-A"}),
            json!({"type": "array", "x-mcp-header": "X-A"}),
            json!({"type": "null", "x-mcp-header": "X-A"}),
            json!({"x-mcp-header": "X-A"}),
            json!({"type": ["string"], "x-mcp-header": "X-A"}),
        ] {
            let schema = json!({"properties": {"a": property}});
            assert_eq!(
                reason(&schema),
                Some(AnnotationError::TypeNotPrimitive),
                "{property}"
            );
        }
    }

    #[test]
    fn integer_bounds_outside_the_safe_range_are_rejected() {
        let below = json!({
            "properties": {
                "a": {"type": "integer", "minimum": -9_007_199_254_740_992_i64, "x-mcp-header": "X-A"},
            },
        });
        assert_eq!(reason(&below), Some(AnnotationError::IntegerRangeInvalid));

        let above = json!({
            "properties": {
                "a": {"type": "integer", "maximum": 9_007_199_254_740_992_i64, "x-mcp-header": "X-A"},
            },
        });
        assert_eq!(reason(&above), Some(AnnotationError::IntegerRangeInvalid));
    }

    #[test]
    fn unreachable_annotations_are_rejected() {
        let property = json!({"type": "string", "x-mcp-header": "X-A"});
        for schema in [
            json!({"type": "string", "x-mcp-header": "X-A"}),
            json!({"items": property.clone()}),
            json!({"oneOf": [property.clone()]}),
            json!({"anyOf": [property.clone()]}),
            json!({"allOf": [property.clone()]}),
            json!({"properties": {"a": {"allOf": [property.clone()]}}}),
            json!({"not": property.clone()}),
            json!({"if": property.clone()}),
            json!({"then": property.clone()}),
            json!({"else": property.clone()}),
            json!({"additionalProperties": property.clone()}),
            json!({"patternProperties": {"^a$": property.clone()}}),
            json!({"contains": property.clone()}),
            json!({"dependentSchemas": {"a": property.clone()}}),
            json!({"propertyNames": property.clone()}),
            json!({"$defs": {"a": property.clone()}}),
            json!({"definitions": {"a": property.clone()}}),
            json!({"unevaluatedProperties": property.clone()}),
            json!({"allOf": [{"properties": {"a": property.clone()}}]}),
        ] {
            assert_eq!(
                reason(&schema),
                Some(AnnotationError::NotStaticallyReachable),
                "{schema}"
            );
        }
    }

    #[test]
    fn error_tokens_and_display() {
        for (error, token) in [
            (AnnotationError::NameNotString, "annotation_name_not_string"),
            (AnnotationError::NameEmpty, "annotation_name_empty"),
            (AnnotationError::NameControl, "annotation_name_control"),
            (AnnotationError::NameNotToken, "annotation_name_not_token"),
            (AnnotationError::NameDuplicate, "annotation_name_duplicate"),
            (
                AnnotationError::NotStaticallyReachable,
                "annotation_not_statically_reachable",
            ),
            (
                AnnotationError::TypeNotPrimitive,
                "annotation_type_not_primitive",
            ),
            (
                AnnotationError::IntegerRangeInvalid,
                "annotation_integer_range_invalid",
            ),
        ] {
            assert_eq!(error.as_str(), token);
            assert_eq!(error.to_string(), token);
        }
    }
}
