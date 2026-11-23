package modern

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

// AnnotationCheck is the C5 verdict for one tool or event inputSchema.
type AnnotationCheck struct {
	// Valid reports that the inputSchema carries no annotation violation.
	Valid bool
	// Reason is one of the eight closed reasons below, "" when Valid.
	Reason string
}

// The closed C5/C11 reason list. Each token maps to one source constraint of
// spec 04 section 6.
const (
	// ReasonAnnotationNameNotString reports an x-mcp-header value that is not
	// a JSON string.
	ReasonAnnotationNameNotString = "annotation_name_not_string"
	// ReasonAnnotationNameEmpty reports an empty x-mcp-header value.
	ReasonAnnotationNameEmpty = "annotation_name_empty"
	// ReasonAnnotationNameControl reports a name with a byte below 0x20 or
	// 0x7f, including CR and LF.
	ReasonAnnotationNameControl = "annotation_name_control"
	// ReasonAnnotationNameNotToken reports a name that fails 1*tchar
	// (RFC 9110 section 5.6.2).
	ReasonAnnotationNameNotToken = "annotation_name_not_token"
	// ReasonAnnotationNameDuplicate reports a name case-insensitively equal to
	// another annotation name in the same inputSchema.
	ReasonAnnotationNameDuplicate = "annotation_name_duplicate"
	// ReasonAnnotationTypeNotPrimitive reports a property type that is not
	// exactly "string", "integer" or "boolean".
	ReasonAnnotationTypeNotPrimitive = "annotation_type_not_primitive"
	// ReasonAnnotationIntegerRangeInvalid reports an integer property with a
	// minimum below -SafeIntMax or a maximum above SafeIntMax.
	ReasonAnnotationIntegerRangeInvalid = "annotation_integer_range_invalid"
	// ReasonAnnotationNotStaticallyReachable reports an annotation that does
	// not sit below a chain of `properties` member names.
	ReasonAnnotationNotStaticallyReachable = "annotation_not_statically_reachable"
)

// annotation is one x-mcp-header keyword found by the structural traversal.
type annotation struct {
	// node is the schema object that carries the keyword.
	node *jsonValue
	// name is the keyword value, which need not be a JSON string.
	name *jsonValue
	// propPath is the property-name chain of the annotation, meaningful only
	// when reachable.
	propPath []string
	// reachable reports a statically reachable annotation, that is an
	// even-length (>= 2) path that alternates "properties" and a property
	// name.
	reachable bool
}

// isNameMapKeyword reports whether a schema member is a name map: its members
// are property, pattern or definition names rather than keywords.
func isNameMapKeyword(name string) bool {
	switch name {
	case "properties", "patternProperties", "$defs", "definitions", "dependentSchemas":
		return true
	}
	return false
}

// isSchemaKeyword reports whether the value of a schema member is a schema or
// an array of schemas, so its members are keywords again.
func isSchemaKeyword(name string) bool {
	switch name {
	case "allOf", "anyOf", "oneOf", "not", "if", "then", "else", "items",
		"prefixItems", "contains", "additionalProperties", "additionalItems",
		"propertyNames", "unevaluatedProperties", "unevaluatedItems":
		return true
	}
	return false
}

// extendPath returns path with segment appended, without aliasing path.
func extendPath(path []string, segment string) []string {
	next := make([]string, len(path)+1)
	copy(next, path)
	next[len(path)] = segment
	return next
}

// staticPropertyPath reports the property-name chain of a path from the schema
// root: it must be even-length and at least two segments, alternating
// "properties" and a property name. The root itself, an odd length and any
// other segment make the annotation statically unreachable. An empty property
// name is legal.
func staticPropertyPath(path []string) ([]string, bool) {
	if len(path) < 2 || len(path)%2 != 0 {
		return nil, false
	}
	names := make([]string, 0, len(path)/2)
	for i := 0; i < len(path); i += 2 {
		if path[i] != "properties" {
			return nil, false
		}
		names = append(names, path[i+1])
	}
	return names, true
}

// collectAnnotations walks the inputSchema of a tool or event and returns its
// x-mcp-header keywords in depth-first document order.
//
// The recursion carries whether the current node is a schema (its members are
// keywords) or a name map (its members are property, pattern or definition
// names). Only the value of a name-map keyword is a name map; the value of an
// applicator keyword is a schema again. A member named x-mcp-header is an
// annotation only in a schema node, so a property named properties keeps its
// own annotation and a property named x-mcp-header - at the root, in a name
// map or inside an allOf subschema - is never an annotation keyword.
func collectAnnotations(inputSchema *jsonValue) []annotation {
	var out []annotation

	push := func(node *jsonValue, path []string) {
		propPath, reachable := staticPropertyPath(path)
		name, _ := node.member(AnnotationKey)
		out = append(out, annotation{node: node, name: name, propPath: propPath, reachable: reachable})
	}

	var walkValue func(*jsonValue, []string)
	var walkSchema func(*jsonValue, []string)
	var walkSubschema func(*jsonValue, []string)
	var walkNameMap func(*jsonValue, []string)

	// walkValue recurses through a generic value: arrays by index and objects
	// by member, without any schema interpretation.
	walkValue = func(node *jsonValue, path []string) {
		if node == nil {
			return
		}
		if node.kind == jsonArray {
			for i, item := range node.arrayItems() {
				walkValue(item, extendPath(path, strconv.Itoa(i)))
			}
			return
		}
		if !node.isObject() {
			return
		}
		for _, m := range node.objectMembers() {
			if m.name == AnnotationKey {
				push(node, path)
				continue
			}
			walkValue(m.value, extendPath(path, m.name))
		}
	}

	// walkSubschema visits the value of an applicator keyword: a schema or an
	// array of schemas.
	walkSubschema = func(node *jsonValue, path []string) {
		if node == nil {
			return
		}
		if node.kind == jsonArray {
			for i, item := range node.arrayItems() {
				walkSubschema(item, extendPath(path, strconv.Itoa(i)))
			}
			return
		}
		walkSchema(node, path)
	}

	// walkNameMap visits the value of a name-map keyword: every member value is
	// a schema whose path segment is the member name.
	walkNameMap = func(node *jsonValue, path []string) {
		if !node.isObject() {
			return
		}
		for _, m := range node.objectMembers() {
			walkSchema(m.value, extendPath(path, m.name))
		}
	}

	walkSchema = func(node *jsonValue, path []string) {
		if !node.isObject() {
			return
		}
		for _, m := range node.objectMembers() {
			switch {
			case m.name == AnnotationKey:
				push(node, path)
			case isNameMapKeyword(m.name):
				walkNameMap(m.value, extendPath(path, m.name))
			case isSchemaKeyword(m.name):
				walkSubschema(m.value, extendPath(path, m.name))
			default:
				walkValue(m.value, extendPath(path, m.name))
			}
		}
	}

	walkSchema(inputSchema, nil)
	return out
}

// ValidateAnnotations reports the C5 verdict for a tool or event inputSchema.
// A schema that is not valid JSON, or is not an object, has no annotations and
// is valid.
//
// The rules run in a fixed order and each one scans every annotation in
// document order, so the first hit of the first failing rule is the reported
// reason.
func ValidateAnnotations(inputSchema []byte) AnnotationCheck {
	root, ok := parseJSONValue(inputSchema)
	if !ok {
		return AnnotationCheck{Valid: true}
	}
	return checkAnnotations(collectAnnotations(root))
}

// checkAnnotations applies the C5 rule order to already collected annotations.
func checkAnnotations(annotations []annotation) AnnotationCheck {
	fail := func(reason string) AnnotationCheck { return AnnotationCheck{Reason: reason} }

	for _, a := range annotations {
		if a.name == nil || a.name.kind != jsonString {
			return fail(ReasonAnnotationNameNotString)
		}
	}
	for _, a := range annotations {
		if a.name.text == "" {
			return fail(ReasonAnnotationNameEmpty)
		}
	}
	for _, a := range annotations {
		if hasControlByte(a.name.text) {
			return fail(ReasonAnnotationNameControl)
		}
	}
	for _, a := range annotations {
		if !IsToken(a.name.text) {
			return fail(ReasonAnnotationNameNotToken)
		}
	}
	seen := make(map[string]struct{}, len(annotations))
	for _, a := range annotations {
		// Every name is an ASCII token here, so a simple case folding is the
		// same case-insensitive comparison the reference uses.
		folded := strings.ToLower(a.name.text)
		if _, dup := seen[folded]; dup {
			return fail(ReasonAnnotationNameDuplicate)
		}
		seen[folded] = struct{}{}
	}
	for _, a := range annotations {
		if !a.reachable {
			return fail(ReasonAnnotationNotStaticallyReachable)
		}
	}
	for _, a := range annotations {
		if !isPrimitiveType(a.node) {
			return fail(ReasonAnnotationTypeNotPrimitive)
		}
	}
	for _, a := range annotations {
		if integerRangeInvalid(a.node) {
			return fail(ReasonAnnotationIntegerRangeInvalid)
		}
	}
	return AnnotationCheck{Valid: true}
}

// hasControlByte reports a byte below 0x20 or equal to 0x7f. Bytes of a
// multi-byte UTF-8 sequence are all 0x80 or above, so this matches a code
// point scan.
func hasControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// isPrimitiveType reports whether the property schema's "type" is exactly the
// JSON string "string", "integer" or "boolean".
func isPrimitiveType(node *jsonValue) bool {
	typ, ok := stringMember(node, "type")
	if !ok {
		return false
	}
	switch typ {
	case "string", "integer", "boolean":
		return true
	}
	return false
}

// integerRangeInvalid reports an integer property whose numeric minimum is
// below -SafeIntMax or numeric maximum above SafeIntMax. Absent or non-numeric
// bounds are valid because the runtime value is checked at projection time.
func integerRangeInvalid(node *jsonValue) bool {
	typ, ok := stringMember(node, "type")
	if !ok || typ != "integer" {
		return false
	}
	if min, ok := numberMember(node, "minimum"); ok && min < -SafeIntMax {
		return true
	}
	if max, ok := numberMember(node, "maximum"); ok && max > SafeIntMax {
		return true
	}
	return false
}

// stringMember returns the string value of the member named name, using the
// last occurrence of a repeated name. The second result is false when the
// member is absent or is not a JSON string.
func stringMember(node *jsonValue, name string) (string, bool) {
	member, ok := node.member(name)
	if !ok || member.kind != jsonString {
		return "", false
	}
	return member.text, true
}

// numberMember returns the value of the member named name as a float64, using
// the last occurrence of a repeated name. The second result is false when the
// member is absent or is not a JSON number.
func numberMember(node *jsonValue, name string) (float64, bool) {
	member, ok := node.member(name)
	if !ok || member.kind != jsonNumber {
		return 0, false
	}
	value, err := strconv.ParseFloat(member.text, 64)
	if err != nil {
		// The decoder validated the lexeme, so only range overflow is
		// possible; ParseFloat reports it as ±Inf, exactly as JSON.parse does.
		if math.IsInf(value, 0) {
			return value, true
		}
		return 0, false
	}
	return value, true
}

// Definition is one tool or event type descriptor whose inputSchema carries
// x-mcp-header annotations.
type Definition struct {
	// Name is the tool name or the event type name, reported when excluded.
	Name string
	// InputSchema is the raw inputSchema document of the definition.
	InputSchema []byte
}

// Exclusion reports a definition dropped from a tools/list or events/list
// result and why (C5/C11: excluded, not an error response).
type Exclusion struct {
	// Name is the excluded tool name or event type name.
	Name string
	// Reason is the AnnotationCheck reason that excluded it.
	Reason string
}

// FilterDefinitions validates each definition and keeps the valid ones in
// input order; the others are reported with their reason.
func FilterDefinitions(defs []Definition) (kept []Definition, excluded []Exclusion) {
	for _, def := range defs {
		check := ValidateAnnotations(def.InputSchema)
		if check.Valid {
			kept = append(kept, def)
			continue
		}
		excluded = append(excluded, Exclusion{Name: def.Name, Reason: check.Reason})
	}
	return kept, excluded
}

// ProjectArguments projects the annotated arguments into Mcp-Param-* headers in
// depth-first document order (C6). The caller must have validated the schema
// first. A present argument whose type does not match its annotation returns
// ErrHeaderProjectionInvalidValue.
//
// A schema that is not valid JSON and arguments that are not valid JSON carry
// no annotation and no present argument, so both yield no headers: the
// argument table of C6 maps an absent argument to an omitted header.
func ProjectArguments(inputSchema, arguments []byte) ([]Header, error) {
	root, ok := parseJSONValue(inputSchema)
	if !ok {
		return nil, nil
	}
	// Unparseable arguments are treated like absent ones.
	args, _ := parseJSONValue(arguments)

	headers := make([]Header, 0, 4)
	for _, a := range collectAnnotations(root) {
		if !a.reachable {
			continue
		}
		if a.name == nil || a.name.kind != jsonString {
			// validateAnnotations rejects a non-string name, so this only
			// guards a caller that skipped validation.
			return nil, ErrHeaderProjectionInvalidValue
		}
		value, present := readArgument(args, a.propPath)
		if !present {
			continue
		}
		typ, _ := stringMember(a.node, "type")
		text, ok := textOfJSONValue(value, typ)
		if !ok {
			return nil, ErrHeaderProjectionInvalidValue
		}
		headers = append(headers, Header{Name: "Mcp-Param-" + a.name.text, Value: EncodeHeaderValue(text)})
	}
	return headers, nil
}

// readArgument walks the arguments along propPath: any step absent, a
// non-object intermediate or a null value means the header is omitted.
func readArgument(args *jsonValue, propPath []string) (*jsonValue, bool) {
	current := args
	for _, name := range propPath {
		if !current.isObject() {
			return nil, false
		}
		next, ok := current.member(name)
		if !ok {
			return nil, false
		}
		current = next
	}
	if current == nil || current.isNull() {
		return nil, false
	}
	return current, true
}

// textOfJSONValue converts a present argument to the header text of typ, using
// the section 4 conversion in TextOfValue. The second result is false when the
// value is not representable as typ, which is the C6 mismatch.
func textOfJSONValue(value *jsonValue, typ string) (string, bool) {
	switch value.kind {
	case jsonString:
		return TextOfValue(value.text, typ)
	case jsonNumber:
		return TextOfValue(json.Number(value.text), typ)
	case jsonBool:
		return TextOfValue(value.boolean, typ)
	}
	return "", false
}
