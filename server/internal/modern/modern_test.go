package modern

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// hdr builds one received header field with its received casing.
func hdr(name, value string) Header { return Header{Name: name, Value: value} }

// headers builds a header list in the given order.
func headers(hs ...Header) []Header { return hs }

// sentinelText wraps an inner base64 text in the two sentinel markers.
func sentinelText(inner string) string { return "=?base64?" + inner + "?=" }

// sentinelBytes wraps the standard base64 of raw bytes in the two markers.
func sentinelBytes(raw []byte) string {
	return sentinelText(base64.StdEncoding.EncodeToString(raw))
}

// toolCallNoMeta is a POST tools/call request body without params._meta. The
// id and params.name members are supplied as raw JSON text.
func toolCallNoMeta(idJSON, nameJSON string) []byte {
	return []byte(fmt.Sprintf(
		`{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":%s}}`,
		idJSON, nameJSON))
}

// toolCallMeta is a POST tools/call request body whose params._meta carries
// MetaVersionKey with the given string version.
func toolCallMeta(idJSON, nameJSON, version string) []byte {
	return []byte(fmt.Sprintf(
		`{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":%s,"_meta":{%q:%q}}}`,
		idJSON, nameJSON, MetaVersionKey, version))
}

// wireHeaders renders a Header list the way Outcome.Wire does.
func wireHeaders(hs []Header) [][2]string {
	out := make([][2]string, len(hs))
	for i, h := range hs {
		out[i] = [2]string{h.Name, h.Value}
	}
	return out
}

// wireForward is the expected Wire() map of a forward outcome.
func wireForward(era, method, target string, hs []Header) map[string]any {
	return map[string]any{
		"outcome": "forward",
		"era":     era,
		"forward": map[string]any{
			"method":  method,
			"target":  target,
			"headers": wireHeaders(hs),
		},
		"consumes_nonce": true,
	}
}

// wireRefuse is the expected Wire() map of a signed JSON-RPC refusal. id is
// nil for a null id and json.RawMessage otherwise.
func wireRefuse(era string, status, code int, id any, message string) map[string]any {
	return map[string]any{
		"outcome":        "refuse",
		"era":            era,
		"signed":         true,
		"http_status":    status,
		"content_type":   "application/json",
		"jsonrpc":        "2.0",
		"id":             id,
		"error":          map[string]any{"code": code, "message": message},
		"consumes_nonce": true,
	}
}

// ---------------------------------------------------------------------------
// C4 decoder (spec 04 section 4, values.mjs decodeHeaderValue)
// ---------------------------------------------------------------------------

func TestModernValuesDecodeHeaderValue(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"plain value decodes to itself", "us-west1", "us-west1", true},
		{"empty plain value", "", "", true},
		{"sentinel non-ASCII round trip", "=?base64?SGVsbG8sIOS4lueVjA==?=", "Hello, 世界", true},
		{"encoded edge spaces", "=?base64?IHBhZGRlZCA=?=", " padded ", true},
		{"encoded newline", "=?base64?bGluZTEKbGluZTI=?=", "line1\nline2", true},
		{"encoded sentinel-shaped literal", "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=", "=?base64?literal?=", true},
		{"empty inner text decodes to empty", "=?base64??=", "", true},
		{"upper-case marker is plain", "=?BASE64?SGVsbG8=?=", "=?BASE64?SGVsbG8=?=", true},

		{"bad alphabet", sentinelText("SGVsbG8*"), "", false},
		{"missing padding", sentinelText("SGVsbG8"), "", false},
		{"non-canonical trailing bits", sentinelText("SGVsbG9="), "", false},
		{"space inside inner text", sentinelText("SGVs bG8="), "", false},
		{"base64url underscore", sentinelText("SGVsbG-_"), "", false},
		{"lone 0xFF byte", sentinelBytes([]byte{0xff}), "", false},
		{"overlong two-byte form", sentinelBytes([]byte{0xc0, 0xaf}), "", false},
		{"encoded surrogate", sentinelBytes([]byte{0xed, 0xa0, 0x80}), "", false},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got, ok := decodeHeaderValue(c.in)
			if ok != c.ok {
				t.Fatalf("decodeHeaderValue(%q) ok = %v, want %v", c.in, ok, c.ok)
			}
			if !c.ok {
				// An undecodable value has no text: the second result must be
				// false and the text must stay empty.
				if got != "" {
					t.Fatalf("decodeHeaderValue(%q) = %q, want empty text", c.in, got)
				}
				return
			}
			if got != c.want {
				t.Fatalf("decodeHeaderValue(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// C3 encoder and round trip (spec 04 section 4, values.mjs encodeHeaderValue)
// ---------------------------------------------------------------------------

func TestModernValuesEncodeRoundTrip(t *testing.T) {
	cases := []struct {
		text string
		want string
	}{
		{"us-west1", "us-west1"},
		{"Hello, 世界", "=?base64?SGVsbG8sIOS4lueVjA==?="},
		{" padded ", "=?base64?IHBhZGRlZCA=?="},
		{"line1\nline2", "=?base64?bGluZTEKbGluZTI=?="},
		{"=?base64?literal?=", "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="},
		{"", ""},
		{"a\tb", sentinelBytes([]byte("a\tb"))},
		{"=?BASE64?SGVsbG8=?=", "=?BASE64?SGVsbG8=?="},
		{"Seattle WA", "Seattle WA"},
	}

	for _, c := range cases {
		c := c
		t.Run(fmt.Sprintf("%q", c.text), func(t *testing.T) {
			encoded := encodeHeaderValue(c.text)
			if encoded != c.want {
				t.Fatalf("encodeHeaderValue(%q) = %q, want %q", c.text, encoded, c.want)
			}
			decoded, ok := decodeHeaderValue(encoded)
			if !ok {
				t.Fatalf("decodeHeaderValue(%q) ok = false, want true", encoded)
			}
			if decoded != c.text {
				t.Fatalf("decodeHeaderValue(%q) = %q, want %q", encoded, decoded, c.text)
			}
		})
	}

	// A value holding HTAB must not stay plain: HTAB is outside 0x20-0x7E.
	if got := encodeHeaderValue("a\tb"); got == "a\tb" {
		t.Fatalf("encodeHeaderValue(%q) = %q, want an encoded sentinel", "a\tb", got)
	}
}

// ---------------------------------------------------------------------------
// version, field-value and token grammars (spec 04 section 2, values.mjs)
// ---------------------------------------------------------------------------

func TestModernValuesVersionAndFieldValue(t *testing.T) {
	t.Run("isVersion", func(t *testing.T) {
		cases := []struct {
			in   string
			want bool
		}{
			{"2026-07-28", true},
			{"2025-11-25", true},
			{"2026-7-28", false},
			{"2026-07-28-draft", false},
			{"DRAFT-2026", false},
			{"", false},
		}
		for _, c := range cases {
			if got := isVersion(c.in); got != c.want {
				t.Fatalf("isVersion(%q) = %v, want %v", c.in, got, c.want)
			}
		}
	})

	t.Run("isModernVersion", func(t *testing.T) {
		// The comparison is byte-wise against ModernMin, so ModernMin itself is
		// the first modern version and ModernMin-1 day is below it.
		cases := []struct {
			in   string
			want bool
		}{
			{"0000-00-00", false},
			{"2025-11-25", false},
			{"2026-07-27", false},
			{"2026-07-28", true},
			{"2026-07-29", true},
			{"2026-08-00", true},
			{"9999-12-31", true},
			{"2026-07-2", false},
			{"2026-7-28", false},
			{"", false},
		}
		for _, c := range cases {
			if got := isModernVersion(c.in); got != c.want {
				t.Fatalf("isModernVersion(%q) = %v, want %v", c.in, got, c.want)
			}
		}
		if !isModernVersion(ModernMin) {
			t.Fatalf("isModernVersion(ModernMin) = false, want true")
		}
	})

	t.Run("isFieldValue", func(t *testing.T) {
		cases := []struct {
			in   string
			want bool
		}{
			{"", true},
			{"us-west1", true},
			{"\t", true},
			{"a\tb", true},
			{" Seattle ", true},
			{"~~", true},
			{"\x00", false},
			{"a\x00b", false},
			{"\n", false},
			{"\r", false},
			{"\x7f", false},
			{"\x80", false},
			{"\xff", false},
			{"世界", false},
		}
		for _, c := range cases {
			if got := isFieldValue(c.in); got != c.want {
				t.Fatalf("isFieldValue(%q) = %v, want %v", c.in, got, c.want)
			}
		}
	})

	t.Run("isToken", func(t *testing.T) {
		cases := []struct {
			in   string
			want bool
		}{
			{"Region", true},
			{"x-mcp-header", true},
			{"!#$%&'*+-.^_`|~", true},
			{"a1", true},
			{"", false},
			{"a b", false},
			{"a:b", false},
			{"a\tb", false},
		}
		for _, c := range cases {
			if got := isToken(c.in); got != c.want {
				t.Fatalf("isToken(%q) = %v, want %v", c.in, got, c.want)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Classify edges (spec 04 sections 3 and 5)
// ---------------------------------------------------------------------------

func TestModernClassifyEdges(t *testing.T) {
	t.Run("both profile without signals is legacy and untouched", func(t *testing.T) {
		hs := headers(
			hdr("Content-Type", "application/json"),
			hdr("Mcp-Session-Id", "sess-1"),
		)
		got := Classify(ProfileBoth, Request{
			Method:  "POST",
			Target:  "/mcp",
			Headers: hs,
			Body:    toolCallNoMeta("1", `"weather"`),
		})
		if got.Kind != KindForward || got.Era != eraLegacy {
			t.Fatalf("Kind/Era = %v/%q, want KindForward/legacy", got.Kind, got.Era)
		}
		if !reflect.DeepEqual(got.Forward.Headers, hs) {
			t.Fatalf("forwarded headers = %#v, want %#v", got.Forward.Headers, hs)
		}
		if got.Forward.Method != "POST" || got.Forward.Target != "/mcp" {
			t.Fatalf("forward = %q %q, want POST /mcp", got.Forward.Method, got.Forward.Target)
		}
		if want := wireForward(eraLegacy, "POST", "/mcp", hs); !reflect.DeepEqual(got.Wire(), want) {
			t.Fatalf("Wire() = %#v, want %#v", got.Wire(), want)
		}
	})

	t.Run("lower-case version header with matching meta is modern", func(t *testing.T) {
		hs := headers(
			hdr("mcp-protocol-version", "2026-07-28"),
			hdr("Mcp-Method", "tools/call"),
			hdr("Mcp-Name", "weather"),
		)
		got := Classify(ProfileBoth, Request{
			Method:  "POST",
			Target:  "/mcp",
			Headers: hs,
			Body:    toolCallMeta("7", `"weather"`, "2026-07-28"),
		})
		if got.Kind != KindForward || got.Era != eraModern {
			t.Fatalf("Kind/Era = %v/%q, want KindForward/modern", got.Kind, got.Era)
		}
		if !reflect.DeepEqual(got.Forward.Headers, hs) {
			t.Fatalf("forwarded headers = %#v, want %#v", got.Forward.Headers, hs)
		}
		if want := wireForward(eraModern, "POST", "/mcp", hs); !reflect.DeepEqual(got.Wire(), want) {
			t.Fatalf("Wire() = %#v, want %#v", got.Wire(), want)
		}
	})

	t.Run("repeated version header in different casing is refused", func(t *testing.T) {
		hs := headers(
			hdr("MCP-Protocol-Version", "2025-11-25"),
			hdr("Mcp-Protocol-Version", "2026-07-28"),
		)
		got := Classify(ProfileBoth, Request{
			Method:  "POST",
			Target:  "/mcp",
			Headers: hs,
			Body:    toolCallMeta("3", `"weather"`, "2026-07-28"),
		})
		// Any modern instance selects the modern era, even when the other
		// instance is pre-2026, and S1 then refuses the repetition.
		if got.Kind != KindRefuse || got.Era != eraModern {
			t.Fatalf("Kind/Era = %v/%q, want KindRefuse/modern", got.Kind, got.Era)
		}
		if got.HTTPStatus != 400 {
			t.Fatalf("HTTPStatus = %d, want 400", got.HTTPStatus)
		}
		if got.Error.Code != -32020 {
			t.Fatalf("Error.Code = %d, want -32020", got.Error.Code)
		}
		wantMsg := "Header mismatch: a request metadata header appears more than once"
		if got.Error.Message != wantMsg {
			t.Fatalf("Error.Message = %q, want %q", got.Error.Message, wantMsg)
		}
		if got.JSONRPC != "2.0" || got.ContentType != "application/json" || !got.Signed {
			t.Fatalf("refusal shape = %q %q signed=%v", got.JSONRPC, got.ContentType, got.Signed)
		}
		if string(got.ID) != "3" {
			t.Fatalf("ID = %q, want %q", got.ID, "3")
		}
		if want := wireRefuse(eraModern, 400, -32020, json.RawMessage("3"), wantMsg); !reflect.DeepEqual(got.Wire(), want) {
			t.Fatalf("Wire() = %#v, want %#v", got.Wire(), want)
		}
	})

	t.Run("NUL in a mirror value is header_value_invalid", func(t *testing.T) {
		got := Classify(ProfileModern, Request{
			Method: "POST",
			Target: "/mcp",
			Headers: headers(
				hdr("MCP-NAME", "weather\x00"),
				hdr("Mcp-Method", "tools/call"),
			),
			Body: toolCallMeta("1", `"weather"`, "2026-07-28"),
		})
		if got.Kind != KindRefuse || got.Era != eraModern {
			t.Fatalf("Kind/Era = %v/%q, want KindRefuse/modern", got.Kind, got.Era)
		}
		wantMsg := "Header mismatch: a request metadata header value contains a character outside the HTTP field-value syntax"
		if got.HTTPStatus != 400 || got.Error.Code != -32020 || got.Error.Message != wantMsg {
			t.Fatalf("refusal = %d %d %q, want 400 -32020 %q", got.HTTPStatus, got.Error.Code, got.Error.Message, wantMsg)
		}
		if string(got.ID) != "1" {
			t.Fatalf("ID = %q, want %q", got.ID, "1")
		}
	})

	t.Run("param header with HTAB is kept and session headers dropped", func(t *testing.T) {
		hs := headers(
			hdr("MCP-Protocol-Version", "2026-07-28"),
			hdr("Mcp-Method", "tools/call"),
			hdr("Mcp-Name", "weather"),
			hdr("Mcp-Param-Region", "us\twest1"),
			hdr("Mcp-Session-Id", "sess-1"),
			hdr("last-event-id", "42"),
			hdr("X-Trace", "abc"),
			hdr("Mcp-Session-Id", "sess-2"),
		)
		want := headers(
			hdr("MCP-Protocol-Version", "2026-07-28"),
			hdr("Mcp-Method", "tools/call"),
			hdr("Mcp-Name", "weather"),
			hdr("Mcp-Param-Region", "us\twest1"),
			hdr("X-Trace", "abc"),
		)
		got := Classify(ProfileModern, Request{
			Method:  "POST",
			Target:  "/mcp",
			Headers: hs,
			Body:    toolCallMeta("1", `"weather"`, "2026-07-28"),
		})
		if got.Kind != KindForward || got.Era != eraModern {
			t.Fatalf("Kind/Era = %v/%q, want KindForward/modern", got.Kind, got.Era)
		}
		if !reflect.DeepEqual(got.Forward.Headers, want) {
			t.Fatalf("forwarded headers = %#v, want %#v", got.Forward.Headers, want)
		}
		if wantWire := wireForward(eraModern, "POST", "/mcp", want); !reflect.DeepEqual(got.Wire(), wantWire) {
			t.Fatalf("Wire() = %#v, want %#v", got.Wire(), wantWire)
		}
	})

	t.Run("bare Mcp-Param- is not a recognised param header", func(t *testing.T) {
		hs := headers(
			hdr("MCP-Protocol-Version", "2026-07-28"),
			hdr("Mcp-Method", "tools/call"),
			hdr("Mcp-Name", "weather"),
			hdr("Mcp-Param-", ""),
		)
		got := Classify(ProfileModern, Request{
			Method:  "POST",
			Target:  "/mcp",
			Headers: hs,
			Body:    toolCallMeta("1", `"weather"`, "2026-07-28"),
		})
		if got.Kind != KindForward || got.Era != eraModern {
			t.Fatalf("Kind/Era = %v/%q, want KindForward/modern", got.Kind, got.Era)
		}
		if !reflect.DeepEqual(got.Forward.Headers, hs) {
			t.Fatalf("forwarded headers = %#v, want %#v", got.Forward.Headers, hs)
		}
	})

	t.Run("client-sent response object needs no mirrors", func(t *testing.T) {
		hs := headers(
			hdr("Mcp-Session-Id", "sess-1"),
			hdr("Content-Type", "application/json"),
		)
		want := headers(hdr("Content-Type", "application/json"))
		got := Classify(ProfileModern, Request{
			Method:  "POST",
			Target:  "/mcp",
			Headers: hs,
			Body:    []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`),
		})
		if got.Kind != KindForward || got.Era != eraModern {
			t.Fatalf("Kind/Era = %v/%q, want KindForward/modern", got.Kind, got.Era)
		}
		if !reflect.DeepEqual(got.Forward.Headers, want) {
			t.Fatalf("forwarded headers = %#v, want %#v", got.Forward.Headers, want)
		}

		// params._meta is never a mirror source for a response object, so
		// profile both stays legacy-era and forwards untouched.
		responseWithMeta := []byte(`{"jsonrpc":"2.0","id":1,"result":{},"params":{"_meta":{` +
			`"` + MetaVersionKey + `":"2026-07-28"}}}`)
		respHS := headers(hdr("Mcp-Session-Id", "sess-1"))
		respGot := Classify(ProfileBoth, Request{
			Method:  "POST",
			Target:  "/mcp",
			Headers: respHS,
			Body:    responseWithMeta,
		})
		if respGot.Kind != KindForward || respGot.Era != eraLegacy {
			t.Fatalf("response object Kind/Era = %v/%q, want KindForward/legacy", respGot.Kind, respGot.Era)
		}
		if !reflect.DeepEqual(respGot.Forward.Headers, respHS) {
			t.Fatalf("response object headers = %#v, want %#v", respGot.Forward.Headers, respHS)
		}
	})

	t.Run("modern profile refuses a non-POST method", func(t *testing.T) {
		got := Classify(ProfileModern, Request{Method: "DELETE", Target: "/mcp"})
		if got.Kind != KindRefuse || got.Era != eraModern {
			t.Fatalf("Kind/Era = %v/%q, want KindRefuse/modern", got.Kind, got.Era)
		}
		if got.ID != nil || len(got.ID) != 0 {
			t.Fatalf("ID = %q, want nil", got.ID)
		}
		wantMsg := "HTTP method not allowed"
		if got.HTTPStatus != 405 || got.Error.Code != -32600 || got.Error.Message != wantMsg {
			t.Fatalf("refusal = %d %d %q, want 405 -32600 %q", got.HTTPStatus, got.Error.Code, got.Error.Message, wantMsg)
		}
		wire := got.Wire()
		if wire["id"] != nil {
			t.Fatalf("Wire()[\"id\"] = %#v, want nil", wire["id"])
		}
		if _, ok := wire["id"]; !ok {
			t.Fatalf("Wire() has no \"id\" member, want one holding null")
		}
		if want := wireRefuse(eraModern, 405, -32600, nil, wantMsg); !reflect.DeepEqual(wire, want) {
			t.Fatalf("Wire() = %#v, want %#v", wire, want)
		}
	})

	t.Run("legacy profile forwards malformed values untouched", func(t *testing.T) {
		hs := headers(
			hdr("Mcp-Name", "=?base64?***?="),
			hdr("mcp-session-id", "sess-1"),
			hdr("last-event-id", "9"),
			hdr("mcp-protocol-version", "2026-07-28"),
		)
		got := Classify(ProfileLegacy, Request{
			Method:  "POST",
			Target:  "/mcp",
			Headers: hs,
			Body:    toolCallNoMeta("1", `"weather"`),
		})
		if got.Kind != KindForward || got.Era != eraLegacy {
			t.Fatalf("Kind/Era = %v/%q, want KindForward/legacy", got.Kind, got.Era)
		}
		if !reflect.DeepEqual(got.Forward.Headers, hs) {
			t.Fatalf("forwarded headers = %#v, want %#v", got.Forward.Headers, hs)
		}
		if want := wireForward(eraLegacy, "POST", "/mcp", hs); !reflect.DeepEqual(got.Wire(), want) {
			t.Fatalf("Wire() = %#v, want %#v", got.Wire(), want)
		}
	})

	t.Run("notification without mirrors is forwarded modern", func(t *testing.T) {
		got := Classify(ProfileModern, Request{
			Method:  "POST",
			Target:  "/mcp",
			Headers: []Header{},
			Body:    []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`),
		})
		if got.Kind != KindForward || got.Era != eraModern {
			t.Fatalf("Kind/Era = %v/%q, want KindForward/modern", got.Kind, got.Era)
		}
		if !reflect.DeepEqual(got.Forward.Headers, []Header{}) {
			t.Fatalf("forwarded headers = %#v, want none", got.Forward.Headers)
		}
	})

	t.Run("notification with a mismatched Mcp-Name is refused with null id", func(t *testing.T) {
		got := Classify(ProfileModern, Request{
			Method:  "POST",
			Target:  "/mcp",
			Headers: headers(hdr("Mcp-Name", "b")),
			Body:    []byte(`{"jsonrpc":"2.0","method":"events/poll","params":{"name":"a"}}`),
		})
		if got.Kind != KindRefuse || got.Era != eraModern {
			t.Fatalf("Kind/Era = %v/%q, want KindRefuse/modern", got.Kind, got.Era)
		}
		wantMsg := "Header mismatch: Mcp-Name does not match the body value"
		if got.HTTPStatus != 400 || got.Error.Code != -32020 || got.Error.Message != wantMsg {
			t.Fatalf("refusal = %d %d %q, want 400 -32020 %q", got.HTTPStatus, got.Error.Code, got.Error.Message, wantMsg)
		}
		if len(got.ID) != 0 {
			t.Fatalf("ID = %q, want nil for a notification", got.ID)
		}
		if want := wireRefuse(eraModern, 400, -32020, nil, wantMsg); !reflect.DeepEqual(got.Wire(), want) {
			t.Fatalf("Wire() = %#v, want %#v", got.Wire(), want)
		}
	})

	t.Run("tool name refusal is the era-neutral body refusal", func(t *testing.T) {
		got := Classify(ProfileBoth, Request{
			Method:      "POST",
			Target:      "/mcp",
			Body:        toolCallNoMeta("1", `42`),
			BodyRefusal: BodyRefusalToolName,
		})
		if got.Kind != KindRefuseInvalidRequest {
			t.Fatalf("Kind = %v, want KindRefuseInvalidRequest", got.Kind)
		}
		if got.HTTPStatus != 400 || got.ErrorCode != ClassificationCode {
			t.Fatalf("HTTPStatus/ErrorCode = %d/%q, want 400/%q", got.HTTPStatus, got.ErrorCode, ClassificationCode)
		}
		if got.Error.Message != ClassificationMessage {
			t.Fatalf("Error.Message = %q, want %q", got.Error.Message, ClassificationMessage)
		}
		if !got.Signed || got.ContentType != "application/json" || !got.ConsumesNonce {
			t.Fatalf("refusal shape = signed=%v ct=%q nonce=%v", got.Signed, got.ContentType, got.ConsumesNonce)
		}
		wire := got.Wire()
		if _, ok := wire["jsonrpc"]; ok {
			t.Fatalf("Wire() has a \"jsonrpc\" member: %#v", wire)
		}
		if _, ok := wire["id"]; ok {
			t.Fatalf("Wire() has an \"id\" member: %#v", wire)
		}
		want := map[string]any{
			"outcome":        "refuse_invalid_request",
			"era":            nil,
			"signed":         true,
			"http_status":    400,
			"content_type":   "application/json",
			"error":          map[string]any{"code": "invalid_request", "message": "tools/call requires a string params.name"},
			"consumes_nonce": true,
		}
		if !reflect.DeepEqual(wire, want) {
			t.Fatalf("Wire() = %#v, want %#v", wire, want)
		}
	})

	t.Run("non-string params.name without a body refusal is KindNone", func(t *testing.T) {
		// S6's defensive path: a tools/call body whose params.name is not a
		// string only reaches S6 when the body classifier did not already
		// refuse it, and then the caller keeps its own answer.
		got := Classify(ProfileBoth, Request{
			Method: "POST",
			Target: "/mcp",
			Headers: headers(
				hdr("MCP-Protocol-Version", "2026-07-28"),
				hdr("Mcp-Method", "tools/call"),
			),
			Body:        toolCallMeta("1", `42`, "2026-07-28"),
			BodyRefusal: BodyRefusalNone,
		})
		if got.Kind != KindNone {
			t.Fatalf("Kind = %v, want KindNone", got.Kind)
		}
		if got.Wire() != nil {
			t.Fatalf("Wire() = %#v, want nil", got.Wire())
		}
	})
}

// ---------------------------------------------------------------------------
// S10 refusal id (spec 04 section 5, S10)
// ---------------------------------------------------------------------------

// TestModernClassifyRefusalID drives a header_repeated refusal and checks the
// echoed id. An id member that is a string or a number makes the body a
// request; a boolean, an object, an array or null makes it a notification, so
// the refusal carries a null id in that case too.
// Integrality is exact: a fraction with a non-zero part, or a magnitude outside int64, becomes null.
func TestModernClassifyRefusalID(t *testing.T) {
	// Two MCP-Protocol-Version headers trip S1, so every case reaches S10.
	repeated := headers(
		hdr("MCP-Protocol-Version", "2026-07-28"),
		hdr("Mcp-Protocol-Version", "2026-07-28"),
	)
	bodyWithID := func(idJSON string) []byte {
		return []byte(fmt.Sprintf(
			`{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"weather"}}`,
			idJSON))
	}

	cases := []struct {
		name string
		id   string
		want []byte
	}{
		{"string id is echoed", `"abc"`, []byte(`"abc"`)},
		{"integer id is echoed", `1`, []byte(`1`)},
		{"integral exponent id is echoed", `1e3`, []byte(`1e3`)},
		{"integral fraction id is echoed", `1.0`, []byte(`1.0`)},
		{"integral fraction with exponent id is echoed", `1.5e1`, []byte(`1.5e1`)},
		{"negative zero id is echoed", `-0`, []byte(`-0`)},
		{"max int64 id is echoed", `9223372036854775807`, []byte(`9223372036854775807`)},
		{"rounded fraction id becomes null", `9007199254740992.5`, nil},
		{"out of int64 range id becomes null", `9223372036854775808`, nil},
		{"twenty digit id becomes null", `12345678901234567890`, nil},
		{"huge exponent id becomes null", `1e400`, nil},
		{"fractional id becomes null", `1.5`, nil},
		{"non-integral exponent id becomes null", `1.5e0`, nil},
		{"non-integral scaled fraction id becomes null", `1.25e1`, nil},
		{"boolean id becomes null", `true`, nil},
		{"object id becomes null", `{"a":1}`, nil},
		{"array id becomes null", `[1]`, nil},
		{"null id becomes null", `null`, nil},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got := Classify(ProfileModern, Request{
				Method:  "POST",
				Target:  "/mcp",
				Headers: repeated,
				Body:    bodyWithID(c.id),
			})
			if got.Kind != KindRefuse || got.Era != eraModern {
				t.Fatalf("Kind/Era = %v/%q, want KindRefuse/modern", got.Kind, got.Era)
			}
			wantMsg := "Header mismatch: a request metadata header appears more than once"
			if got.HTTPStatus != 400 || got.Error.Code != -32020 || got.Error.Message != wantMsg {
				t.Fatalf("refusal = %d %d %q, want 400 -32020 %q",
					got.HTTPStatus, got.Error.Code, got.Error.Message, wantMsg)
			}
			if !reflect.DeepEqual(got.ID, c.want) {
				t.Fatalf("id %s: ID = %q, want %q", c.id, got.ID, c.want)
			}
			wantWire := wireRefuse(eraModern, 400, -32020, nil, wantMsg)
			if c.want != nil {
				wantWire["id"] = json.RawMessage(c.want)
			}
			if wire := got.Wire(); !reflect.DeepEqual(wire, wantWire) {
				t.Fatalf("id %s: Wire() = %#v, want %#v", c.id, wire, wantWire)
			}
		})
	}
}

// TestModernEraFromHeaders pins the header-only era decision used for non-POST
// requests (spec 04 section 3): profile modern is always modern, profile both
// counts only well-formed modern version header instances, and any other
// profile is always legacy.
func TestModernEraFromHeaders(t *testing.T) {
	cases := []struct {
		name    string
		profile Profile
		headers []Header
		want    string
	}{
		{"modern profile without headers", ProfileModern, nil, eraModern},
		{"legacy profile with a modern header", ProfileLegacy, headers(hdr("MCP-Protocol-Version", "2026-07-28")), eraLegacy},
		{"both without headers", ProfileBoth, nil, eraLegacy},
		{"both with a legacy version", ProfileBoth, headers(hdr("MCP-Protocol-Version", "2025-11-25")), eraLegacy},
		{"both with a modern version", ProfileBoth, headers(hdr("MCP-Protocol-Version", "2026-07-28")), eraModern},
		{"both matches the name case-insensitively", ProfileBoth, headers(hdr("mcp-protocol-version", "2026-07-28")), eraModern},
		{"both ignores a malformed version", ProfileBoth, headers(hdr("MCP-Protocol-Version", "2026-7-28")), eraLegacy},
		{"both counts a repeated header when any value is modern", ProfileBoth, headers(hdr("MCP-Protocol-Version", "2025-11-25"), hdr("Mcp-Protocol-Version", "2026-07-28")), eraModern},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got := EraFromHeaders(c.profile, c.headers); got != c.want {
				t.Fatalf("EraFromHeaders(%q) = %q, want %q", c.profile, got, c.want)
			}
		})
	}
}
