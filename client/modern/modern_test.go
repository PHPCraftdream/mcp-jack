package modern_test

import (
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/PHPCraftdream/mcp-jack/client/modern"
)

func TestModernHeaderValueEncodeDecode(t *testing.T) {
	encoded := []struct {
		name string
		text string
		want string
	}{
		{"token plain", "us-west1", "us-west1"},
		{"non-ascii", "Hello, 世界", "=?base64?SGVsbG8sIOS4lueVjA==?="},
		{"padded spaces", " padded ", "=?base64?IHBhZGRlZCA=?="},
		{"newline", "line1\nline2", "=?base64?bGluZTEKbGluZTI=?="},
		{"sentinel shaped", "=?base64?literal?=", "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="},
		{"empty stays empty", "", ""},
		{"tab", "a\tb", "=?base64?YQli?="},
		{"upper sentinel markers are plain", "=?BASE64?SGVsbG8=?=", "=?BASE64?SGVsbG8=?="},
		{"interior space is plain", "a b", "a b"},
	}
	for _, tc := range encoded {
		t.Run(tc.name, func(t *testing.T) {
			if got := modern.EncodeHeaderValue(tc.text); got != tc.want {
				t.Fatalf("EncodeHeaderValue(%q) = %q, want %q", tc.text, got, tc.want)
			}
			got, ok := modern.DecodeHeaderValue(tc.want)
			if !ok {
				t.Fatalf("DecodeHeaderValue(%q) = not ok, want %q", tc.want, tc.text)
			}
			if got != tc.text {
				t.Fatalf("DecodeHeaderValue(%q) = %q, want %q", tc.want, got, tc.text)
			}
		})
	}

	undecodable := []struct {
		name  string
		value string
	}{
		{"bad alphabet", "=?base64?SGVsbG8!?="},
		{"missing padding", "=?base64?SGVsbG8?="},
		{"non-canonical trailing bits", "=?base64?SGVsbG9=?="},
		{"space inside", "=?base64?SGVs bG8=?="},
		{"base64url underscore", "=?base64?SGVsbG8_?="},
		{"lone 0xff byte", "=?base64?/w==?="},
		{"overlong two-byte form", "=?base64?wIA=?="},
		{"encoded surrogate", "=?base64?7aCA?="},
	}
	for _, tc := range undecodable {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := modern.DecodeHeaderValue(tc.value); ok {
				t.Fatalf("DecodeHeaderValue(%q) = %q, true; want failure", tc.value, got)
			}
		})
	}

	t.Run("empty inner sentinel", func(t *testing.T) {
		got, ok := modern.DecodeHeaderValue("=?base64??=")
		if !ok || got != "" {
			t.Fatalf("DecodeHeaderValue(empty sentinel) = %q, %v; want \"\", true", got, ok)
		}
		if !modern.IsSentinel("=?base64??=") {
			t.Fatalf("IsSentinel(empty sentinel) = false, want true")
		}
	})
}

func TestModernTextOfValue(t *testing.T) {
	representable := []struct {
		name  string
		value any
		typ   string
		want  string
	}{
		{"string", "hello", "string", "hello"},
		{"integer 42", 42, "integer", "42"},
		{"integer -7", -7, "integer", "-7"},
		{"integer 0", 0, "integer", "0"},
		{"safe int max", 9007199254740991, "integer", "9007199254740991"},
		{"float64 1e3", float64(1e3), "integer", "1000"},
		{"negative zero", math.Copysign(0, -1), "integer", "0"},
		{"boolean true", true, "boolean", "true"},
		{"boolean false", false, "boolean", "false"},
	}
	for _, tc := range representable {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := modern.TextOfValue(tc.value, tc.typ)
			if !ok {
				t.Fatalf("TextOfValue(%#v, %q) = not ok, want %q", tc.value, tc.typ, tc.want)
			}
			if got != tc.want {
				t.Fatalf("TextOfValue(%#v, %q) = %q, want %q", tc.value, tc.typ, got, tc.want)
			}
		})
	}

	unrepresentable := []struct {
		name  string
		value any
		typ   string
	}{
		{"fraction for integer", 1.5, "integer"},
		{"too large for integer", float64(9007199254740992), "integer"},
		{"number for string", 42, "string"},
		{"string for integer", "42", "integer"},
	}
	for _, tc := range unrepresentable {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := modern.TextOfValue(tc.value, tc.typ); ok {
				t.Fatalf("TextOfValue(%#v, %q) = %q, true; want failure", tc.value, tc.typ, got)
			}
		})
	}
}

func TestModernBuildRequestMirrors(t *testing.T) {
	t.Run("tools call order and meta", func(t *testing.T) {
		got, err := modern.BuildRequestMirrors(modern.ModernMin, "tools/call", map[string]any{"name": "echo"}, nil)
		if err != nil {
			t.Fatalf("BuildRequestMirrors: %v", err)
		}
		wantMeta := map[string]any{
			modern.MetaVersionKey:            modern.ModernMin,
			modern.MetaClientCapabilitiesKey: map[string]any{},
		}
		if !reflect.DeepEqual(got.Meta, wantMeta) {
			t.Fatalf("Meta = %#v, want %#v", got.Meta, wantMeta)
		}
		if _, ok := got.Meta[modern.MetaClientInfoKey]; ok {
			t.Fatalf("Meta carries %q without a client info", modern.MetaClientInfoKey)
		}
		wantHeaders := []modern.Header{
			{Name: "MCP-Protocol-Version", Value: modern.ModernMin},
			{Name: "Mcp-Method", Value: "tools/call"},
			{Name: "Mcp-Name", Value: "echo"},
		}
		if !reflect.DeepEqual(got.Headers, wantHeaders) {
			t.Fatalf("Headers = %#v, want %#v", got.Headers, wantHeaders)
		}
	})

	t.Run("non-ascii name", func(t *testing.T) {
		got, err := modern.BuildRequestMirrors(modern.ModernMin, "tools/call", map[string]any{"name": "世界"}, nil)
		if err != nil {
			t.Fatalf("BuildRequestMirrors: %v", err)
		}
		want := modern.Header{Name: "Mcp-Name", Value: "=?base64?5LiW55WM?="}
		if len(got.Headers) != 3 || got.Headers[2] != want {
			t.Fatalf("Headers = %#v, want last %#v", got.Headers, want)
		}
	})

	t.Run("empty name", func(t *testing.T) {
		got, err := modern.BuildRequestMirrors(modern.ModernMin, "prompts/get", map[string]any{"name": ""}, nil)
		if err != nil {
			t.Fatalf("BuildRequestMirrors: %v", err)
		}
		want := modern.Header{Name: "Mcp-Name", Value: ""}
		if len(got.Headers) != 3 || got.Headers[2] != want {
			t.Fatalf("Headers = %#v, want last %#v", got.Headers, want)
		}
	})

	noName := []string{"server/discover", "events/list"}
	for _, method := range noName {
		t.Run("no name source "+method, func(t *testing.T) {
			got, err := modern.BuildRequestMirrors(modern.ModernMin, method, map[string]any{"name": "echo"}, nil)
			if err != nil {
				t.Fatalf("BuildRequestMirrors: %v", err)
			}
			want := []modern.Header{
				{Name: "MCP-Protocol-Version", Value: modern.ModernMin},
				{Name: "Mcp-Method", Value: method},
			}
			if !reflect.DeepEqual(got.Headers, want) {
				t.Fatalf("Headers = %#v, want %#v", got.Headers, want)
			}
		})
	}

	t.Run("resources read mirrors uri", func(t *testing.T) {
		got, err := modern.BuildRequestMirrors(modern.ModernMin, "resources/read", map[string]any{"uri": "echo://x"}, nil)
		if err != nil {
			t.Fatalf("BuildRequestMirrors: %v", err)
		}
		want := modern.Header{Name: "Mcp-Name", Value: "echo://x"}
		if len(got.Headers) != 3 || got.Headers[2] != want {
			t.Fatalf("Headers = %#v, want last %#v", got.Headers, want)
		}
	})

	t.Run("missing name source", func(t *testing.T) {
		if got, err := modern.BuildRequestMirrors(modern.ModernMin, "tools/call", nil, nil); err == nil {
			t.Fatalf("BuildRequestMirrors = %#v, nil; want error", got)
		}
	})

	t.Run("non-string name source", func(t *testing.T) {
		if got, err := modern.BuildRequestMirrors(modern.ModernMin, "tools/call", map[string]any{"name": 42}, nil); err == nil {
			t.Fatalf("BuildRequestMirrors = %#v, nil; want error", got)
		}
	})

	t.Run("client info when non-nil", func(t *testing.T) {
		info := map[string]any{"name": "jack", "version": "0.1.0"}
		got, err := modern.BuildRequestMirrors(modern.ModernMin, "server/discover", nil, info)
		if err != nil {
			t.Fatalf("BuildRequestMirrors: %v", err)
		}
		wantMeta := map[string]any{
			modern.MetaVersionKey:            modern.ModernMin,
			modern.MetaClientCapabilitiesKey: map[string]any{},
			modern.MetaClientInfoKey:         info,
		}
		if !reflect.DeepEqual(got.Meta, wantMeta) {
			t.Fatalf("Meta = %#v, want %#v", got.Meta, wantMeta)
		}
	})
}

func TestModernValidateAnnotations(t *testing.T) {
	valid := []struct {
		name   string
		schema string
	}{
		{"string", `{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}}`},
		{"integer", `{"type":"object","properties":{"count":{"type":"integer","minimum":0,"maximum":100,"x-mcp-header":"Count"}}}`},
		{"boolean", `{"type":"object","properties":{"flag":{"type":"boolean","x-mcp-header":"Flag"}}}`},
		{"no annotations", `{"type":"object","properties":{"a":{"type":"string"}}}`},
		{"nested properties chain", `{"properties":{"a":{"type":"object","properties":{"b":{"type":"string","x-mcp-header":"B"}}}}}`},
		{"empty property name", `{"properties":{"":{"type":"string","x-mcp-header":"Z"}}}`},
		{"property named x-mcp-header", `{"properties":{"x-mcp-header":{"type":"string"}}}`},
		{"property named properties", `{"properties":{"properties":{"type":"string","x-mcp-header":"P"}}}`},
		{"allOf property named x-mcp-header", `{"properties":{"a":{"type":"string","x-mcp-header":"A"}},"allOf":[{"properties":{"x-mcp-header":{"type":"string"}}}]}`},
	}
	for _, tc := range valid {
		t.Run("valid "+tc.name, func(t *testing.T) {
			got := modern.ValidateAnnotations([]byte(tc.schema))
			if !got.Valid || got.Reason != "" {
				t.Fatalf("ValidateAnnotations(%s) = %#v, want valid", tc.schema, got)
			}
		})
	}

	invalid := []struct {
		name   string
		schema string
		reason string
	}{
		{
			"annotation_name_not_string",
			`{"properties":{"a":{"type":"string","x-mcp-header":5}}}`,
			modern.ReasonAnnotationNameNotString,
		},
		{
			"annotation_name_empty",
			`{"properties":{"a":{"type":"string","x-mcp-header":""}}}`,
			modern.ReasonAnnotationNameEmpty,
		},
		{
			"annotation_name_control",
			`{"properties":{"a":{"type":"string","x-mcp-header":"A\rB"}}}`,
			modern.ReasonAnnotationNameControl,
		},
		{
			"annotation_name_not_token space",
			`{"properties":{"a":{"type":"string","x-mcp-header":"A B"}}}`,
			modern.ReasonAnnotationNameNotToken,
		},
		{
			"annotation_name_not_token colon",
			`{"properties":{"a":{"type":"string","x-mcp-header":"A:B"}}}`,
			modern.ReasonAnnotationNameNotToken,
		},
		{
			"annotation_name_duplicate",
			`{"properties":{"a":{"type":"string","x-mcp-header":"Region"},"b":{"type":"string","x-mcp-header":"region"}}}`,
			modern.ReasonAnnotationNameDuplicate,
		},
		{
			"annotation_type_not_primitive number",
			`{"properties":{"a":{"type":"number","x-mcp-header":"A"}}}`,
			modern.ReasonAnnotationTypeNotPrimitive,
		},
		{
			"annotation_type_not_primitive array",
			`{"properties":{"a":{"type":"array","x-mcp-header":"A"}}}`,
			modern.ReasonAnnotationTypeNotPrimitive,
		},
		{
			"annotation_type_not_primitive missing",
			`{"properties":{"a":{"x-mcp-header":"A"}}}`,
			modern.ReasonAnnotationTypeNotPrimitive,
		},
		{
			"annotation_integer_range_invalid minimum",
			`{"properties":{"a":{"type":"integer","minimum":-9007199254740992,"x-mcp-header":"A"}}}`,
			modern.ReasonAnnotationIntegerRangeInvalid,
		},
		{
			"annotation_integer_range_invalid maximum",
			`{"properties":{"a":{"type":"integer","maximum":9007199254740992,"x-mcp-header":"A"}}}`,
			modern.ReasonAnnotationIntegerRangeInvalid,
		},
		{
			"annotation_not_statically_reachable root",
			`{"type":"object","x-mcp-header":"Root"}`,
			modern.ReasonAnnotationNotStaticallyReachable,
		},
		{
			"annotation_not_statically_reachable items",
			`{"properties":{"a":{"type":"array","items":{"type":"string","x-mcp-header":"X"}}}}`,
			modern.ReasonAnnotationNotStaticallyReachable,
		},
		{
			"annotation_not_statically_reachable oneOf",
			`{"properties":{"a":{"oneOf":[{"type":"string","x-mcp-header":"X"}]}}}`,
			modern.ReasonAnnotationNotStaticallyReachable,
		},
		{
			"annotation_not_statically_reachable allOf",
			`{"allOf":[{"properties":{"a":{"type":"string","x-mcp-header":"A"}}}]}`,
			modern.ReasonAnnotationNotStaticallyReachable,
		},
		{
			"annotation_not_statically_reachable $defs",
			`{"$defs":{"T":{"type":"string","x-mcp-header":"D"}}}`,
			modern.ReasonAnnotationNotStaticallyReachable,
		},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			got := modern.ValidateAnnotations([]byte(tc.schema))
			if got.Valid {
				t.Fatalf("ValidateAnnotations(%s) = valid, want %q", tc.schema, tc.reason)
			}
			if got.Reason != tc.reason {
				t.Fatalf("ValidateAnnotations(%s).Reason = %q, want %q", tc.schema, got.Reason, tc.reason)
			}
		})
	}
}

func TestModernProjectArguments(t *testing.T) {
	one := func(name, typ, headerName string) string {
		return `{"properties":{"` + name + `":{"type":"` + typ + `","x-mcp-header":"` + headerName + `"}}}`
	}

	success := []struct {
		name   string
		schema string
		args   string
		want   []modern.Header
	}{
		{
			"string",
			one("region", "string", "Region"),
			`{"region":"us-west1"}`,
			[]modern.Header{{Name: "Mcp-Param-Region", Value: "us-west1"}},
		},
		{
			"integer",
			one("count", "integer", "Count"),
			`{"count":42}`,
			[]modern.Header{{Name: "Mcp-Param-Count", Value: "42"}},
		},
		{
			"negative integer",
			one("count", "integer", "Count"),
			`{"count":-7}`,
			[]modern.Header{{Name: "Mcp-Param-Count", Value: "-7"}},
		},
		{
			"zero",
			one("count", "integer", "Count"),
			`{"count":0}`,
			[]modern.Header{{Name: "Mcp-Param-Count", Value: "0"}},
		},
		{
			"boolean false",
			one("flag", "boolean", "Flag"),
			`{"flag":false}`,
			[]modern.Header{{Name: "Mcp-Param-Flag", Value: "false"}},
		},
		{
			"empty string",
			one("region", "string", "Region"),
			`{"region":""}`,
			[]modern.Header{{Name: "Mcp-Param-Region", Value: ""}},
		},
		{
			"sentinel value",
			one("region", "string", "Region"),
			`{"region":"=?base64?x?="}`,
			[]modern.Header{{Name: "Mcp-Param-Region", Value: "=?base64?PT9iYXNlNjQ/eD89?="}},
		},
		{
			"nested path",
			`{"properties":{"a":{"type":"object","properties":{"b":{"type":"string","x-mcp-header":"B"}}}}}`,
			`{"a":{"b":"deep"}}`,
			[]modern.Header{{Name: "Mcp-Param-B", Value: "deep"}},
		},
		{
			"absent argument",
			one("region", "string", "Region"),
			`{}`,
			nil,
		},
		{
			"null value",
			one("region", "string", "Region"),
			`{"region":null}`,
			nil,
		},
		{
			"null intermediate",
			`{"properties":{"a":{"type":"object","properties":{"b":{"type":"string","x-mcp-header":"B"}}}}}`,
			`{"a":null}`,
			nil,
		},
		{
			"depth-first order",
			`{"properties":{"a":{"type":"string","x-mcp-header":"A"},"b":{"type":"integer","x-mcp-header":"B"},"c":{"type":"boolean","x-mcp-header":"C"}}}`,
			`{"a":"x","b":1,"c":true}`,
			[]modern.Header{
				{Name: "Mcp-Param-A", Value: "x"},
				{Name: "Mcp-Param-B", Value: "1"},
				{Name: "Mcp-Param-C", Value: "true"},
			},
		},
		{
			"partial arguments",
			`{"properties":{"a":{"type":"string","x-mcp-header":"A"},"b":{"type":"integer","x-mcp-header":"B"},"c":{"type":"boolean","x-mcp-header":"C"}}}`,
			`{"b":2}`,
			[]modern.Header{{Name: "Mcp-Param-B", Value: "2"}},
		},
		{
			"property named x-mcp-header",
			`{"properties":{"x-mcp-header":{"type":"string","x-mcp-header":"H"}}}`,
			`{"x-mcp-header":"v"}`,
			[]modern.Header{{Name: "Mcp-Param-H", Value: "v"}},
		},
	}
	for _, tc := range success {
		t.Run(tc.name, func(t *testing.T) {
			got, err := modern.ProjectArguments([]byte(tc.schema), []byte(tc.args))
			if err != nil {
				t.Fatalf("ProjectArguments: %v", err)
			}
			if len(tc.want) == 0 {
				if len(got) != 0 {
					t.Fatalf("ProjectArguments = %#v, want no headers", got)
				}
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ProjectArguments = %#v, want %#v", got, tc.want)
			}
		})
	}

	mismatch := []struct {
		name   string
		schema string
		args   string
	}{
		{"string for integer", one("count", "integer", "Count"), `{"count":"5"}`},
		{"fraction for integer", one("count", "integer", "Count"), `{"count":1.5}`},
		{"too large for integer", one("count", "integer", "Count"), `{"count":9007199254740992}`},
		{"string for boolean", one("flag", "boolean", "Flag"), `{"flag":"true"}`},
		{"object for string", one("region", "string", "Region"), `{"region":{"a":1}}`},
	}
	for _, tc := range mismatch {
		t.Run(tc.name, func(t *testing.T) {
			got, err := modern.ProjectArguments([]byte(tc.schema), []byte(tc.args))
			if !errors.Is(err, modern.ErrHeaderProjectionInvalidValue) {
				t.Fatalf("ProjectArguments(%s, %s) = %#v, %v; want ErrHeaderProjectionInvalidValue", tc.schema, tc.args, got, err)
			}
		})
	}
}

func TestModernDetectEra(t *testing.T) {
	cases := []struct {
		name           string
		status         int
		verified       bool
		body           string
		clientVersions []string
		wantEra        modern.Era
		wantAction     modern.EraAction
		wantReason     string
		wantSupported  []string
	}{
		{
			name:       "success",
			status:     200,
			verified:   true,
			body:       `{}`,
			wantEra:    modern.EraModern,
			wantAction: modern.ActionStayModern,
		},
		{
			name:       "unsupported protocol version",
			status:     400,
			verified:   true,
			body:       `{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"unsupported protocol version"}}`,
			wantEra:    modern.EraModern,
			wantAction: modern.ActionStayModern,
		},
		{
			name:       "jack envelope",
			status:     400,
			verified:   true,
			body:       `{"error":{"code":"invalid_request","message":"bad request"}}`,
			wantEra:    modern.EraLegacy,
			wantAction: modern.ActionFallbackInitialize,
			wantReason: "jack_envelope",
		},
		{
			name:       "jsonrpc 1.0 with string code",
			status:     400,
			verified:   true,
			body:       `{"jsonrpc":"1.0","id":1,"error":{"code":"invalid_request","message":"bad request"}}`,
			wantEra:    modern.EraLegacy,
			wantAction: modern.ActionFallbackInitialize,
			wantReason: "no_modern_error",
		},
		{
			name:       "unlisted json-rpc code",
			status:     400,
			verified:   true,
			body:       `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid params"}}`,
			wantEra:    modern.EraLegacy,
			wantAction: modern.ActionFallbackInitialize,
			wantReason: "no_modern_error",
		},
		{
			name:           "retry with supported",
			status:         400,
			verified:       true,
			body:           `{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"unsupported client versions","data":{"supported":["2026-07-28","2025-11-25"]}}}`,
			clientVersions: []string{"2025-11-25", "2026-07-28"},
			wantEra:        modern.EraModern,
			wantAction:     modern.ActionRetryWithSupported,
			wantSupported:  []string{"2026-07-28", "2025-11-25"},
		},
		{
			name:           "empty supported list",
			status:         400,
			verified:       true,
			body:           `{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"unsupported client versions","data":{"supported":[]}}}`,
			clientVersions: []string{"2026-07-28"},
			wantEra:        modern.EraModern,
			wantAction:     modern.ActionAbort,
			wantReason:     "unsupported_version_no_overlap",
		},
		{
			name:           "mixed supported list",
			status:         400,
			verified:       true,
			body:           `{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"unsupported client versions","data":{"supported":["2026-07-28",7]}}}`,
			clientVersions: []string{"2026-07-28"},
			wantEra:        modern.EraModern,
			wantAction:     modern.ActionAbort,
			wantReason:     "unsupported_version_no_overlap",
		},
		{
			name:           "no supported data",
			status:         400,
			verified:       true,
			body:           `{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"unsupported client versions"}}`,
			clientVersions: []string{"2026-07-28"},
			wantEra:        modern.EraModern,
			wantAction:     modern.ActionAbort,
			wantReason:     "unsupported_version_no_overlap",
		},
		{
			name:       "modern method not found",
			status:     404,
			verified:   true,
			body:       `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`,
			wantEra:    modern.EraModern,
			wantAction: modern.ActionStayModern,
			wantReason: "modern_method_not_found",
		},
		{
			name:       "bare error object",
			status:     404,
			verified:   true,
			body:       `{"error":{"code":-32601}}`,
			wantEra:    modern.EraLegacy,
			wantAction: modern.ActionFallbackInitialize,
			wantReason: "no_modern_error",
		},
		{
			name:       "method not allowed",
			status:     405,
			verified:   true,
			body:       ``,
			wantEra:    modern.EraLegacy,
			wantAction: modern.ActionFallbackInitialize,
			wantReason: "no_modern_error",
		},
		{
			name:       "server error",
			status:     500,
			verified:   true,
			body:       `{}`,
			wantEra:    modern.EraNone,
			wantAction: modern.ActionAbort,
			wantReason: "no_era_signal",
		},
		{
			name:       "rate limited",
			status:     429,
			verified:   true,
			body:       `{}`,
			wantEra:    modern.EraNone,
			wantAction: modern.ActionAbort,
			wantReason: "no_era_signal",
		},
		{
			name:       "unverified",
			status:     200,
			verified:   false,
			body:       `{}`,
			wantEra:    modern.EraNone,
			wantAction: modern.ActionAbort,
			wantReason: "unverified",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := modern.DetectEra(tc.status, tc.verified, []byte(tc.body), tc.clientVersions)
			if got.Era != tc.wantEra {
				t.Fatalf("Era = %q, want %q", got.Era, tc.wantEra)
			}
			if got.Action != tc.wantAction {
				t.Fatalf("Action = %q, want %q", got.Action, tc.wantAction)
			}
			if got.Reason != tc.wantReason {
				t.Fatalf("Reason = %q, want %q", got.Reason, tc.wantReason)
			}
			if !reflect.DeepEqual(got.Supported, tc.wantSupported) {
				t.Fatalf("Supported = %#v, want %#v", got.Supported, tc.wantSupported)
			}
		})
	}
}

func TestModernDetectEraAttempt(t *testing.T) {
	cases := []struct {
		name             string
		status           int
		verified         bool
		body             string
		clientVersions   []string
		attemptedVersion string
		wantEra          modern.Era
		wantAction       modern.EraAction
		wantReason       string
		wantSupported    []string
	}{
		{
			name:             "unsupported protocol version unchanged",
			status:           400,
			verified:         true,
			body:             `{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"unsupported protocol version"}}`,
			clientVersions:   []string{"2026-07-28"},
			attemptedVersion: "2026-07-28",
			wantEra:          modern.EraModern,
			wantAction:       modern.ActionStayModern,
		},
		{
			name:             "only the attempted version is supported",
			status:           400,
			verified:         true,
			body:             `{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"unsupported client versions","data":{"supported":["2026-07-28"]}}}`,
			clientVersions:   []string{"2026-07-28"},
			attemptedVersion: "2026-07-28",
			wantEra:          modern.EraModern,
			wantAction:       modern.ActionAbort,
			wantReason:       "unsupported_version_no_overlap",
		},
		{
			name:             "filters the attempted version out",
			status:           400,
			verified:         true,
			body:             `{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"unsupported client versions","data":{"supported":["2026-08-01","2025-11-25"]}}}`,
			clientVersions:   []string{"2026-07-28", "2025-11-25"},
			attemptedVersion: "2026-07-28",
			wantEra:          modern.EraModern,
			wantAction:       modern.ActionRetryWithSupported,
			wantSupported:    []string{"2025-11-25"},
		},
		{
			name:             "keeps a different mutually implemented version",
			status:           400,
			verified:         true,
			body:             `{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"unsupported client versions","data":{"supported":["2026-08-01"]}}}`,
			clientVersions:   []string{"2026-07-28", "2026-08-01"},
			attemptedVersion: "2026-07-28",
			wantEra:          modern.EraModern,
			wantAction:       modern.ActionRetryWithSupported,
			wantSupported:    []string{"2026-08-01"},
		},
		{
			name:           "empty attempted version keeps the retry",
			status:         400,
			verified:       true,
			body:           `{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"unsupported client versions","data":{"supported":["2026-07-28"]}}}`,
			clientVersions: []string{"2026-07-28"},
			wantEra:        modern.EraModern,
			wantAction:     modern.ActionRetryWithSupported,
			wantSupported:  []string{"2026-07-28"},
		},
		{
			name:             "jack envelope unchanged",
			status:           400,
			verified:         true,
			body:             `{"error":{"code":"invalid_request","message":"bad request"}}`,
			clientVersions:   []string{"2026-07-28"},
			attemptedVersion: "2026-07-28",
			wantEra:          modern.EraLegacy,
			wantAction:       modern.ActionFallbackInitialize,
			wantReason:       "jack_envelope",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.body)
			got := modern.DetectEraAttempt(tc.status, tc.verified, body, tc.clientVersions, tc.attemptedVersion)
			if got.Era != tc.wantEra {
				t.Fatalf("Era = %q, want %q", got.Era, tc.wantEra)
			}
			if got.Action != tc.wantAction {
				t.Fatalf("Action = %q, want %q", got.Action, tc.wantAction)
			}
			if got.Reason != tc.wantReason {
				t.Fatalf("Reason = %q, want %q", got.Reason, tc.wantReason)
			}
			if !reflect.DeepEqual(got.Supported, tc.wantSupported) {
				t.Fatalf("Supported = %#v, want %#v", got.Supported, tc.wantSupported)
			}
			if tc.attemptedVersion == "" {
				want := modern.DetectEra(tc.status, tc.verified, body, tc.clientVersions)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("empty attempted version = %#v, want DetectEra %#v", got, want)
				}
			}
		})
	}
}

func TestModernResultCache(t *testing.T) {
	now := time.Unix(1700000000, 0)
	key := modern.CacheKey{Method: "tools/call", Params: `{"name":"echo"}`, Era: "modern"}
	value := []byte(`{"ok":true}`)

	t.Run("put get round trip", func(t *testing.T) {
		cache := modern.NewResultCache()
		cache.Put(key, value, 60000, now)
		got, ok := cache.Get(key, now)
		if !ok {
			t.Fatalf("Get after Put = not ok")
		}
		if string(got) != string(value) {
			t.Fatalf("Get = %q, want %q", got, value)
		}
	})

	t.Run("ttl zero is never reused", func(t *testing.T) {
		cache := modern.NewResultCache()
		cache.Put(key, value, 0, now)
		if got, ok := cache.Get(key, now); ok {
			t.Fatalf("Get after zero ttl Put = %q, true; want miss", got)
		}
	})

	t.Run("ttl zero drops an existing entry", func(t *testing.T) {
		cache := modern.NewResultCache()
		cache.Put(key, value, 60000, now)
		cache.Put(key, []byte(`{"other":true}`), 0, now)
		if got, ok := cache.Get(key, now); ok {
			t.Fatalf("Get after zero ttl replacement = %q, true; want miss", got)
		}
	})

	t.Run("expiry at the deadline", func(t *testing.T) {
		cache := modern.NewResultCache()
		cache.Put(key, value, 60000, now)
		if _, ok := cache.Get(key, now.Add(59999*time.Millisecond)); !ok {
			t.Fatalf("Get before the deadline = miss, want hit")
		}
		if got, ok := cache.Get(key, now.Add(60000*time.Millisecond)); ok {
			t.Fatalf("Get at the deadline = %q, true; want miss", got)
		}
		if _, ok := cache.Get(key, now.Add(60000*time.Millisecond)); ok {
			t.Fatalf("Get of the expired entry = hit, want miss")
		}
	})

	t.Run("different keys miss", func(t *testing.T) {
		cache := modern.NewResultCache()
		cache.Put(key, value, 60000, now)
		others := []modern.CacheKey{
			{Method: "tools/list", Params: key.Params, Era: key.Era},
			{Method: key.Method, Params: `{"name":"other"}`, Era: key.Era},
			{Method: key.Method, Params: key.Params, Era: "legacy"},
		}
		for _, other := range others {
			if got, ok := cache.Get(other, now); ok {
				t.Fatalf("Get(%#v) = %q, true; want miss", other, got)
			}
		}
		if _, ok := cache.Get(key, now); !ok {
			t.Fatalf("Get(original) = miss after other keys, want hit")
		}
	})

	t.Run("returned slice is a copy", func(t *testing.T) {
		cache := modern.NewResultCache()
		original := []byte(`{"ok":true}`)
		cache.Put(key, original, 60000, now)
		original[0] = 'X'

		got, ok := cache.Get(key, now)
		if !ok {
			t.Fatalf("Get = not ok")
		}
		if string(got) != `{"ok":true}` {
			t.Fatalf("Get after mutating the input = %q, want %q", got, `{"ok":true}`)
		}
		got[0] = 'Y'

		again, ok := cache.Get(key, now)
		if !ok {
			t.Fatalf("second Get = not ok")
		}
		if string(again) != `{"ok":true}` {
			t.Fatalf("Get after mutating the result = %q, want %q", again, `{"ok":true}`)
		}
	})
}
