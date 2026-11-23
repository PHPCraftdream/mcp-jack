package wire_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/wire"
)

const validOccurrence = `{"eventId":"evt_1","name":"pull_request.opened","timestamp":"2026-01-01T00:00:00Z","data":{"action":"opened"}}`

func TestParseOccurrence(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantCursor string
		hasCursor  bool
	}{
		{"without cursor", validOccurrence, "", false},
		{
			"with cursor",
			`{"eventId":"evt_1","name":"pull_request.opened","timestamp":"2026-01-01T00:00:00Z","data":{"action":"opened"},"cursor":"page-2"}`,
			"page-2", true,
		},
		{
			"null cursor",
			`{"eventId":"evt_1","name":"pull_request.opened","timestamp":"2026-01-01T00:00:00Z","data":{"action":"opened"},"cursor":null}`,
			"", false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			message, reason := wire.Parse([]byte(tc.body))
			if reason != "" {
				t.Fatalf("Parse(%s) reason = %q, want empty", tc.body, reason)
			}
			if message.Kind != wire.KindEvent {
				t.Fatalf("Parse(%s) Kind = %q, want %q", tc.body, message.Kind, wire.KindEvent)
			}
			if message.Type != "" {
				t.Fatalf("Parse(%s) Type = %q, want empty", tc.body, message.Type)
			}
			if (message.Cursor != nil) != tc.hasCursor {
				t.Fatalf("Parse(%s) Cursor = %v, want present = %v", tc.body, message.Cursor, tc.hasCursor)
			}
			if tc.hasCursor && *message.Cursor != tc.wantCursor {
				t.Fatalf("Parse(%s) Cursor = %q, want %q", tc.body, *message.Cursor, tc.wantCursor)
			}
		})
	}
}

func TestParseTimestampShapes(t *testing.T) {
	cases := []struct {
		name       string
		timestamp  string
		wantReason string
	}{
		{"fraction and offset", "2026-01-01T01:30:00.500+01:30", ""},
		{"leap day", "2024-02-29T12:00:00Z", ""},
		{"non leap day", "2025-02-29T12:00:00Z", "malformed_body"},
		{"impossible february", "2026-02-30T12:00:00Z", "malformed_body"},
		{"date only", "2026-01-01", "malformed_body"},
		{"no zone", "2026-01-01T00:00:00", "malformed_body"},
		{"not a date", "not-a-date", "malformed_body"},
		{"hour 24", "2026-01-01T24:00:00Z", "malformed_body"},
		{"minute 60", "2026-01-01T00:60:00Z", "malformed_body"},
		{"second 60", "2026-01-01T00:00:60Z", "malformed_body"},
		{"offset hour 24", "2026-01-01T00:00:00+24:00", "malformed_body"},
		{"offset minute 60", "2026-01-01T00:00:00+00:60", "malformed_body"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"eventId":"evt_1","name":"pull_request.opened","timestamp":%q,"data":{}}`, tc.timestamp)
			message, reason := wire.Parse([]byte(body))
			if reason != tc.wantReason {
				t.Fatalf("Parse(timestamp %q) reason = %q, want %q", tc.timestamp, reason, tc.wantReason)
			}
			if tc.wantReason == "" && message.Kind != wire.KindEvent {
				t.Fatalf("Parse(timestamp %q) Kind = %q, want %q", tc.timestamp, message.Kind, wire.KindEvent)
			}
		})
	}
}

func TestParseOccurrenceRejectedFields(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"data array", `{"eventId":"evt_1","name":"n","timestamp":"2026-01-01T00:00:00Z","data":[]}`},
		{"data string", `{"eventId":"evt_1","name":"n","timestamp":"2026-01-01T00:00:00Z","data":"x"}`},
		{"data null", `{"eventId":"evt_1","name":"n","timestamp":"2026-01-01T00:00:00Z","data":null}`},
		{"missing data", `{"eventId":"evt_1","name":"n","timestamp":"2026-01-01T00:00:00Z"}`},
		{"missing eventId", `{"name":"n","timestamp":"2026-01-01T00:00:00Z","data":{}}`},
		{"missing name", `{"eventId":"evt_1","timestamp":"2026-01-01T00:00:00Z","data":{}}`},
		{"missing timestamp", `{"eventId":"evt_1","name":"n","data":{}}`},
		{"empty eventId", `{"eventId":"","name":"n","timestamp":"2026-01-01T00:00:00Z","data":{}}`},
		{"empty name", `{"eventId":"evt_1","name":"","timestamp":"2026-01-01T00:00:00Z","data":{}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			message, reason := wire.Parse([]byte(tc.body))
			if reason != "malformed_body" {
				t.Fatalf("Parse(%s) reason = %q, want %q", tc.body, reason, "malformed_body")
			}
			if message.Kind != "" {
				t.Fatalf("Parse(%s) Kind = %q, want empty", tc.body, message.Kind)
			}
		})
	}
}

func TestParseUnknownEnvelopeType(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"unrecognised string type", `{"type":"paging"}`},
		{"numeric type", `{"type":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			message, reason := wire.Parse([]byte(tc.body))
			if reason != "unknown_envelope_type" {
				t.Fatalf("Parse(%s) reason = %q, want %q", tc.body, reason, "unknown_envelope_type")
			}
			if message.Kind != "" {
				t.Fatalf("Parse(%s) Kind = %q, want empty", tc.body, message.Kind)
			}
		})
	}
}

func TestParseGap(t *testing.T) {
	message, reason := wire.Parse([]byte(`{"type":"gap","cursor":"next-page"}`))
	if reason != "" {
		t.Fatalf("Parse(gap) reason = %q, want empty", reason)
	}
	if message.Kind != wire.KindGap {
		t.Fatalf("Parse(gap) Kind = %q, want %q", message.Kind, wire.KindGap)
	}
	if message.Type != "gap" {
		t.Fatalf("Parse(gap) Type = %q, want %q", message.Type, "gap")
	}
	if message.Cursor == nil || *message.Cursor != "next-page" {
		t.Fatalf("Parse(gap) Cursor = %v, want %q", message.Cursor, "next-page")
	}

	cases := []struct {
		name string
		body string
	}{
		{"missing cursor", `{"type":"gap"}`},
		{"cursor number", `{"type":"gap","cursor":7}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			message, reason := wire.Parse([]byte(tc.body))
			if reason != "malformed_body" {
				t.Fatalf("Parse(%s) reason = %q, want %q", tc.body, reason, "malformed_body")
			}
			if message.Kind != "" {
				t.Fatalf("Parse(%s) Kind = %q, want empty", tc.body, message.Kind)
			}
		})
	}
}

func TestParseTerminated(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantReason string
	}{
		{
			name:       "ok",
			body:       `{"type":"terminated","error":{"code":-32024,"message":"budget exhausted"}}`,
			wantReason: "",
		},
		{
			name:       "object data",
			body:       `{"type":"terminated","error":{"code":-32024,"message":"budget exhausted","data":{"reason":"budget"}}}`,
			wantReason: "",
		},
		{
			name:       "integral exponent code",
			body:       `{"type":"terminated","error":{"code":1e3,"message":"bye"}}`,
			wantReason: "",
		},
		{
			name:       "top level data is ignored",
			body:       `{"type":"terminated","error":{"code":1,"message":"bye"},"data":[1,2]}`,
			wantReason: "",
		},
		{
			name:       "string code",
			body:       `{"type":"terminated","error":{"code":"-32024","message":"bye"}}`,
			wantReason: "malformed_body",
		},
		{
			name:       "fractional code",
			body:       `{"type":"terminated","error":{"code":-32024.5,"message":"bye"}}`,
			wantReason: "malformed_body",
		},
		{
			name:       "missing message",
			body:       `{"type":"terminated","error":{"code":-32024}}`,
			wantReason: "malformed_body",
		},
		{
			name:       "numeric message",
			body:       `{"type":"terminated","error":{"code":-32024,"message":403}}`,
			wantReason: "malformed_body",
		},
		{
			name:       "null data",
			body:       `{"type":"terminated","error":{"code":-32024,"message":"bye","data":null}}`,
			wantReason: "malformed_body",
		},
		{
			name:       "array data",
			body:       `{"type":"terminated","error":{"code":-32024,"message":"bye","data":[]}}`,
			wantReason: "malformed_body",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			message, reason := wire.Parse([]byte(tc.body))
			if reason != tc.wantReason {
				t.Fatalf("Parse(%s) reason = %q, want %q", tc.body, reason, tc.wantReason)
			}
			if tc.wantReason != "" {
				if message.Kind != "" {
					t.Fatalf("Parse(%s) Kind = %q, want empty", tc.body, message.Kind)
				}
				return
			}
			if message.Kind != wire.KindTerminated {
				t.Fatalf("Parse(%s) Kind = %q, want %q", tc.body, message.Kind, wire.KindTerminated)
			}
			if message.Type != "terminated" {
				t.Fatalf("Parse(%s) Type = %q, want %q", tc.body, message.Type, "terminated")
			}
			if message.Cursor != nil {
				t.Fatalf("Parse(%s) Cursor = %v, want nil", tc.body, message.Cursor)
			}
		})
	}
}

func TestParseMalformedBodies(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"array body", `[1,2]`},
		{"string body", `"hello"`},
		{"invalid json", `{"eventId":`},
		{"null body", `null`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			message, reason := wire.Parse([]byte(tc.body))
			if reason != "malformed_body" {
				t.Fatalf("Parse(%s) reason = %q, want %q", tc.body, reason, "malformed_body")
			}
			if message.Kind != "" {
				t.Fatalf("Parse(%s) Kind = %q, want empty", tc.body, message.Kind)
			}
		})
	}
}

func TestParseRawIsCopy(t *testing.T) {
	body := []byte(validOccurrence)
	snapshot := append([]byte(nil), body...)
	message, reason := wire.Parse(body)
	if reason != "" {
		t.Fatalf("Parse(occurrence) reason = %q, want empty", reason)
	}
	if !bytes.Equal(message.Raw, snapshot) {
		t.Fatalf("Parse(occurrence) Raw = %s, want a copy of %s", message.Raw, snapshot)
	}
	message.Raw[0] = 'X'
	if !bytes.Equal(body, snapshot) {
		t.Fatalf("mutating Raw changed the input body: got %s, want %s", body, snapshot)
	}
}

func TestParseObjectMembers(t *testing.T) {
	message, reason := wire.Parse([]byte(validOccurrence))
	if reason != "" {
		t.Fatalf("Parse(occurrence) reason = %q, want empty", reason)
	}
	if got := message.Object["eventId"]; got != "evt_1" {
		t.Fatalf("Object[eventId] = %v, want %q", got, "evt_1")
	}
	if got := message.Object["name"]; got != "pull_request.opened" {
		t.Fatalf("Object[name] = %v, want %q", got, "pull_request.opened")
	}
	if got := message.Object["timestamp"]; got != "2026-01-01T00:00:00Z" {
		t.Fatalf("Object[timestamp] = %v, want %q", got, "2026-01-01T00:00:00Z")
	}
	data, ok := message.Object["data"].(map[string]any)
	if !ok {
		t.Fatalf("Object[data] = %T, want map[string]any", message.Object["data"])
	}
	if got := data["action"]; got != "opened" {
		t.Fatalf("Object[data][action] = %v, want %q", got, "opened")
	}
}
