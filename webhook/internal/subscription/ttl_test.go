package subscription_test

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/subscription"
)

func TestSubscriptionTTLGrantFinite(t *testing.T) {
	const now = 1767225600
	if subscription.DefaultTTLMs != 3600000 || subscription.MinTTLMs != 60000 || subscription.MaxTTLMs != 86400000 {
		t.Fatal("unexpected TTL constants")
	}
	for _, tc := range []struct {
		name     string
		ttl      subscription.TTLValue
		ms       int64
		deadline string
	}{
		{"default", subscription.TTLValue{}, 3600000, "2026-01-01T01:00:00Z"},
		{"clamp up", subscription.TTLValue{Present: true, MS: 30000}, 60000, "2026-01-01T00:01:00Z"},
		{"clamp zero", subscription.TTLValue{Present: true}, 60000, "2026-01-01T00:01:00Z"},
		{"clamp down", subscription.TTLValue{Present: true, MS: 172800000}, 86400000, "2026-01-02T00:00:00Z"},
		{"whole seconds", subscription.TTLValue{Present: true, MS: 61500}, 61500, "2026-01-01T00:01:01Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := subscription.TTLGrant(tc.ttl, now)
			if err != nil || got.GrantMS == nil || got.RefreshBefore == nil {
				t.Fatalf("TTLGrant = %+v, %v; want a finite grant", got, err)
			}
			if *got.GrantMS != tc.ms || *got.RefreshBefore != tc.deadline {
				t.Errorf("TTLGrant = %d, %q; want %d, %q", *got.GrantMS, *got.RefreshBefore, tc.ms, tc.deadline)
			}
		})
	}
}

func TestSubscriptionTTLGrantNullAndNegative(t *testing.T) {
	const now = 1767225600
	if got, err := subscription.TTLGrant(subscription.TTLValue{Present: true, Null: true}, now); got != (subscription.Grant{}) || err != nil {
		t.Errorf("TTLGrant(null) = %+v, %v; want a null grant and no error", got, err)
	}
	got, err := subscription.TTLGrant(subscription.TTLValue{Present: true, MS: -1}, now)
	want := subscription.KeyError{Code: "invalid_arguments", Reason: "ttl"}
	if got != (subscription.Grant{}) || err == nil || *err != want {
		t.Errorf("TTLGrant(-1) = %+v, %v; want a null grant and %+v", got, err, want)
	}
}

func TestSubscriptionActiveSecretGrace(t *testing.T) {
	current, previous := []byte("current"), []byte("previous")
	const graceEndsAt = 1767225900
	for _, tc := range []struct {
		name        string
		hasPrevious bool
		now         int64
		wantCount   int
	}{
		{"open", true, graceEndsAt - 1, 2},
		{"at deadline", true, graceEndsAt, 1},
		{"after deadline", true, graceEndsAt + 1, 1},
		{"no previous", false, graceEndsAt - 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := subscription.ActiveSecrets(current, previous, tc.hasPrevious, graceEndsAt, tc.now)
			if len(got) != tc.wantCount {
				t.Fatalf("got %d active secrets; want %d", len(got), tc.wantCount)
			}
			if !got[0].Current || !bytes.Equal(got[0].Key, current) {
				t.Errorf("first entry = %+v; want current key", got[0])
			}
			if tc.wantCount == 2 && (got[1].Current || !bytes.Equal(got[1].Key, previous)) {
				t.Errorf("second entry = %+v; want previous key", got[1])
			}
		})
	}
}

func TestSubscriptionGapEnvelopeBytes(t *testing.T) {
	for _, tc := range []struct{ cursor, want string }{
		{"cursor_7f3a", `{"type":"gap","cursor":"cursor_7f3a"}`},
		{"\"\\\x01é<&>\u2028\u2029", `{"type":"gap","cursor":"\"\\\u0001é<&>` + "\u2028\u2029" + `"}`},
	} {
		if got := subscription.GapEnvelope(tc.cursor); string(got) != tc.want {
			t.Errorf("GapEnvelope(%q) = %q; want %q", tc.cursor, got, tc.want)
		}
	}
}

func TestSubscriptionTerminatedEnvelopeBytes(t *testing.T) {
	for _, tc := range []struct {
		code    int64
		message string
		data    json.RawMessage
		want    string
	}{
		{-32024, "Forbidden", nil, `{"type":"terminated","error":{"code":-32024,"message":"Forbidden"}}`},
		{-32024, "Forbidden", json.RawMessage{}, `{"type":"terminated","error":{"code":-32024,"message":"Forbidden"}}`},
		{-32024, "Forbidden", json.RawMessage(" \n{\"reason\" : \"Access revoked\"}\t"), `{"type":"terminated","error":{"code":-32024,"message":"Forbidden","data":{"reason":"Access revoked"}}}`},
		{0, "é<&>\"\t\u2028", json.RawMessage(`{ "z": [ true, { "x": "a b" } ], "a": null }`), `{"type":"terminated","error":{"code":0,"message":"é<&>\"\t` + "\u2028" + `","data":{"z":[true,{"x":"a b"}],"a":null}}}`},
		{math.MinInt64, "", json.RawMessage(`{}`), `{"type":"terminated","error":{"code":-9223372036854775808,"message":"","data":{}}}`},
		{math.MaxInt64, "maximum", nil, `{"type":"terminated","error":{"code":9223372036854775807,"message":"maximum"}}`},
	} {
		got, err := subscription.TerminatedEnvelope(tc.code, tc.message, tc.data)
		if err != nil || string(got) != tc.want {
			t.Errorf("TerminatedEnvelope(%d, %q, %q) = %q, %v; want %q", tc.code, tc.message, tc.data, got, err, tc.want)
		}
	}
}

func TestSubscriptionTerminatedEnvelopeRefusals(t *testing.T) {
	// Non-integer codes and non-string or missing messages cannot be passed
	// through the typed API. All other invalid JSON data shapes can.
	for _, data := range []string{`null`, `[]`, `[{}]`, `"text"`, `42`, `true`, `false`, `{"a":}`, `{`, `{} []`, `{}x`, " \t\r\n", "{\"a\":\"\xff\"}"} {
		got, err := subscription.TerminatedEnvelope(-32024, "Forbidden", json.RawMessage(data))
		if got != nil || err == nil || err.Code != "invalid_envelope" || err.Error() != "invalid_envelope" {
			t.Errorf("TerminatedEnvelope with %q = %q, %v; want invalid_envelope", data, got, err)
		}
	}
}

func TestSubscriptionCursorBoundaries(t *testing.T) {
	if !subscription.CursorOK(nil) {
		t.Fatal("CursorOK(nil) = false")
	}
	if subscription.MaxCursorLen != 512 {
		t.Errorf("MaxCursorLen = %d; want 512", subscription.MaxCursorLen)
	}
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"", false}, {"!", true}, {"~", true}, {"!~", true},
		{strings.Repeat("~", 512), true}, {strings.Repeat("~", 513), false},
		{"a b", false}, {"\t", false}, {"\x00", false}, {"\x7f", false}, {"é", false}, {"\xff", false},
	} {
		if got := subscription.CursorOK(&tc.value); got != tc.want {
			t.Errorf("CursorOK(%q) = %v; want %v", tc.value, got, tc.want)
		}
	}
}
