package subscription_test

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/subscription"
)

func TestSubscriptionJCSNumbers(t *testing.T) {
	for _, tc := range []struct {
		value float64
		want  string
	}{
		{0, "0"},
		{math.Copysign(0, -1), "0"},
		{1, "1"},
		{-1, "-1"},
		{1.5, "1.5"},
		{1e3, "1000"},
		{1e20, "100000000000000000000"},
		{1e21, "1e+21"},
		{1e-6, "0.000001"},
		{1e-7, "1e-7"},
		{-1.25e-7, "-1.25e-7"},
		{123456789012345, "123456789012345"},
		{9007199254740991, "9007199254740991"},
		{math.SmallestNonzeroFloat64, "5e-324"},
		{math.MaxFloat64, "1.7976931348623157e+308"},
	} {
		got, err := subscription.JCS(tc.value)
		if err != nil || got != tc.want {
			t.Errorf("JCS(%g) = %q, %v; want %q", tc.value, got, err, tc.want)
		}
	}
}

func TestSubscriptionJCSDecodedValues(t *testing.T) {
	for _, tc := range []struct {
		input, want string
	}{
		{`{"a":"café"}`, `{"a":"café"}`},
		{`{"\"":"\u0001\\\/\b\f\n\r\t\u001f<&>\u2028\u2029"}`, `{"\"":"\u0001\\/\b\f\n\r\t\u001f<&>` + "\u2028\u2029" + `"}`},
		// U+10000 sorts before U+E000 in UTF-16, unlike in UTF-8.
		{`{"\ue000":3,"\ud800\udc00":2,"z":1,"za":4}`, `{"z":1,"za":4,"` + "\U00010000" + `":2,"` + "\ue000" + `":3}`},
		{` { "b" : [ null, true, false, { "z": -0, "a": [1.0, [], {}] } ], "a" : 1e3 } `, `{"a":1000,"b":[null,true,false,{"a":[1,[],{}],"z":0}]}`},
		{`{"\u00e9":1,"e\u0301":2}`, `{"e` + "\u0301" + `":2,"é":1}`},
	} {
		var value any
		if err := json.Unmarshal([]byte(tc.input), &value); err != nil {
			t.Fatalf("decode %s: %v", tc.input, err)
		}
		got, err := subscription.JCS(value)
		if err != nil || got != tc.want {
			t.Errorf("JCS of %s = %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
}

func TestSubscriptionJCSRefusals(t *testing.T) {
	for _, value := range []any{
		math.NaN(), math.Inf(1), math.Inf(-1), 1, json.Number("1"),
		[]string{"x"}, map[string]string{"x": "y"},
		[]any{map[string]any{"x": math.NaN()}}, "\xff", map[string]any{"\xff": nil},
	} {
		if got, err := subscription.JCS(value); got != "" || err == nil {
			t.Errorf("JCS(%#v) = %q, %v; want an empty result and an error", value, got, err)
		}
	}
}
