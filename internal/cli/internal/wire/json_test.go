package wire

import (
	"encoding/json"
	"testing"
)

func TestResponseErrorCodeStrictInteger(t *testing.T) {
	for _, tc := range []struct {
		code  string
		valid bool
	}{
		{"-32603", true}, {"0", true}, {"null", false}, {`"-32603"`, false},
		{"1.5", false}, {"1e2", false}, {"true", false}, {"{}", false},
	} {
		t.Run(tc.code, func(t *testing.T) {
			body := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":` + tc.code + `,"message":"failure"}}`)
			_, err := ResponseObject(body, json.RawMessage("1"))
			if (err == nil) != tc.valid {
				t.Fatal("error code type accepted incorrectly")
			}
		})
	}
}

func TestObjectRejectsCaseVariantDuplicateMembers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		allowed bool
	}{
		{"flat request", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, true},
		{"nested distinct names", `{"params":{"a":1},"meta":{"A":2}}`, true},
		{"shared prefix only", `{"method":1,"methodX":2}`, true},
		{"case-variant flat", `{"jsonrpc":"2.0","method":"ping","Method":"notifications/cancelled"}`, false},
		{"case-variant nested", `{"params":{"a":1,"A":2}}`, false},
		{"case-variant inside array is data", `{"params":[{"a":1,"A":2}]}`, true},
		{"case-variant arguments are data", `{"method":"tools/call","params":{"name":"t","arguments":{"Path":1,"PATH":2}}}`, true},
		{"case-variant params name", `{"method":"tools/call","params":{"name":"t","Name":"jack.enroll"}}`, false},
		{"exact duplicate inside arguments", `{"params":{"arguments":{"a":1,"a":2}}}`, false},
		{"case-variant escaped name", `{"meth\u006F\u0064":1,"Method":2}`, false},
		{"identical duplicate", `{"a":1,"a":2}`, false},
		{"escaped identical duplicate", `{"a":1,"\u0061":2}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Object([]byte(tc.body))
			if (err == nil) != tc.allowed {
				t.Fatalf("object(%s) err = %v, want accepted = %v", tc.body, err, tc.allowed)
			}
		})
	}
}
