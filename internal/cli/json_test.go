package cli

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
			_, err := responseObject(body, json.RawMessage("1"))
			if (err == nil) != tc.valid {
				t.Fatal("error code type accepted incorrectly")
			}
		})
	}
}
