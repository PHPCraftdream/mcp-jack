package rpcbody

import (
	"testing"
)

// TestClassifyBodyDuplicateMembers pins that a repeated member name at any
// depth makes the body unacceptable, while equal names in different objects
// are fine.
func TestClassifyBodyDuplicateMembers(t *testing.T) {
	cases := []struct {
		name string
		body string
		ok   bool
	}{
		{"top level", `{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}`, false},
		{"nested in params", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":1,"a":2}}`, false},
		{"object inside an array", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":[{"k":1},{"k":1,"k":2}]}}`, false},
		{"free-form tool arguments", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"q":{"z":1,"z":1}}}}`, false},
		{"escaped name", `{"jsonrpc":"2.0","id":1,"meth\u006fd":"ping","method":"ping"}`, false},
		{"same names in different objects", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":{"k":1},"b":{"k":2},"c":[{"k":3},{"k":4}]}}`, true},
		{"name equal to a string value", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":"a","b":"a"}}`, true},
		{"case differs", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":1,"A":2}}`, true},
		// A huge number literal must not abort the duplicate scan: without
		// UseNumber the token decoder errors on 1e999 and a duplicate after
		// it would be missed.
		{"1e999 then duplicate", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":1e999,"x":2}}`, false},
		{"1e999 without duplicates", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":1e999,"y":2}}`, true},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if _, ok := Classify([]byte(c.body)); ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
		})
	}
}
