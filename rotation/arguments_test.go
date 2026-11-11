package rotation_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/rotation"
)

func TestServerKeyArgumentsExactSchemaAndIntegerDomain(t *testing.T) {
	hash := strings.Repeat("A", 43)
	escapedOrdinal := "after_" + string(rune(92)) + "u006frdinal"
	for _, test := range []struct {
		wire string
		cursor rotation.ResultCursor
	}{
		{`{"`+escapedOrdinal+`":0,"after_hash":"-"}`, rotation.ResultCursor{Ordinal:0,Hash:"-"}},
		{`{"after_ordinal":0,"after_hash":"-"}`, rotation.ResultCursor{Ordinal:0,Hash:"-"}},
		{` { "after_hash":"-", "after_ordinal":0 } `, rotation.ResultCursor{Ordinal:0,Hash:"-"}},
		{`{"after_ordinal":-0,"after_hash":"-"}`, rotation.ResultCursor{Ordinal:0,Hash:"-"}},
		{`{"after_ordinal":1,"after_hash":"`+hash+`"}`, rotation.ResultCursor{Ordinal:1,Hash:hash}},
		{`{"after_ordinal":9007199254740991,"after_hash":"`+hash+`"}`, rotation.ResultCursor{Ordinal:rotation.MaxOrdinal,Hash:hash}},
	} {
		cursor,err := rotation.DecodeServerKeyArguments([]byte(test.wire))
		if err != nil || cursor != test.cursor { t.Fatalf("valid cursor rejected: %v",err) }
	}
}

func TestServerKeyArgumentsRejectAmbiguityBeforeObjectDecoding(t *testing.T) {
	hash := strings.Repeat("A",43)
	escapedOrdinal := "after_" + string(rune(92)) + "u006frdinal"
	escapedHash := "after_" + string(rune(92)) + "u0068ash"
	for _, wire := range []string{
		`{"after_ordinal":0,"`+escapedOrdinal+`":0,"after_hash":"-"}`,
		`{"after_ordinal":0,"after_hash":"-","`+escapedHash+`":"-"}`,
		``, `null`, `[]`, `{}`, `true`, `"object"`,
		`{"after_ordinal":0}`, `{"after_hash":"-"}`,
		`{"after_ordinal":0,"after_hash":"-","unknown":null}`,
		`{"after_ordinal":0,"after_ordinal":0,"after_hash":"-"}`,
		`{"after_ordinal":7,"after_ordinal":0,"after_hash":"-"}`,
		`{"after_ordinal":0,"after_hash":"bad","after_hash":"-"}`,
		`{"after_ordinal":0,"after_hash":"-","after_hash":"-"}`,
		`{"after_ordinal":null,"after_hash":"-"}`,
		`{"after_ordinal":false,"after_hash":"-"}`,
		`{"after_ordinal":"0","after_hash":"-"}`,
		`{"after_ordinal":0.0,"after_hash":"-"}`,
		`{"after_ordinal":0e0,"after_hash":"-"}`,
		`{"after_ordinal":0E0,"after_hash":"-"}`,
		`{"after_ordinal":-1,"after_hash":"-"}`,
		`{"after_ordinal":9007199254740992,"after_hash":"`+hash+`"}`,
		`{"after_ordinal":18446744073709551616,"after_hash":"`+hash+`"}`,
		`{"after_ordinal":0,"after_hash":null}`,
		`{"after_ordinal":0,"after_hash":false}`,
		`{"after_ordinal":0,"after_hash":"`+hash+`"}`,
		`{"after_ordinal":1,"after_hash":"-"}`,
		`{"after_ordinal":1,"after_hash":"`+hash+`="}`,
		`{"after_ordinal":1,"after_hash":"`+hash[:42]+`B"}`,
		`{"after_ordinal":1,"after_hash":"\ud800"}`,
		`{"after_ordinal":0,"after_hash":"-"} {}`,
		string([]byte{'{',0xff,'}'}),
	} {
		cursor,err := rotation.DecodeServerKeyArguments([]byte(wire))
		var refusal *rotation.Error
		if !errors.As(err,&refusal) || refusal.Code != "invalid_params" || cursor != (rotation.ResultCursor{}) { t.Fatalf("invalid arguments accepted: %q: %v",wire,err) }
	}
	// Независимый control: last-wins decoder действительно принял бы опасный duplicate.
	ambiguous := []byte(`{"after_ordinal":7,"after_ordinal":0,"after_hash":"-"}`)
	var decoded map[string]any
	if err := json.Unmarshal(ambiguous,&decoded); err != nil || decoded["after_ordinal"] != float64(0) { t.Fatal("duplicate negative fixture does not exercise last-wins ambiguity") }
}
