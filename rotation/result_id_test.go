package rotation_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/rotation"
)

func TestDecodeResultRejectsNonCanonicalNumericResponseIDLexemes(t *testing.T) {
	payload := resultPayload(t)
	for _, lexeme := range []json.RawMessage{
		[]byte(`7.0`), []byte(`7e0`), []byte(`7E0`), []byte(`+7`), []byte(`07`), []byte(`-0`), []byte(`7.`),
	} {
		requireResultInvalid(t, resultEnvelope(t, payload, nil, lexeme))
	}
	requireResultInvalid(t, resultEnvelope(t, payload, nil, []byte(`"7"`)))
}

func TestDecodeResultRejectsNumberResponseForStringExpectedID(t *testing.T) {
	payload := resultPayload(t)
	body := resultEnvelope(t, payload, nil, json.RawMessage(`7`))
	_, err := rotation.DecodeResult(body, json.RawMessage(`"7"`))
	var rejected *rotation.Error
	if !errors.As(err, &rejected) || rejected.Code != "rotation_result_invalid" {
		t.Fatalf("number response for string expected id accepted: %v", err)
	}
}

func TestDecodeResultCanonicalResponseMatchesNonCanonicalExpectedID(t *testing.T) {
	payload := resultPayload(t)
	if _, err := rotation.DecodeResult(resultEnvelope(t, payload, nil, json.RawMessage(`7`)), json.RawMessage(`7e0`)); err != nil {
		t.Fatal("canonical response for 7e0 expected id rejected:", err)
	}
	requireResultInvalid(t, resultEnvelope(t, payload, nil, json.RawMessage(`7e0`)))
	if _, err := rotation.DecodeResult(resultEnvelope(t, payload, nil, json.RawMessage(`0`)), json.RawMessage(`-0`)); err != nil {
		t.Fatal("canonical response for -0 expected id rejected:", err)
	}
	requireResultInvalid(t, resultEnvelope(t, payload, nil, json.RawMessage(`-0`)))
}
