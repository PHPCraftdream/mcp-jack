package rotation_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/rotation"
)

func TestDecodeResultExactDecimalAboveSafeInteger(t *testing.T) {
	payload := resultPayload(t)
	// Точная канонизация: 9007199254740993 не представим в float64 точно,
	// но канонический текст совпадает byte-for-byte.
	body := resultEnvelope(t, payload, nil, json.RawMessage(`9007199254740993`))
	if _, err := rotation.DecodeResult(body, json.RawMessage(`9007199254740993`)); err != nil {
		t.Fatal("exact lexeme above 2^53 rejected:", err)
	}
	for _, lexeme := range []string{`9007199254740992`, `9007199254740993.0`, `9.007199254740993e15`} {
		var rejected *rotation.Error
		rejectBody := bytes.Replace(body, []byte(`"id":9007199254740993,`), []byte(`"id":`+lexeme+`,`), 1)
		if bytes.Equal(rejectBody, body) {
			t.Fatalf("id lexeme %s was not substituted", lexeme)
		}
		if _, err := rotation.DecodeResult(rejectBody, json.RawMessage(`9007199254740993`)); !errors.As(err, &rejected) || rejected.Code != "rotation_result_invalid" {
			t.Fatalf("lexeme %s accepted: %v", lexeme, err)
		}
	}
	// -0 канонизируется в "0": ожидание -0 принимает ответ 0.
	if _, err := rotation.DecodeResult(resultEnvelope(t, payload, nil, json.RawMessage(`0`)), json.RawMessage(`-0`)); err != nil {
		t.Fatal("-0 expected did not accept response 0:", err)
	}
	// 1e999 за гейтом 2^1024: Number() в TS даёт Infinity — reject с обеих сторон.
	var rejected *rotation.Error
	if _, err := rotation.DecodeResult(resultEnvelope(t, payload, nil, json.RawMessage(`1`)), json.RawMessage(`1e999`)); !errors.As(err, &rejected) || rejected.Code != "rotation_result_invalid" {
		t.Fatalf("1e999 expected accepted: %v", err)
	}
}

func TestDecodeResultRejectsNonCanonicalNumericResponseIDLexemes(t *testing.T) {
	payload := resultPayload(t)
	// json.Marshal отвергает невалидные лексемы (+7, 07, 7.), поэтому id подставляется в готовое тело.
	base := resultEnvelope(t, payload, nil, json.RawMessage(`7`))
	for _, lexeme := range []string{`7.0`, `7e0`, `7E0`, `+7`, `07`, `-0`, `7.`} {
		body := bytes.Replace(base, []byte(`"id":7,`), []byte(`"id":`+lexeme+`,`), 1)
		if bytes.Equal(body, base) {
			t.Fatalf("id lexeme %s was not substituted", lexeme)
		}
		requireResultInvalid(t, body)
	}
	requireResultInvalid(t, resultEnvelope(t, payload, nil, json.RawMessage(`"7"`)))
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
