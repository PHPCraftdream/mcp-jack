package rotation_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

func resultPayload(t *testing.T) []byte {
	t.Helper()
	vectors, _, _, _ := fixture(t)
	anchor := vectors.Keys["anchor"]
	return []byte(`{"current":{"kid":"` + anchor.KID + `","public_key":"` + anchor.Public + `"},"records":[],"head":{"ordinal":0,"hash":"-"},"complete":true}`)
}

func resultEnvelope(t *testing.T, payload, mirror []byte, id json.RawMessage) []byte {
	t.Helper()
	if mirror == nil {
		mirror = payload
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": id,
		"result": map[string]any{
			"content": []any{map[string]any{"type": "text", "text": string(mirror)}},
			"structuredContent": json.RawMessage(payload), "isError": false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func requireResultInvalid(t *testing.T, body []byte) {
	t.Helper()
	_, err := rotation.DecodeResult(body, json.RawMessage(`7`))
	var rejected *rotation.Error
	if !errors.As(err, &rejected) || rejected.Code != "rotation_result_invalid" {
		t.Fatalf("invalid result accepted or misclassified: %v", err)
	}
}

func TestDecodeResultExactSchemaParityOwnershipAndScalarIDs(t *testing.T) {
	payload := resultPayload(t)
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatal(err)
	}
	mirror, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []json.RawMessage{[]byte(`7`), []byte(`1.5`), []byte(`"request-😀"`), []byte(`"literal\\ud800"`), []byte(`"say\"hi"`), []byte(`"�"`)} {
		body := resultEnvelope(t, payload, mirror, id)
		result, err := rotation.DecodeResult(body, id)
		if err != nil || result.Head.Ordinal != 0 || result.Head.Hash != "-" || !result.Complete || len(result.Records) != 0 || jack.KeyID(result.Current.PublicKey[:]) != result.Current.KID {
			t.Fatalf("valid result: %+v %v", result, err)
		}
		before := result.Current.KID
		clear(body)
		if result.Current.KID != before {
			t.Fatal("decoded data aliased mutable body")
		}
	}
	body := resultEnvelope(t, payload, nil, json.RawMessage(`7`))
	_, err = rotation.DecodeResult(body, json.RawMessage(`7e0`))
	if err == nil {
		t.Fatal("numeric ID lexeme mismatch accepted")
	}
}

func TestDecodeResultRejectsDuplicateExtraTypeLexicalAndSurrogateErrors(t *testing.T) {
	payload := string(resultPayload(t))
	for _, changed := range []string{
		strings.Replace(payload, `"complete":true`, `"complete":true,"complete":true`, 1),
		strings.Replace(payload, `"ordinal":0`, `"ordinal":0,"ordinal":0`, 1),
		strings.Replace(payload, `"kid":`, `"kid":"duplicate","kid":`, 1),
		strings.Replace(payload, `"complete":true`, `"complete":true,"extra":1`, 1),
		strings.Replace(payload, `"complete":true`, `"complete":null`, 1),
		strings.Replace(payload, `"records":[]`, `"records":{}`, 1),
		strings.Replace(payload, `"records":[]`, `"records":["\ud800"]`, 1),
		strings.Replace(payload, `"records":[]`, `"records":["\udc00"]`, 1),
		strings.Replace(payload, `"ordinal":0`, `"ordinal":-0`, 1),
		strings.Replace(payload, `"ordinal":0`, `"ordinal":0.0`, 1),
		strings.Replace(payload, `"ordinal":0`, `"ordinal":0e0`, 1),
		strings.Replace(payload, `"hash":"-"`, `"hash":"wrong"`, 1),
	} {
		requireResultInvalid(t, resultEnvelope(t, []byte(changed), nil, json.RawMessage(`7`)))
		requireResultInvalid(t, resultEnvelope(t, []byte(payload), []byte(changed), json.RawMessage(`7`)))
	}
	ordinary := resultEnvelope(t, []byte(payload), nil, json.RawMessage(`7`))
	for _, body := range [][]byte{
		bytes.Replace(ordinary, []byte(`"jsonrpc":"2.0"`), []byte(`"jsonrpc":"2.0","jsonrpc":"2.0"`), 1),
		bytes.Replace(ordinary, []byte(`"isError":false`), []byte(`"isError":false,"isError":false`), 1),
		bytes.Replace(ordinary, []byte(`"type":"text"`), []byte(`"type":"text","extra":1`), 1),
		bytes.Replace(ordinary, []byte(`"isError":false`), []byte(`"isError":true`), 1),
		[]byte{0xff},
	} {
		requireResultInvalid(t, body)
	}
	other := strings.Replace(payload, `"complete":true`, `"complete":false`, 1)
	requireResultInvalid(t, resultEnvelope(t, []byte(payload), []byte(other), json.RawMessage(`7`)))
}

func TestDecodeResultFullBodyAndPageCapsHavePositiveEqualityControls(t *testing.T) {
	payload := resultPayload(t)
	body := resultEnvelope(t, payload, nil, json.RawMessage(`7`))
	exact := append(append([]byte(nil), body...), bytes.Repeat([]byte(" "), rotation.MaxResultBodyBytes-len(body))...)
	if _, err := rotation.DecodeResult(exact, json.RawMessage(`7`)); err != nil {
		t.Fatal("inclusive full-body cap:", err)
	}
	requireResultInvalid(t, append(exact, ' '))
	vectors, _, _, _ := fixture(t)
	var value map[string]any
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatal(err)
	}
	rows := make([]string, 16)
	for index := range rows {
		rows[index] = vectors.Chains["overlapping"][0]
	}
	value["records"] = rows
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := rotation.DecodeResult(resultEnvelope(t, encoded, nil, json.RawMessage(`7`)), json.RawMessage(`7`)); err != nil || len(decoded.Records) != 16 {
		t.Fatalf("inclusive page cap: %v", err)
	}
	value["records"] = append(rows, rows[0])
	encoded, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	requireResultInvalid(t, resultEnvelope(t, encoded, nil, json.RawMessage(`7`)))
}
