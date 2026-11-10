package rotation

import (
	"encoding/json"
	"reflect"
	"strconv"

	jack "github.com/PHPCraftdream/mcp-jack"
)

const MaxResultBodyBytes = 256 << 10
const MaxPageRecords = 16

type CurrentKey struct {
	KID       string
	PublicKey [32]byte
}

type ResultCursor struct {
	Ordinal uint64
	Hash    string
}

// DecodedResult — owned schema data, не authenticated carrier или ACKed trust.
type DecodedResult struct {
	Current  CurrentKey
	Records  []string
	Head     ResultCursor
	Complete bool
}

func fields(value any, names ...string) (map[string]any, bool) {
	object, ok := value.(map[string]any)
	if !ok || len(object) != len(names) {
		return nil, false
	}
	for _, name := range names {
		if _, exists := object[name]; !exists {
			return nil, false
		}
	}
	return object, true
}

func structuredResult(value any) (DecodedResult, error) {
	fail := func() (DecodedResult, error) { return DecodedResult{}, invalid("rotation_result_invalid") }
	object, ok := fields(value, "current", "records", "head", "complete")
	if !ok {
		return fail()
	}
	current, ok := fields(object["current"], "kid", "public_key")
	if !ok {
		return fail()
	}
	kid, kidOK := current["kid"].(string)
	encoded, publicOK := current["public_key"].(string)
	public, err := jack.DecodeBase64URLFixed(encoded, 32)
	if !kidOK || !publicOK || err != nil || jack.ValidatePublicKey(public) != nil || jack.KeyID(public) != kid {
		return fail()
	}
	head, ok := fields(object["head"], "ordinal", "hash")
	if !ok {
		return fail()
	}
	number, numberOK := head["ordinal"].(json.Number)
	ordinal, err := strconv.ParseUint(number.String(), 10, 64)
	hash, hashOK := head["hash"].(string)
	if !numberOK || err != nil || ordinal > MaxOrdinal || !hashOK {
		return fail()
	}
	if ordinal == 0 {
		if hash != "-" {
			return fail()
		}
	} else if _, err := jack.DecodeBase64URLFixed(hash, 32); err != nil {
		return fail()
	}
	rows, rowsOK := object["records"].([]any)
	complete, completeOK := object["complete"].(bool)
	if !rowsOK || len(rows) > MaxPageRecords || !completeOK {
		return fail()
	}
	result := DecodedResult{Current: CurrentKey{KID: kid}, Records: make([]string, len(rows)), Head: ResultCursor{Ordinal: ordinal, Hash: hash}, Complete: complete}
	copy(result.Current.PublicKey[:], public)
	for index, row := range rows {
		wire, ok := row.(string)
		if !ok {
			return fail()
		}
		result.Records[index] = wire
	}
	return result, nil
}

// DecodeResult вызывать только после outer authentication, known interval и ClockGuard.
// Проверяет success schema/parity/limits, не proofs/cursor/gaps/current binding;
// не выполняет ACK, persistence, fetch или refresh. Signed errors обрабатывает caller.
func DecodeResult(body []byte, expectedID json.RawMessage) (DecodedResult, error) {
	fail := func() (DecodedResult, error) { return DecodedResult{}, invalid("rotation_result_invalid") }
	if len(body) == 0 || len(body) > MaxResultBodyBytes {
		return fail()
	}
	expected, err := strictJSON(expectedID)
	if err != nil {
		return fail()
	}
	switch expected.(type) {
	case string, json.Number:
	default:
		return fail()
	}
	value, err := strictJSON(body)
	if err != nil {
		return fail()
	}
	root, ok := fields(value, "jsonrpc", "id", "result")
	if !ok || root["jsonrpc"] != "2.0" || !reflect.DeepEqual(root["id"], expected) {
		return fail()
	}
	result, ok := fields(root["result"], "content", "structuredContent", "isError")
	if !ok || result["isError"] != false {
		return fail()
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) != 1 {
		return fail()
	}
	item, ok := fields(content[0], "type", "text")
	if !ok || item["type"] != "text" {
		return fail()
	}
	text, ok := item["text"].(string)
	if !ok {
		return fail()
	}
	mirror, err := strictJSON([]byte(text))
	if err != nil {
		return fail()
	}
	decoded, err := structuredResult(result["structuredContent"])
	if err != nil {
		return fail()
	}
	if _, err := structuredResult(mirror); err != nil || !reflect.DeepEqual(result["structuredContent"], mirror) {
		return fail()
	}
	return decoded, nil
}
