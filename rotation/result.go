package rotation

import (
	"encoding/json"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/rotation/internal/strictjson"
)

func strictJSON(data []byte) (any, error) {
	value, err := strictjson.Scan(data)
	if err != nil {
		return nil, invalid("rotation_result_invalid")
	}
	return value, nil
}

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

// DecodedResult — owned schema data, not an authenticated carrier or ACKed trust.
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

// canonicalNumber returns the canonical JSON text of a numeric id: exact
// decimal canonicalization without float. Rejects |value| >= 2^1024, the point
// where Number() in TS yields Infinity.
func canonicalNumber(number json.Number) (string, bool) {
	negative, digits, exponent, ok := parseNumberLexeme(number.String())
	if !ok || !withinFloatRange(digits, exponent) {
		return "", false
	}
	return canonicalDecimal(negative, digits, exponent), true
}

// parseNumberLexeme checks the JSON number grammar
// -?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)? and splits the lexeme into:
// sign, concatenated digits int+frac, E = exp - len(frac).
func parseNumberLexeme(text string) (bool, string, int, bool) {
	rest := text
	negative := false
	if len(rest) > 0 && rest[0] == '-' {
		negative, rest = true, rest[1:]
	}
	mantissa, expText := rest, ""
	if index := strings.IndexAny(rest, "eE"); index >= 0 {
		mantissa, expText = rest[:index], rest[index+1:]
	}
	intPart, fracPart := mantissa, ""
	if index := strings.IndexByte(mantissa, '.'); index >= 0 {
		intPart, fracPart = mantissa[:index], mantissa[index+1:]
	}
	if !allDigits(intPart) || (len(intPart) > 1 && intPart[0] == '0') {
		return false, "", 0, false
	}
	if index := strings.IndexByte(mantissa, '.'); index >= 0 && !allDigits(fracPart) {
		return false, "", 0, false
	}
	exponent := -len(fracPart)
	if expText != "" {
		sign := 1
		if expText[0] == '+' || expText[0] == '-' {
			if expText[0] == '-' {
				sign = -1
			}
			expText = expText[1:]
		}
		if !allDigits(expText) {
			return false, "", 0, false
		}
		parsed, err := strconv.Atoi(expText)
		if err != nil {
			return false, "", 0, false
		}
		exponent += sign * parsed
	}
	return negative, intPart + fracPart, exponent, true
}

func allDigits(text string) bool {
	if text == "" {
		return false
	}
	for index := 0; index < len(text); index++ {
		if text[index] < '0' || text[index] > '9' {
			return false
		}
	}
	return true
}

// withinFloatRange is an exact |value| < 2^1024 gate via math/big:
// E >= 0 compares D·10^E with 2^1024, E < 0 compares D with 2^1024·10^(-E).
// Outside the f64 range the gate can be closed immediately: 10^309 > 2^1024;
// E < -MaxResultBodyBytes ⇒ the canonical text is longer than the body limit
// and cannot match the lexeme in an accepted response byte-for-byte.
func withinFloatRange(digits string, exponent int) bool {
	if exponent > 308 {
		return false
	}
	if -exponent > MaxResultBodyBytes {
		return false
	}
	value, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		return false
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 1024)
	if exponent >= 0 {
		value.Mul(value, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(exponent)), nil))
	} else {
		limit.Mul(limit, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(-exponent)), nil))
	}
	return value.Cmp(limit) < 0
}

// canonicalDecimal is the shortest decimal form without an exponent;
// leading/trailing zeros are removed, -0 → "0", minus sign only on nonzero values.
func canonicalDecimal(negative bool, digits string, exponent int) string {
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return "0"
	}
	var text string
	if exponent >= 0 {
		text = digits + strings.Repeat("0", exponent)
	} else {
		split := -exponent
		integer := "0"
		fraction := digits
		if len(digits) > split {
			integer, fraction = digits[:len(digits)-split], digits[len(digits)-split:]
		} else {
			fraction = strings.Repeat("0", split-len(digits)) + digits
		}
		fraction = strings.TrimRight(fraction, "0")
		if fraction == "" {
			text = integer
		} else {
			text = integer + "." + fraction
		}
	}
	if negative {
		text = "-" + text
	}
	return text
}

// idMatches compares the response id with the expected one: strings by decoded
// value, numbers byte-for-byte with the canonical text of the expected value.
func idMatches(actual, expected any) bool {
	switch expectedValue := expected.(type) {
	case string:
		actualValue, ok := actual.(string)
		return ok && actualValue == expectedValue
	case json.Number:
		text, ok := canonicalNumber(expectedValue)
		number, numberOK := actual.(json.Number)
		return ok && numberOK && number.String() == text
	default:
		return false
	}
}

// DecodeResult call only after outer authentication, known interval and ClockGuard.
// Checks success schema/parity/limits, not proofs/cursor/gaps/current binding;
// performs no ACK, persistence, fetch or refresh. The caller handles signed errors.
func DecodeResult(body []byte, expectedID json.RawMessage) (DecodedResult, error) {
	fail := func() (DecodedResult, error) { return DecodedResult{}, invalid("rotation_result_invalid") }
	if len(body) == 0 || len(body) > MaxResultBodyBytes {
		return fail()
	}
	expected, err := strictJSON(expectedID)
	if err != nil {
		return fail()
	}
	value, err := strictJSON(body)
	if err != nil {
		return fail()
	}
	root, ok := fields(value, "jsonrpc", "id", "result")
	if !ok || root["jsonrpc"] != "2.0" || !idMatches(root["id"], expected) {
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

// DecodeServerKeyArguments checks the original member sequence, not a last-wins map.
// The caller bounds the complete request body before the call; parsing grants no checkpoint authority.
func DecodeServerKeyArguments(data []byte) (ResultCursor, error) {
	refuse := func() (ResultCursor, error) { return ResultCursor{}, invalid("invalid_params") }
	value, err := strictJSON(data)
	if err != nil {
		return refuse()
	}
	object, ok := fields(value, "after_ordinal", "after_hash")
	if !ok {
		return refuse()
	}
	number, ok := object["after_ordinal"].(json.Number)
	if !ok || strings.ContainsAny(number.String(), ".eE") {
		return refuse()
	}
	ordinal, err := strconv.ParseInt(number.String(), 10, 64)
	if err != nil || ordinal < 0 || uint64(ordinal) > MaxOrdinal {
		return refuse()
	}
	hash, ok := object["after_hash"].(string)
	if !ok {
		return refuse()
	}
	if ordinal == 0 {
		if hash != "-" {
			return refuse()
		}
	} else if _, err := jack.DecodeBase64URLFixed(hash, 32); err != nil {
		return refuse()
	}
	return ResultCursor{Ordinal: uint64(ordinal), Hash: hash}, nil
}
