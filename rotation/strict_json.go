package rotation

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// Stdlib проверяет JSON grammar; дополнительный guard запрещает lone surrogates,
// которые encoding/json иначе заменяет на U+FFFD. Native JSON policy не меняется.
func scalarJSON(data []byte) bool {
	if !utf8.Valid(data) || !json.Valid(data) {
		return false
	}
	for index := 0; index < len(data); index++ {
		if data[index] != '"' {
			continue
		}
		index++
		for index < len(data) && data[index] != '"' {
			if data[index] != '\\' {
				index++
				continue
			}
			if index+1 >= len(data) {
				return false
			}
			if data[index+1] != 'u' {
				index += 2
				continue
			}
			if index+6 > len(data) {
				return false
			}
			unit, err := strconv.ParseUint(string(data[index+2:index+6]), 16, 16)
			if err != nil {
				return false
			}
			index += 6
			if unit >= 0xd800 && unit <= 0xdbff {
				if index+6 > len(data) || data[index] != '\\' || data[index+1] != 'u' {
					return false
				}
				low, err := strconv.ParseUint(string(data[index+2:index+6]), 16, 16)
				if err != nil || low < 0xdc00 || low > 0xdfff || utf16.DecodeRune(rune(unit), rune(low)) == utf8.RuneError {
					return false
				}
				index += 6
			} else if unit >= 0xdc00 && unit <= 0xdfff {
				return false
			}
		}
	}
	return true
}

func strictJSON(data []byte) (any, error) {
	if !scalarJSON(data) {
		return nil, invalid("rotation_result_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := strictJSONValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, invalid("rotation_result_invalid")
	}
	return value, nil
}

func strictJSONValue(decoder *json.Decoder, depth int) (any, error) {
	fail := func() (any, error) { return nil, invalid("rotation_result_invalid") }
	if depth > 64 {
		return fail()
	}
	token, err := decoder.Token()
	if err != nil {
		return fail()
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return fail()
			}
			if _, duplicate := object[key]; duplicate {
				return fail()
			}
			value, err := strictJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
			return fail()
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			value, err := strictJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if closing, err := decoder.Token(); err != nil || closing != json.Delim(']') {
			return fail()
		}
		return array, nil
	default:
		return fail()
	}
}
