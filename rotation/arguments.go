package rotation

import (
	"encoding/json"
	"strconv"
	"strings"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// DecodeServerKeyArguments проверяет исходный member sequence, не last-wins map.
// Caller ограничивает complete request body до вызова; parse не даёт checkpoint authority.
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
