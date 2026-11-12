package rotation

import (
	"strings"
	"testing"
)

func TestStrictJSONScalarEscapesAndDepthGuards(t *testing.T) {
	quote := string(rune(0x22))
	slash := string(rune(0x5c))
	for _, row := range []struct {
		text  string
		valid bool
	}{
		{quote + slash + "ud83d" + slash + "ude00" + quote, true},
		{quote + slash + "ud800" + quote, false},
		{quote + slash + "udc00" + quote, false},
		{quote + slash + "ud800" + slash + slash + "udc00" + quote, false},
		{quote + slash + slash + "ud800" + quote, true},
		{quote + slash + "ufffd" + quote, true},
	} {
		_, err := strictJSON([]byte(row.text))
		if (err == nil) != row.valid {
			t.Fatalf("scalar source %q valid=%v error=%v", row.text, row.valid, err)
		}
	}
	for depth := 64; depth <= 65; depth++ {
		source := strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth)
		_, err := strictJSON([]byte(source))
		if (err == nil) != (depth == 64) {
			t.Fatalf("depth=%d error=%v", depth, err)
		}
	}
	duplicate := `{"complete":true,"` + slash + `u0063omplete":true}`
	if _, err := strictJSON([]byte(duplicate)); err == nil {
		t.Fatal("escaped duplicate key accepted")
	}
}
