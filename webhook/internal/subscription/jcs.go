// Package subscription implements the deterministic webhook subscription rules.
package subscription

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// JCS serializes a value decoded by encoding/json per RFC 8785.
func JCS(v any) (string, error) {
	var b strings.Builder
	if err := writeJCS(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func writeJCS(b *strings.Builder, v any) error {
	switch v := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(v))
	case string:
		if !utf8.ValidString(v) {
			return fmt.Errorf("jcs cannot serialize a string with invalid UTF-8")
		}
		writeJSONString(b, v)
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("jcs cannot serialize a non-finite number")
		}
		writeJCSNumber(b, v)
	case []any:
		b.WriteByte('[')
		for i, elem := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeJCS(b, elem); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		type member struct {
			key   string
			units []uint16
		}
		members := make([]member, 0, len(v))
		for key := range v {
			if !utf8.ValidString(key) {
				return fmt.Errorf("jcs cannot serialize an object key with invalid UTF-8")
			}
			members = append(members, member{key, utf16.Encode([]rune(key))})
		}
		slices.SortFunc(members, func(a, b member) int {
			return slices.Compare(a.units, b.units)
		})
		b.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSONString(b, m.key)
			b.WriteByte(':')
			if err := writeJCS(b, v[m.key]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("jcs cannot serialize %T", v)
	}
	return nil
}

func writeJSONString(b *strings.Builder, s string) {
	const hex = "0123456789abcdef"
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteByte(byte(r))
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hex[r>>4])
				b.WriteByte(hex[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

func writeJCSNumber(b *strings.Builder, v float64) {
	if v == 0 {
		b.WriteByte('0') // Both signs of zero.
		return
	}
	if v < 0 {
		b.WriteByte('-')
		v = -v
	}
	mantissa, exponent, _ := strings.Cut(strconv.FormatFloat(v, 'e', -1, 64), "e")
	e, _ := strconv.Atoi(exponent) // FormatFloat always supplies a valid exponent here.
	n := e + 1                     // Decimal point position in the shortest digit sequence.
	if n > 21 || n <= -6 {
		b.WriteString(mantissa)
		b.WriteByte('e')
		if e >= 0 {
			b.WriteByte('+')
		}
		b.WriteString(strconv.Itoa(e))
		return
	}
	digits := strings.Replace(mantissa, ".", "", 1)
	switch {
	case n <= 0:
		b.WriteString("0.")
		b.WriteString(strings.Repeat("0", -n))
		b.WriteString(digits)
	case n >= len(digits):
		b.WriteString(digits)
		b.WriteString(strings.Repeat("0", n-len(digits)))
	default:
		b.WriteString(digits[:n])
		b.WriteByte('.')
		b.WriteString(digits[n:])
	}
}
