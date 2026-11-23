package ipaddr

import (
	"strconv"
	"strings"
)

// Family names, host kinds and the two rejection reasons of the host-form rule
// (spec/06-webhooks.md R6.3). The strings are the ones ssrf.mjs returns.
const (
	familyIPv4 = "ipv4"
	familyIPv6 = "ipv6"

	kindIPv4 = "ipv4"
	kindIPv6 = "ipv6"
	kindName = "name"

	reasonNotAHostname = "not_a_hostname"
	reasonHost         = "host"
)

// decimalGroup reports whether s matches /^(0|[1-9][0-9]{0,2})$/ of ssrf.mjs:
// one dotted-quad octet or one CIDR prefix, with no sign, no padding and no
// leading zero.
func decimalGroup(s string) bool {
	if len(s) == 0 || len(s) > 3 {
		return false
	}
	if s[0] == '0' {
		return len(s) == 1
	}
	if s[0] < '1' || s[0] > '9' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// decimalValue reads a string decimalGroup already accepted.
func decimalValue(s string) int {
	value := 0
	for i := 0; i < len(s); i++ {
		value = value*10 + int(s[i]-'0')
	}
	return value
}

// ParseIPv4 parses the canonical dotted-quad form of R6.3/R6.4: exactly four
// decimal octets of 0-255, no leading zeros, no sign, no whitespace, and no
// short, integer, octal or hexadecimal spelling.
func ParseIPv4(text string) ([4]byte, bool) {
	var out [4]byte
	parts := strings.Split(text, ".")
	if len(parts) != 4 {
		return out, false
	}
	for i, part := range parts {
		if !decimalGroup(part) {
			return out, false
		}
		value := decimalValue(part)
		if value > 255 {
			return out, false
		}
		out[i] = byte(value)
	}
	return out, true
}

// hexGroup reports whether s matches /^[0-9a-fA-F]{1,4}$/ of ssrf.mjs.
func hexGroup(s string) bool {
	if len(s) < 1 || len(s) > 4 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// hexValue reads a string hexGroup already accepted.
func hexValue(s string) int {
	value := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		digit := 0
		switch {
		case c >= '0' && c <= '9':
			digit = int(c - '0')
		case c >= 'a' && c <= 'f':
			digit = int(c-'a') + 10
		default:
			digit = int(c-'A') + 10
		}
		value = value<<4 | digit
	}
	return value
}

// parseHexGroups mirrors the private parseHexGroups of ssrf.mjs: every part
// must be a hex group, except that with allowDottedLast the final part may be
// a canonical dotted quad standing for two groups.
func parseHexGroups(parts []string, allowDottedLast bool) ([]int, bool) {
	out := make([]int, 0, len(parts)+1)
	for i, part := range parts {
		if allowDottedLast && i == len(parts)-1 && strings.Contains(part, ".") {
			quad, ok := ParseIPv4(part)
			if !ok {
				return nil, false
			}
			out = append(out, int(quad[0])<<8|int(quad[1]), int(quad[2])<<8|int(quad[3]))
			continue
		}
		if !hexGroup(part) {
			return nil, false
		}
		out = append(out, hexValue(part))
	}
	return out, true
}

// ParseIPv6 parses the literal form of R6.7: 1-8 hex groups, at most one "::"
// compression, at most one embedded dotted quad in the final group (the last
// head group when uncompressed, the last tail group when compressed), and no
// zone id and no brackets. A compressed form needs at most seven explicit
// groups, an uncompressed form exactly eight.
func ParseIPv6(text string) ([16]byte, bool) {
	var out [16]byte
	if strings.ContainsAny(text, "%[]") {
		return out, false
	}
	gap := strings.Index(text, "::")
	if gap >= 0 && strings.Contains(text[gap+2:], "::") {
		return out, false
	}
	compressed := gap >= 0
	var head, tail []string
	if compressed {
		if gap > 0 {
			head = strings.Split(text[:gap], ":")
		}
		if rest := text[gap+2:]; rest != "" {
			tail = strings.Split(rest, ":")
		}
	} else {
		head = strings.Split(text, ":")
	}
	headValues, ok := parseHexGroups(head, !compressed)
	if !ok {
		return out, false
	}
	tailValues, ok := parseHexGroups(tail, compressed)
	if !ok {
		return out, false
	}
	total := len(headValues) + len(tailValues)
	if compressed {
		if total > 7 {
			return out, false
		}
	} else if total != 8 {
		return out, false
	}
	var values [8]int
	copy(values[:], headValues)
	if compressed {
		copy(values[len(headValues)+(8-total):], tailValues)
	}
	for i := 0; i < 8; i++ {
		out[i*2] = byte(values[i] >> 8)
		out[i*2+1] = byte(values[i])
	}
	return out, true
}

// FormatIPv4 renders four bytes as a dotted quad (R6.4).
func FormatIPv4(b [4]byte) string {
	return strconv.Itoa(int(b[0])) + "." + strconv.Itoa(int(b[1])) + "." +
		strconv.Itoa(int(b[2])) + "." + strconv.Itoa(int(b[3]))
}

// FormatIPv6 renders sixteen bytes in the RFC 5952 form of R6.6: lowercase hex
// groups without leading zeros, the longest run of zero groups (at least two
// groups, first run on a tie) replaced by "::", and the IPv4-mapped shape as
// "::ffff:a.b.c.d".
func FormatIPv6(b [16]byte) string {
	if isMapped(b) {
		return "::ffff:" + FormatIPv4([4]byte{b[12], b[13], b[14], b[15]})
	}
	var groups [8]int
	for i := 0; i < 8; i++ {
		groups[i] = int(b[i*2])<<8 | int(b[i*2+1])
	}
	bestStart, bestLen := -1, 0
	for i := 0; i < 8; i++ {
		if groups[i] != 0 {
			continue
		}
		j := i
		for j < 8 && groups[j] == 0 {
			j++
		}
		if j-i > bestLen {
			bestStart, bestLen = i, j-i
		}
		i = j
	}
	hexes := make([]string, 8)
	for i, group := range groups {
		hexes[i] = strconv.FormatUint(uint64(group), 16)
	}
	if bestLen < 2 {
		return strings.Join(hexes, ":")
	}
	return strings.Join(hexes[:bestStart], ":") + "::" + strings.Join(hexes[bestStart+bestLen:], ":")
}

// isMapped reports the ::ffff:0:0/96 shape: ten zero bytes followed by ff ff.
func isMapped(b [16]byte) bool {
	for i := 0; i < 10; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return b[10] == 0xff && b[11] == 0xff
}

// hostBitsZero mirrors the private hostBitsZero of ssrf.mjs: every bit of
// bytes beyond prefix must be zero, so a block text is an exact network.
func hostBitsZero(bytes []byte, prefix int) bool {
	whole := prefix >> 3
	restBits := prefix & 7
	from := whole
	if restBits != 0 {
		from = whole + 1
	}
	for i := from; i < len(bytes); i++ {
		if bytes[i] != 0 {
			return false
		}
	}
	if restBits == 0 {
		return true
	}
	mask := byte(0xff) << uint(8-restBits)
	return bytes[whole]&^mask == 0
}

// matchPrefix mirrors the private matchPrefix of ssrf.mjs: both sides must have
// the same width and agree on the first prefix bits.
func matchPrefix(bytes, network []byte, prefix int) bool {
	if bytes == nil || network == nil || len(bytes) != len(network) {
		return false
	}
	if prefix < 0 || prefix > len(bytes)*8 {
		return false
	}
	whole := prefix >> 3
	for i := 0; i < whole; i++ {
		if bytes[i] != network[i] {
			return false
		}
	}
	restBits := prefix & 7
	if restBits == 0 {
		return true
	}
	mask := byte(0xff) << uint(8-restBits)
	return bytes[whole]&mask == network[whole]&mask
}

// CIDR is one parsed allowedRanges entry of R6.11: the literal text, its
// family, the prefix length and the network bytes with every host bit zero.
type CIDR struct {
	Text   string
	Family string
	Prefix int
	Bytes  []byte
}

// ParseCIDR parses "<literal>/<prefix>" (R6.11): one slash, a decimal prefix
// of 0-32 for IPv4 and 0-128 for IPv6, the family chosen by ':' in the
// literal, and every host bit beyond the prefix zero.
func ParseCIDR(text string) (CIDR, bool) {
	slash := strings.Index(text, "/")
	if slash < 0 || strings.Contains(text[slash+1:], "/") {
		return CIDR{}, false
	}
	literal := text[:slash]
	prefixText := text[slash+1:]
	if !decimalGroup(prefixText) {
		return CIDR{}, false
	}
	prefix := decimalValue(prefixText)
	family := familyIPv4
	limit := 32
	if strings.Contains(literal, ":") {
		family = familyIPv6
		limit = 128
	}
	if prefix > limit {
		return CIDR{}, false
	}
	var bytes []byte
	if family == familyIPv4 {
		parsed, ok := ParseIPv4(literal)
		if !ok {
			return CIDR{}, false
		}
		bytes = parsed[:]
	} else {
		parsed, ok := ParseIPv6(literal)
		if !ok {
			return CIDR{}, false
		}
		bytes = parsed[:]
	}
	if !hostBitsZero(bytes, prefix) {
		return CIDR{}, false
	}
	return CIDR{Text: text, Family: family, Prefix: prefix, Bytes: bytes}, true
}

// Contains reports whether the address literal lies inside c (R6.11). The
// address may carry one surrounding [] pair; a family mismatch, an unparsable
// spelling or a zero CIDR is never contained.
func (c CIDR) Contains(address string) bool {
	parsed, ok := ParseAddress(address)
	if !ok {
		return false
	}
	if parsed.Family != c.Family {
		return false
	}
	return matchPrefix(parsed.Bytes, c.Bytes, c.Prefix)
}

// Parsed is one address literal: its family, its bytes and its canonical
// spelling.
type Parsed struct {
	Family  string
	Bytes   []byte
	Address string
}

// ParseAddress mirrors the private parsedAddress of ssrf.mjs: one surrounding
// [] pair is stripped, then the text must be a canonical IPv4 or IPv6 literal.
func ParseAddress(text string) (Parsed, bool) {
	input := text
	if len(input) >= 2 && input[0] == '[' && input[len(input)-1] == ']' {
		input = input[1 : len(input)-1]
	}
	if quad, ok := ParseIPv4(input); ok {
		return Parsed{Family: familyIPv4, Bytes: quad[:], Address: FormatIPv4(quad)}, true
	}
	if six, ok := ParseIPv6(input); ok {
		return Parsed{Family: familyIPv6, Bytes: six[:], Address: FormatIPv6(six)}, true
	}
	return Parsed{}, false
}

// Host is one accepted host spelling of R6.3: Kind is "ipv4", "ipv6" or "name",
// Address the canonical literal or the lowercased name, and Normalized the
// spelling a URL carries (bracketed for IPv6).
type Host struct {
	Kind       string
	Address    string
	Normalized string
}

// ParseHost mirrors parseHost of ssrf.mjs. The second result is the empty
// string on success and otherwise "not_a_hostname" for a spelling that is not
// a host at all, or "host" for a malformed bracketed literal.
func ParseHost(host string) (Host, string) {
	if host == "" {
		return Host{}, reasonNotAHostname
	}
	if host[0] == '[' {
		if host[len(host)-1] != ']' {
			return Host{}, reasonHost
		}
		inner := host[1 : len(host)-1]
		if strings.ContainsAny(inner, "[]%") {
			return Host{}, reasonHost
		}
		parsed, ok := ParseIPv6(inner)
		if !ok {
			return Host{}, reasonHost
		}
		address := FormatIPv6(parsed)
		return Host{Kind: kindIPv6, Address: address, Normalized: "[" + address + "]"}, ""
	}
	if strings.ContainsAny(host, "[]") {
		return Host{}, reasonHost
	}
	if quad, ok := ParseIPv4(host); ok {
		address := FormatIPv4(quad)
		return Host{Kind: kindIPv4, Address: address, Normalized: address}, ""
	}
	name := host
	if strings.HasSuffix(name, ".") {
		name = name[:len(name)-1]
	}
	name = strings.ToLower(name)
	if !isLDHName(name) {
		return Host{}, reasonNotAHostname
	}
	return Host{Kind: kindName, Address: name, Normalized: name}, ""
}

// isLDHName mirrors isLdhName of ssrf.mjs: at most 253 bytes, two or more
// labels of 1-63 bytes of [A-Za-z0-9-] with no edge hyphen, and a last label
// that is not all digits.
func isLDHName(name string) bool {
	if len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !ldhLabel(label) {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return !allDigits(labels[len(labels)-1])
}

// ldhLabel reports whether label matches /^[A-Za-z0-9-]{1,63}$/ of ssrf.mjs.
func ldhLabel(label string) bool {
	if len(label) < 1 || len(label) > 63 {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// allDigits reports whether s matches /^[0-9]+$/: the empty string does not.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
