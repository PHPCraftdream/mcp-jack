// Package urlpolicy implements the client URL destination policy.
package urlpolicy

import (
	"errors"
	"net/http"
)

// ErrMalformedDestination and ErrInsecureDestination are the two refusal
// reasons of CheckDestination.
var (
	ErrMalformedDestination = errors.New("jack client: destination refused: malformed destination url")
	ErrInsecureDestination  = errors.New("jack client: destination refused: https is required for non-loopback hosts")
)

// CheckDestination applies the client URL policy (docs/design/interop.md
// section 9) to the RAW destination string, before any URL parsing. It is
// pure: no DNS, no normalisation, it only accepts (nil) or refuses.
//
// Summary: https is accepted for any syntactically plain host; http only for
// a literal canonical dotted-decimal 127.x.y.z or the bracketed literal [::1].
// There are no localhost aliases. Userinfo and percent escapes in the
// AUTHORITY (which also refuses zone IDs) are refused, as are backslashes and
// control/space/non-ASCII bytes anywhere. Percent-encoded path and query are
// accepted and signed exactly as given.
func CheckDestination(raw string) error {
	if raw == "" {
		return ErrMalformedDestination
	}
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b <= 0x20 || b == 0x7f || b >= 0x80 || b == '\\' {
			return ErrMalformedDestination
		}
	}

	var secure bool
	var rest string
	switch {
	case hasPrefixFold(raw, "https://"):
		secure, rest = true, raw[len("https://"):]
	case hasPrefixFold(raw, "http://"):
		secure, rest = false, raw[len("http://"):]
	default:
		return ErrMalformedDestination
	}

	end := len(rest)
	for i := 0; i < len(rest); i++ {
		if c := rest[i]; c == '/' || c == '?' || c == '#' {
			end = i
			break
		}
	}
	authority := rest[:end]
	if authority == "" {
		return ErrMalformedDestination
	}
	for i := 0; i < len(authority); i++ {
		if authority[i] == '@' || authority[i] == '%' {
			return ErrMalformedDestination
		}
	}

	host, bracketed, err := splitHostPort(authority)
	if err != nil {
		return err
	}
	if secure {
		return nil
	}
	if bracketed {
		if host == "::1" {
			return nil
		}
		return ErrInsecureDestination
	}
	if IsLoopbackIPv4(host) {
		return nil
	}
	return ErrInsecureDestination
}

// CheckRequestDestination applies the client URL policy to the destination of
// req, rebuilt as scheme://host plus the exact path and query bytes that will
// be sent. It refuses a nil URL, an opaque URL and any userinfo.
func CheckRequestDestination(req *http.Request) error {
	u := req.URL
	if u == nil || u.Opaque != "" || u.User != nil {
		return ErrMalformedDestination
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	raw := u.Scheme + "://" + u.Host + path
	if u.ForceQuery || u.RawQuery != "" {
		raw += "?" + u.RawQuery
	}
	return CheckDestination(raw)
}

// hasPrefixFold reports whether s starts with the lowercase ASCII prefix,
// ignoring ASCII case in s.
func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != prefix[i] {
			return false
		}
	}
	return true
}

// splitHostPort validates the authority (host and optional port) and returns
// the host (IPv6 literal without brackets, lowercased) and whether it was
// bracketed.
func splitHostPort(authority string) (host string, bracketed bool, err error) {
	var portPart string
	hasPort := false
	if authority[0] == '[' {
		closeIdx := -1
		for i := 1; i < len(authority); i++ {
			switch authority[i] {
			case '[':
				return "", false, ErrMalformedDestination
			case ']':
				if closeIdx >= 0 {
					return "", false, ErrMalformedDestination
				}
				closeIdx = i
			}
		}
		if closeIdx < 0 {
			return "", false, ErrMalformedDestination
		}
		lit := authority[1:closeIdx]
		if lit == "" {
			return "", false, ErrMalformedDestination
		}
		for i := 0; i < len(lit); i++ {
			c := lit[i]
			if !(isHexDigit(c) || c == ':' || c == '.') {
				return "", false, ErrMalformedDestination
			}
		}
		host = asciiLower(lit)
		bracketed = true
		tail := authority[closeIdx+1:]
		if tail != "" {
			if tail[0] != ':' {
				return "", false, ErrMalformedDestination
			}
			hasPort, portPart = true, tail[1:]
		}
	} else {
		colons := 0
		colonAt := -1
		for i := 0; i < len(authority); i++ {
			switch c := authority[i]; {
			case c == '[' || c == ']':
				return "", false, ErrMalformedDestination
			case c == ':':
				colons++
				colonAt = i
			}
		}
		if colons > 1 {
			return "", false, ErrMalformedDestination
		}
		host = authority
		if colons == 1 {
			host = authority[:colonAt]
			hasPort, portPart = true, authority[colonAt+1:]
		}
		if host == "" {
			return "", false, ErrMalformedDestination
		}
		for i := 0; i < len(host); i++ {
			c := host[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'
			if !ok {
				return "", false, ErrMalformedDestination
			}
		}
	}
	if hasPort {
		if len(portPart) < 1 || len(portPart) > 5 {
			return "", false, ErrMalformedDestination
		}
		n := 0
		for i := 0; i < len(portPart); i++ {
			c := portPart[i]
			if c < '0' || c > '9' {
				return "", false, ErrMalformedDestination
			}
			n = n*10 + int(c-'0')
		}
		if n < 1 || n > 65535 {
			return "", false, ErrMalformedDestination
		}
	}
	return host, bracketed, nil
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// IsLoopbackIPv4 reports whether host is canonical dotted-decimal IPv4 with
// exactly four octets 0..255, no leading zeros, and first octet exactly 127.
func IsLoopbackIPv4(host string) bool {
	octets := 0
	start := 0
	for i := 0; i <= len(host); i++ {
		if i < len(host) && host[i] != '.' {
			continue
		}
		part := host[start:i]
		if len(part) < 1 || len(part) > 3 || (len(part) > 1 && part[0] == '0') {
			return false
		}
		n := 0
		for j := 0; j < len(part); j++ {
			c := part[j]
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 || (octets == 0 && n != 127) {
			return false
		}
		octets++
		start = i + 1
	}
	return octets == 4
}

// asciiLower maps ASCII uppercase letters to lowercase, leaving all other
// bytes unchanged.
func asciiLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
