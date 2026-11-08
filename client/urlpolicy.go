package client

import (
	"errors"
	"fmt"
	"net/http"
)

// errMalformedDestination and errInsecureDestination are the two refusal
// reasons of checkDestination.
var (
	errMalformedDestination = errors.New("jack client: destination refused: malformed destination url")
	errInsecureDestination  = errors.New("jack client: destination refused: https is required for non-loopback hosts")
)

// ErrRedirectRefused is matched (errors.Is) by the error returned when a
// signed request is answered with a redirect status (301, 302, 303, 307 or
// 308). Redirects are never followed, are refused before response
// verification, and the Location header is never surfaced. This is a
// no-follow/no-downgrade guard (a signed request is not replayed to, or
// verified against, a different target); it is NOT TLS enforcement.
var ErrRedirectRefused = errors.New("jack client: redirect response refused")

// RedirectRefusedError reports a redirect-status answer (301, 302, 303, 307,
// 308) to a signed request.
type RedirectRefusedError struct {
	Status int
}

func (e *RedirectRefusedError) Error() string {
	return fmt.Sprintf("jack client: redirect response refused: status %d", e.Status)
}

// Is makes errors.Is(err, ErrRedirectRefused) true.
func (e *RedirectRefusedError) Is(target error) bool { return target == ErrRedirectRefused }

// noFollowRedirects is an http.Client.CheckRedirect that never follows.
func noFollowRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// isRedirectStatus reports whether status is exactly 301, 302, 303, 307 or
// 308. Other 3xx statuses (300, 304, 305, ...) take the normal path
// (streaming guard, signature verification): in particular a correctly signed
// 304 Not Modified is returned as before.
func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// checkDestination applies the client URL policy (docs/design/interop.md
// section 9) to the RAW destination string, before any URL parsing. It is
// pure: no DNS, no normalisation, it only accepts (nil) or refuses.
//
// Summary: https is accepted for any syntactically plain host; http only for
// a literal canonical dotted-decimal 127.x.y.z or the bracketed literal [::1].
// There are no localhost aliases. Userinfo and percent escapes in the
// AUTHORITY (which also refuses zone IDs) are refused, as are backslashes and
// control/space/non-ASCII bytes anywhere. Percent-encoded path and query are
// accepted and signed exactly as given.
func checkDestination(raw string) error {
	if raw == "" {
		return errMalformedDestination
	}
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b <= 0x20 || b == 0x7f || b >= 0x80 || b == '\\' {
			return errMalformedDestination
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
		return errMalformedDestination
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
		return errMalformedDestination
	}
	for i := 0; i < len(authority); i++ {
		if authority[i] == '@' || authority[i] == '%' {
			return errMalformedDestination
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
		return errInsecureDestination
	}
	if isLoopbackIPv4(host) {
		return nil
	}
	return errInsecureDestination
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
				return "", false, errMalformedDestination
			case ']':
				if closeIdx >= 0 {
					return "", false, errMalformedDestination
				}
				closeIdx = i
			}
		}
		if closeIdx < 0 {
			return "", false, errMalformedDestination
		}
		lit := authority[1:closeIdx]
		if lit == "" {
			return "", false, errMalformedDestination
		}
		for i := 0; i < len(lit); i++ {
			c := lit[i]
			if !(isHexDigit(c) || c == ':' || c == '.') {
				return "", false, errMalformedDestination
			}
		}
		host = asciiLower(lit)
		bracketed = true
		tail := authority[closeIdx+1:]
		if tail != "" {
			if tail[0] != ':' {
				return "", false, errMalformedDestination
			}
			hasPort, portPart = true, tail[1:]
		}
	} else {
		colons := 0
		colonAt := -1
		for i := 0; i < len(authority); i++ {
			switch c := authority[i]; {
			case c == '[' || c == ']':
				return "", false, errMalformedDestination
			case c == ':':
				colons++
				colonAt = i
			}
		}
		if colons > 1 {
			return "", false, errMalformedDestination
		}
		host = authority
		if colons == 1 {
			host = authority[:colonAt]
			hasPort, portPart = true, authority[colonAt+1:]
		}
		if host == "" {
			return "", false, errMalformedDestination
		}
		for i := 0; i < len(host); i++ {
			c := host[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'
			if !ok {
				return "", false, errMalformedDestination
			}
		}
	}
	if hasPort {
		if len(portPart) < 1 || len(portPart) > 5 {
			return "", false, errMalformedDestination
		}
		n := 0
		for i := 0; i < len(portPart); i++ {
			c := portPart[i]
			if c < '0' || c > '9' {
				return "", false, errMalformedDestination
			}
			n = n*10 + int(c-'0')
		}
		if n < 1 || n > 65535 {
			return "", false, errMalformedDestination
		}
	}
	return host, bracketed, nil
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// isLoopbackIPv4 reports whether host is canonical dotted-decimal IPv4 with
// exactly four octets 0..255, no leading zeros, and first octet exactly 127.
func isLoopbackIPv4(host string) bool {
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
