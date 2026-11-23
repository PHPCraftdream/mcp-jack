// Package urlcheck validates and canonicalizes webhook callback URLs without
// resolving hosts or deciding whether an address is safe to dial.
package urlcheck

import (
	"strconv"
	"strings"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/ipaddr"
)

const (
	CodeSchemeNotHTTPS     = "scheme_not_https"
	CodeInvalidCallbackURL = "invalid_callback_url"
	CodeNotAHostname       = "not_a_hostname"
)

// URL is a validated callback URL. Host includes brackets for IPv6;
// HostValue is the canonical address without brackets or the normalized name.
// Path and Query retain their original bytes, except an empty path becomes "/".
type URL struct {
	Scheme, Host        string
	Port                int
	Path, Query         string
	Canonical           string
	HostKind, HostValue string
}

// Error contains the rejection code and optional reason from the URL check.
type Error struct {
	Code, Reason string
}

func (e *Error) Error() string {
	if e.Reason == "" {
		return e.Code
	}
	return e.Code + ": " + e.Reason
}

const defaultPort = 443

var dotEscapes = strings.NewReplacer("%2e", ".", "%2E", ".")

// Check mirrors checkUrl in the webhook reference, including rejection order.
func Check(raw string) (URL, *Error) {
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x21 || raw[i] > 0x7e {
			return urlBad("character")
		}
	}
	marker := strings.Index(raw, "://")
	if marker < 0 || !strings.EqualFold(raw[:marker], "https") {
		return URL{}, &Error{Code: CodeSchemeNotHTTPS}
	}

	rest := raw[marker+3:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority, tail := rest[:end], rest[end:]
	if strings.Contains(authority, "@") {
		return urlBad("userinfo")
	}
	if strings.Contains(tail, "#") {
		return urlBad("fragment")
	}
	if authority == "" {
		return urlBad("empty_host")
	}
	hostText, portSuffix, ok := splitAuthority(authority)
	if !ok {
		return urlBad("host")
	}
	port, ok := readPort(portSuffix)
	if !ok {
		return urlBad("port")
	}
	host, reason := ipaddr.ParseHost(hostText)
	switch reason {
	case "":
	case CodeNotAHostname:
		return URL{}, &Error{Code: CodeNotAHostname, Reason: reason}
	default:
		return urlBad("host")
	}

	path, query := "/", ""
	if tail != "" {
		switch tail[0] {
		case '?':
			query = tail[1:]
		case '/':
			path, query, _ = strings.Cut(tail, "?")
		default:
			return urlBad("path")
		}
	}
	if !strings.HasPrefix(path, "/") {
		return urlBad("path")
	}
	for segment := range strings.SplitSeq(path, "/") {
		decoded := dotEscapes.Replace(segment)
		if decoded == "." || decoded == ".." {
			return urlBad("dot_segment")
		}
	}

	suffix := ""
	if port != defaultPort {
		suffix = ":" + strconv.Itoa(port)
	}
	canonical := "https://" + host.Normalized + suffix + path
	if query != "" {
		canonical += "?" + query
	}
	return URL{
		Scheme:    "https",
		Host:      host.Normalized,
		Port:      port,
		Path:      path,
		Query:     query,
		Canonical: canonical,
		HostKind:  host.Kind,
		HostValue: host.Address,
	}, nil
}

// Canonical returns the canonical form of raw, or an empty string and false
// if Check rejects it.
func Canonical(raw string) (string, bool) {
	u, err := Check(raw)
	return u.Canonical, err == nil
}

func urlBad(reason string) (URL, *Error) {
	return URL{}, &Error{Code: CodeInvalidCallbackURL, Reason: reason}
}

// splitAuthority retains the colon in the port suffix to distinguish an
// absent port from an explicitly empty one.
func splitAuthority(authority string) (host, portSuffix string, ok bool) {
	if authority[0] == '[' {
		close := strings.IndexByte(authority, ']')
		if close < 0 {
			return authority, "", true // Let ParseHost reject the missing bracket.
		}
		host, portSuffix = authority[:close+1], authority[close+1:]
		return host, portSuffix, portSuffix == "" || portSuffix[0] == ':'
	}
	first := strings.IndexByte(authority, ':')
	if first < 0 {
		return authority, "", true
	}
	return authority[:first], authority[first:], !strings.Contains(authority[first+1:], ":")
}

func readPort(suffix string) (int, bool) {
	if suffix == "" {
		return defaultPort, true
	}
	text := suffix[1:]
	if len(text) == 0 || len(text) > 5 || text[0] == '0' {
		return 0, false
	}
	port := 0
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		port = port*10 + int(c-'0')
	}
	return port, port <= 65535
}
