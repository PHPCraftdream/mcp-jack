package endpoint

import (
	"strconv"
	"strings"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/ipaddr"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/urlcheck"
)

const (
	httpsPrefix = "https://"
	wildcard    = "*."
	defaultPort = 443
)

// AllowlistEntry is a literal or wildcard HTTPS origin with a path prefix.
type AllowlistEntry struct {
	HostPattern string
	Port        int
	Path        string
}

// ParseAllowlistEntry parses one HTTPS prefix (R5.7).
func ParseAllowlistEntry(text string) (AllowlistEntry, bool) {
	rest, ok := strings.CutPrefix(text, httpsPrefix)
	if !ok {
		return AllowlistEntry{}, false
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] < 0x21 || rest[i] > 0x7e {
			return AllowlistEntry{}, false
		}
	}
	if !strings.HasPrefix(rest, wildcard) {
		u, err := urlcheck.Check(text)
		if err != nil || u.Query != "" {
			return AllowlistEntry{}, false
		}
		return AllowlistEntry{HostPattern: u.Host, Port: u.Port, Path: u.Path}, true
	}

	authority, path := rest, "/"
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		authority, path = rest[:i], rest[i:]
	}
	if hasControlOrMark(path) || strings.Contains(authority, "@") {
		return AllowlistEntry{}, false
	}
	host, portText, hasPort := strings.Cut(authority, ":")
	port := defaultPort
	if hasPort {
		if len(portText) == 0 || len(portText) > 5 || portText[0] < '1' || portText[0] > '9' {
			return AllowlistEntry{}, false
		}
		n, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			return AllowlistEntry{}, false
		}
		port = int(n)
	}
	parent, reason := ipaddr.ParseHost(host[len(wildcard):])
	if reason != "" || parent.Kind != "name" {
		return AllowlistEntry{}, false
	}
	return AllowlistEntry{HostPattern: wildcard + parent.Normalized, Port: port, Path: path}, true
}

// AllowlistMatches returns the first valid matching entry in configuration order.
func AllowlistMatches(entries []string, canonicalURL string) (AllowlistEntry, bool) {
	u, err := urlcheck.Check(canonicalURL)
	if err != nil {
		return AllowlistEntry{}, false
	}
	return allowlistMatches(entries, u)
}

func allowlistMatches(entries []string, u urlcheck.URL) (AllowlistEntry, bool) {
	for _, text := range entries {
		entry, ok := ParseAllowlistEntry(text)
		if ok && entry.Port == u.Port && hostMatches(entry.HostPattern, u.Host) && coversPath(entry.Path, u.Path) {
			return entry, true
		}
	}
	return AllowlistEntry{}, false
}

func hostMatches(pattern, host string) bool {
	if parent, ok := strings.CutPrefix(pattern, wildcard); ok {
		suffix := "." + parent
		return len(host) > len(suffix) && strings.HasSuffix(host, suffix)
	}
	return pattern == host
}
