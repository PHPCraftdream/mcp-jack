// Package card processes Server Cards for webhook key discovery without doing
// network I/O.
package card

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/urlcheck"
)

const EventsExtension = "io.modelcontextprotocol/events"
const DefaultPort = 443

// Remote is the selected remote's URL and original JSON object.
type Remote struct {
	URL string
	Raw json.RawMessage
}

// Info is the selected remote's webhook discovery information.
type Info struct {
	SigningKeys json.RawMessage
	Egress      []string
	RemoteURL   string
}

// SameOrigin reports whether both URLs are accepted and have the same origin.
func SameOrigin(a, b string) bool {
	left, leftErr := urlcheck.Check(a)
	right, rightErr := urlcheck.Check(b)
	return leftErr == nil && rightErr == nil && sameOrigin(left, right)
}

func sameOrigin(a, b urlcheck.URL) bool {
	return a.Scheme == b.Scheme && a.Host == b.Host && a.Port == b.Port
}

// DefaultCardURL returns the reserved server-card URL under the MCP endpoint.
func DefaultCardURL(mcpURL string) (string, bool) {
	target, err := urlcheck.Check(mcpURL)
	if err != nil {
		return "", false
	}
	host := target.Host
	if target.Port != DefaultPort {
		host += ":" + strconv.Itoa(target.Port)
	}
	path := target.Path
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	if path == "/" {
		path = ""
	}
	return "https://" + host + path + "/server-card", true
}

// SelectRemote chooses an exact path, the longest path prefix, or a same-origin
// fallback, in that order. Ties retain document order.
func SelectRemote(card json.RawMessage, mcpURL string) (Remote, bool) {
	target, err := urlcheck.Check(mcpURL)
	if err != nil {
		return Remote{}, false
	}
	var best Remote
	bestTier, bestLength := 0, 0
	for _, raw := range jsonArray(jsonObject(card)["remotes"]) {
		url, ok := jsonString(jsonObject(raw)["url"])
		if !ok || strings.ContainsRune(url, '{') {
			continue
		}
		checked, err := urlcheck.Check(url)
		if err != nil || !sameOrigin(checked, target) {
			continue
		}
		tier, length := 1, 0
		if checked.Path == target.Path {
			tier = 3
		} else if strings.HasPrefix(target.Path, checked.Path) {
			tier, length = 2, len(checked.Path)
		}
		if tier > bestTier || (tier == bestTier && length > bestLength) {
			best, bestTier, bestLength = Remote{URL: url, Raw: raw}, tier, length
		}
	}
	return best, bestTier != 0
}

// WebhookInfo extracts webhook discovery data without requiring it to be present.
func WebhookInfo(card json.RawMessage, mcpURL string) (Info, string) {
	remote, ok := SelectRemote(card, mcpURL)
	if !ok {
		return Info{}, "no_remote"
	}
	extensions := jsonObject(jsonObject(remote.Raw)["extensionsInfo"])
	webhooks := jsonObject(jsonObject(extensions[EventsExtension])["webhooks"])
	info := Info{RemoteURL: remote.URL}
	if keys := webhooks["signingKeys"]; jsonObject(keys) != nil {
		info.SigningKeys = keys
	}
	if ranges := jsonArray(webhooks["egressIpRanges"]); ranges != nil {
		info.Egress = make([]string, 0, len(ranges))
		for _, raw := range ranges {
			if text, ok := jsonString(raw); ok {
				info.Egress = append(info.Egress, text)
			}
		}
	}
	return info, ""
}

// The JSON helpers use exact member names and distinguish null from an empty
// object, array, or string.
func jsonObject(raw json.RawMessage) map[string]json.RawMessage {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return nil
	}
	return object
}

func jsonArray(raw json.RawMessage) []json.RawMessage {
	var array []json.RawMessage
	if json.Unmarshal(raw, &array) != nil {
		return nil
	}
	return array
}

func jsonString(raw json.RawMessage) (string, bool) {
	var text *string
	if json.Unmarshal(raw, &text) != nil || text == nil {
		return "", false
	}
	return *text, true
}
