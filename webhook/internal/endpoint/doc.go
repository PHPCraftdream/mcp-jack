package endpoint

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/urlcheck"
)

const (
	MaxReceivers    = 64
	MaxReceiverPath = 1024
	DefaultDocTTL   = 300
	MaxDocBytes     = 8192

	wellKnownPath = "/.well-known/mcp-webhook-receiver.json"
)

// ParseReceiverDoc validates all entries before returning them in document order.
func ParseReceiverDoc(text string) ([]string, *Error) {
	bad := func(reason string) ([]string, *Error) {
		return nil, &Error{Code: "invalid_document", Reason: reason}
	}
	obj, valid := jsonObject(text)
	if !valid {
		return bad("json")
	}
	var entries []json.RawMessage
	if json.Unmarshal(obj["receivers"], &entries) != nil || entries == nil {
		return bad("receivers")
	}
	if len(entries) < 1 || len(entries) > MaxReceivers {
		return bad("count")
	}
	receivers := make([]string, len(entries))
	for i, raw := range entries {
		entry, ok := jsonString(raw)
		if !ok || !strings.HasPrefix(entry, "/") || !validReceiverPathLength(entry) || hasControlOrMark(entry) {
			return bad("entry")
		}
		for segment := range strings.SplitSeq(entry, "/") {
			if segment == "." || segment == ".." {
				return bad("segment")
			}
		}
		receivers[i] = entry
	}
	return receivers, nil
}

// validReceiverPathLength follows the reference's UTF-16 string length.
func validReceiverPathLength(path string) bool {
	n := 0
	for _, r := range path {
		n++
		if r > 0xFFFF {
			n++
		}
		if n > MaxReceiverPath {
			return false
		}
	}
	return true
}

func hasControlOrMark(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b == 0x7f || b == '?' || b == '#' {
			return true
		}
	}
	return false
}

// jsonObject distinguishes invalid JSON from a valid non-object value.
// Raw members preserve JSON's last-member-wins behavior without interpreting
// irrelevant values (e.g., numbers outside the float64 range).
func jsonObject(text string) (map[string]json.RawMessage, bool) {
	body := []byte(text)
	if !strings.HasPrefix(strings.TrimLeft(text, " \t\r\n"), "{") {
		return nil, json.Valid(body)
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(body, &obj) != nil {
		return nil, false
	}
	return obj, true
}

func jsonString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

// CheckReceiverDocFetch checks the status and byte limit before parsing the body.
// Pass MaxDocBytes for the profile limit; zero limits the body to zero bytes.
func CheckReceiverDocFetch(status int, bodyText string, maxBody int64) ([]string, *Error) {
	if status != 200 {
		return nil, &Error{Code: "document_fetch_failed", Reason: "status_" + strconv.Itoa(status)}
	}
	if int64(len(bodyText)) > maxBody {
		return nil, &Error{Code: "document_fetch_failed", Reason: "too_large"}
	}
	return ParseReceiverDoc(bodyText)
}

// ReceiverDocRequest applies the delivery policy before checking the document.
func ReceiverDocRequest(url string, answers, allowedRanges, recheck []string, redirect *int, status int, bodyText string) ([]string, *Error) {
	decision := delivery.Check(delivery.CheckInput{
		URL: url, Answers: answers, AllowedRanges: allowedRanges, Recheck: recheck, Redirect: redirect,
	})
	if !decision.Allow {
		return nil, &Error{Code: decision.Code, Reason: decision.Reason}
	}
	return CheckReceiverDocFetch(status, bodyText, MaxDocBytes)
}

// ReceiverDocCovers returns the first receiver covering urlPath, without decoding.
func ReceiverDocCovers(receivers []string, urlPath string) (string, bool) {
	for _, entry := range receivers {
		if coversPath(entry, urlPath) {
			return entry, true
		}
	}
	return "", false
}

func coversPath(entry, path string) bool {
	rest, ok := strings.CutPrefix(path, entry)
	return ok && (strings.HasSuffix(entry, "/") || rest == "" || rest[0] == '/')
}

// WellKnownURL returns the receiver document URL at the callback's origin.
func WellKnownURL(canonicalURL string) (string, bool) {
	u, err := urlcheck.Check(canonicalURL)
	if err != nil {
		return "", false
	}
	return wellKnownURL(u), true
}

func wellKnownURL(u urlcheck.URL) string {
	authority := u.Host
	if u.Port != defaultPort {
		authority += ":" + strconv.Itoa(u.Port)
	}
	return httpsPrefix + authority + wellKnownPath
}

// DocCacheTTL returns the document cache lifetime in seconds.
func DocCacheTTL(maxAge *int64) int64 {
	if maxAge == nil || *maxAge < 0 {
		return DefaultDocTTL
	}
	return min(*maxAge, DefaultDocTTL)
}
