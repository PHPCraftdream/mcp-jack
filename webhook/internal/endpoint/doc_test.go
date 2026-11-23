package endpoint_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/endpoint"
)

const endpointDoc = `{"receivers":["/hooks/"]}`

func TestEndpointReceiverDocumentValidation(t *testing.T) {
	validPath := "/" + strings.Repeat("😀", 511) + "é"
	atCount := `{"receivers":["/"` + strings.Repeat(`,"/"`, endpoint.MaxReceivers-1) + `]}`
	for _, tt := range []struct {
		name, text, reason string
	}{
		{"valid", endpointDoc, ""}, {"count-limit", atCount, ""},
		{"path-limit-utf16", `{"receivers":["` + validPath + `"]}`, ""},
		{"preserved-bytes", `{"receivers":["/", "//", "/é", "/%2e%2e", "/a b"]}`, ""},
		{"duplicate-last", `{"receivers":false,"receivers":["/"],"extra":1e999}`, ""},
		{"json", `{"receivers":[`, "json"}, {"trailing", endpointDoc + `true`, "json"},
		{"object", `[]`, "receivers"}, {"null", `null`, "receivers"}, {"missing", `{}`, "receivers"},
		{"wrong-key-case", `{"Receivers":["/"]}`, "receivers"}, {"non-array", `{"receivers":{}}`, "receivers"},
		{"null-array", `{"receivers":null}`, "receivers"}, {"count-empty", `{"receivers":[]}`, "count"},
		{"count-before-entry", `{"receivers":[null` + strings.Repeat(`,"/"`, endpoint.MaxReceivers) + `]}`, "count"},
		{"entry-type", `{"receivers":[1]}`, "entry"}, {"entry-null", `{"receivers":[null]}`, "entry"},
		{"entry-root", `{"receivers":["hooks/"]}`, "entry"}, {"entry-empty", `{"receivers":[""]}`, "entry"},
		{"entry-length", `{"receivers":["` + validPath + `x"]}`, "entry"},
		{"entry-query", `{"receivers":["/hooks?v"]}`, "entry"}, {"entry-fragment", `{"receivers":["/hooks#f"]}`, "entry"},
		{"entry-control", `{"receivers":["/\u0000\u001f"]}`, "entry"}, {"entry-del", `{"receivers":["/\u007f"]}`, "entry"},
		{"segment-dot", `{"receivers":["/a/./b"]}`, "segment"}, {"segment-dotdot", `{"receivers":["/a/.."]}`, "segment"},
		{"first-offender", `{"receivers":["/.",null]}`, "segment"},
		{"entry-before-segment", `{"receivers":["/.#/"]}`, "entry"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := endpoint.ParseReceiverDoc(tt.text)
			if tt.reason == "" {
				assertEndpointError(t, err, "", "")
				if len(got) == 0 || (tt.name == "valid" && !slices.Equal(got, []string{"/hooks/"})) {
					t.Fatalf("unexpected receivers: %q", got)
				}
				return
			}
			assertEndpointError(t, err, "invalid_document", tt.reason)
			if got != nil {
				t.Fatalf("invalid document returned receivers: %q", got)
			}
		})
	}
}

func TestEndpointDocumentFetchPolicy(t *testing.T) {
	atCap := endpointDoc + strings.Repeat(" ", endpoint.MaxDocBytes-len(endpointDoc))
	for _, tt := range []struct {
		name         string
		status       int
		body         string
		limit        int64
		code, reason string
	}{
		{"8192", 200, atCap, endpoint.MaxDocBytes, "", ""},
		{"8193", 200, atCap + " ", endpoint.MaxDocBytes, "document_fetch_failed", "too_large"},
		{"204", 204, atCap + " ", endpoint.MaxDocBytes, "document_fetch_failed", "status_204"},
		{"302", 302, "", endpoint.MaxDocBytes, "document_fetch_failed", "status_302"},
		{"404", 404, "", endpoint.MaxDocBytes, "document_fetch_failed", "status_404"},
		{"500", 500, "", endpoint.MaxDocBytes, "document_fetch_failed", "status_500"},
		{"integer-zero-status", 0, "", endpoint.MaxDocBytes, "document_fetch_failed", "status_0"},
		{"zero-limit", 200, endpointDoc, 0, "document_fetch_failed", "too_large"},
		{"empty", 200, "", 0, "invalid_document", "json"},
		{"invalid-document", 200, `{}`, endpoint.MaxDocBytes, "invalid_document", "receivers"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := endpoint.CheckReceiverDocFetch(tt.status, tt.body, tt.limit)
			assertEndpointError(t, err, tt.code, tt.reason)
			if err == nil && !slices.Equal(got, []string{"/hooks/"}) {
				t.Fatalf("receivers = %q", got)
			}
		})
	}

	const originDoc = "https://hooks.example.test/.well-known/mcp-webhook-receiver.json"
	public := []string{"93.184.216.34"}
	private := []string{"10.0.0.5"}
	redirect := 302
	got, err := endpoint.ReceiverDocRequest(originDoc, public, nil, nil, nil, 200, endpointDoc)
	assertEndpointError(t, err, "", "")
	if !slices.Equal(got, []string{"/hooks/"}) {
		t.Fatalf("receivers = %q", got)
	}
	_, err = endpoint.ReceiverDocRequest(originDoc, append(slices.Clone(public), private...), nil, nil, nil, 500, "bad")
	assertEndpointError(t, err, "blocked_address", "private_use")
	_, err = endpoint.ReceiverDocRequest(originDoc, private, []string{"10.0.0.0/8"}, nil, nil, 200, endpointDoc)
	assertEndpointError(t, err, "", "")
	_, err = endpoint.ReceiverDocRequest(originDoc, public, nil, []string{"93.184.216.35"}, nil, 200, endpointDoc)
	assertEndpointError(t, err, "dns_rebinding", "address_changed")
	_, err = endpoint.ReceiverDocRequest(originDoc, public, nil, nil, &redirect, 200, endpointDoc)
	assertEndpointError(t, err, "redirect_refused", "status_302")
	_, err = endpoint.ReceiverDocRequest(originDoc, public, nil, nil, nil, 200, atCap+" ")
	assertEndpointError(t, err, "document_fetch_failed", "too_large")
	_, err = endpoint.ReceiverDocRequest("https://hooks.example.test/.%2E/x", public, nil, nil, nil, 200, endpointDoc)
	assertEndpointError(t, err, "invalid_callback_url", "dot_segment")
}

func TestEndpointReceiverCoverage(t *testing.T) {
	for _, tt := range []struct {
		entries    []string
		path, want string
	}{
		{[]string{"/hooks/"}, "/hooks/a", "/hooks/"}, {[]string{"/hooks/"}, "/hooks/", "/hooks/"},
		{[]string{"/hooks/"}, "/hooks", ""}, {[]string{"/hooks"}, "/hooks", "/hooks"},
		{[]string{"/hooks"}, "/hooks/A", "/hooks"}, {[]string{"/hooks"}, "/Hooks/a", ""},
		{[]string{"/hooks"}, "/hooksx", ""}, {[]string{"/hooks"}, "/hooks%2Fa", ""},
		{[]string{"/hooks%2Fa"}, "/hooks%2Fa/more", "/hooks%2Fa"}, {[]string{"/"}, "/anything", "/"},
		{[]string{"/", "/hooks"}, "/hooks/a", "/"}, {[]string{"/hooks", "/"}, "/hooks/a", "/hooks"},
		{nil, "/hooks/a", ""},
	} {
		if got, ok := endpoint.ReceiverDocCovers(tt.entries, tt.path); got != tt.want || ok != (tt.want != "") {
			t.Errorf("coverage of %q by %q = (%q, %t), want %q", tt.path, tt.entries, got, ok, tt.want)
		}
	}
}

func TestEndpointWellKnownURLAndCacheTTL(t *testing.T) {
	const path = "/.well-known/mcp-webhook-receiver.json"
	for _, tt := range []struct{ url, want string }{
		{"https://hooks.example.test/hooks/alice", "https://hooks.example.test" + path},
		{"HTTPS://HOOKS.EXAMPLE.TEST.:443/x?token=1", "https://hooks.example.test" + path},
		{"https://hooks.example.test:8443/x", "https://hooks.example.test:8443" + path},
		{"https://[2001:0DB8::1]:444/x", "https://[2001:db8::1]:444" + path},
		{"http://hooks.example.test/x", ""}, {"https://hooks.example.test/x/%2e%2E", ""},
	} {
		if got, ok := endpoint.WellKnownURL(tt.url); got != tt.want || ok != (tt.want != "") {
			t.Errorf("WellKnownURL(%q) = (%q, %t), want %q", tt.url, got, ok, tt.want)
		}
	}
	if got := endpoint.DocCacheTTL(nil); got != 300 {
		t.Errorf("absent max-age: got %d, want 300", got)
	}
	for _, tt := range []struct{ age, want int64 }{{-1, 300}, {0, 0}, {60, 60}, {300, 300}, {301, 300}, {600, 300}} {
		if got := endpoint.DocCacheTTL(&tt.age); got != tt.want {
			t.Errorf("max-age %d: got %d, want %d", tt.age, got, tt.want)
		}
	}
}
