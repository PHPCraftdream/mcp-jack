package card_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/card"
)

const cardTestMCPURL = "https://mcp.example.test/mcp/v2"

func cardTestBody(t *testing.T, webhooks any) json.RawMessage {
	t.Helper()
	return cardTestJSON(t, map[string]any{"remotes": []any{
		map[string]any{"url": cardTestMCPURL, "extensionsInfo": map[string]any{
			card.EventsExtension: map[string]any{"webhooks": webhooks},
		}},
	}})
}

func TestServerCardOriginAndDefaultURL(t *testing.T) {
	for _, tt := range []struct {
		url  string
		want bool
	}{
		{"https://MCP.EXAMPLE.TEST:443/other?x=1", true},
		{"https://mcp.example.test:8443/mcp/v2", false},
		{"https://other.example.test/mcp/v2", false},
		{"http://mcp.example.test/mcp/v2", false},
		{"https://mcp.example.test/../mcp/v2", false},
	} {
		if got := card.SameOrigin(cardTestMCPURL, tt.url); got != tt.want {
			t.Errorf("SameOrigin(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
	if card.SameOrigin("not a URL", "not a URL") {
		t.Error("two refused URLs are not same-origin")
	}
	for _, tt := range []struct{ url, want string }{
		{"HTTPS://MCP.EXAMPLE.TEST:443/?ignored", "https://mcp.example.test/server-card"},
		{"https://mcp.example.test", "https://mcp.example.test/server-card"},
		{"https://mcp.example.test:8443/mcp/v2/?ignored", "https://mcp.example.test:8443/mcp/v2/server-card"},
		{"https://mcp.example.test/mcp//", "https://mcp.example.test/mcp//server-card"},
		{"https://[2001:DB8::1]:8443/mcp", "https://[2001:db8::1]:8443/mcp/server-card"},
		{"http://mcp.example.test/mcp", ""},
	} {
		if got, ok := card.DefaultCardURL(tt.url); got != tt.want || ok != (tt.want != "") {
			t.Errorf("DefaultCardURL(%q) = %q, %v; want %q", tt.url, got, ok, tt.want)
		}
	}
}

func TestServerCardSelectRemoteTiers(t *testing.T) {
	entries := []json.RawMessage{
		json.RawMessage(`null`),
		json.RawMessage(`{"url":false}`),
		json.RawMessage(`{"url":"https://mcp.example.test/mcp/v2?q={template}"}`),
		json.RawMessage(`{"url":"https://other.example.test/mcp/v2"}`),
		json.RawMessage(`{"url":"https://mcp.example.test:8443/mcp/v2"}`),
		json.RawMessage(`{"url":"https://mcp.example.test/mcp/v2/child"}`),
		json.RawMessage(`{"url":"https://mcp.example.test/sibling"}`),
		json.RawMessage(`{"url":"https://mcp.example.test/"}`),
		json.RawMessage(`{"url":"https://mcp.example.test/mcp/v?first"}`),
		json.RawMessage(`{"url":"https://mcp.example.test/mcp/v?second"}`),
		json.RawMessage(`{"url":"https://mcp.example.test/mcp?short"}`),
		json.RawMessage(`{"url":"https://mcp.example.test/mcp/v2?exact"}`),
		json.RawMessage(`{"url":"https://mcp.example.test/mcp/v2?exact-second"}`),
	}
	for _, tt := range []struct {
		name string
		end  int
		pick int
		url  string
	}{
		{"no remote", 5, -1, ""},
		{"origin only tie", 7, 5, "https://mcp.example.test/mcp/v2/child"},
		{"prefix beats origin only", 8, 7, "https://mcp.example.test/"},
		{"longest prefix and tie", 11, 8, "https://mcp.example.test/mcp/v?first"},
		{"exact and tie", 13, 11, "https://mcp.example.test/mcp/v2?exact"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := cardTestJSON(t, map[string]any{"remotes": entries[:tt.end]})
			got, ok := card.SelectRemote(body, cardTestMCPURL)
			if ok != (tt.pick >= 0) || got.URL != tt.url || (ok && !bytes.Equal(got.Raw, entries[tt.pick])) {
				t.Errorf("SelectRemote = %q, raw %s, %v; want %q", got.URL, got.Raw, ok, tt.url)
			}
			if _, ok := card.SelectRemote(body, "http://mcp.example.test/mcp/v2"); ok {
				t.Error("selected a remote for a refused MCP URL")
			}
		})
	}
}

func TestServerCardWebhookInfoShapes(t *testing.T) {
	for _, tt := range []struct {
		name, extension string
		keys            string
		ranges          []string
	}{
		{name: "no extensions"},
		{name: "empty events", extension: `,"extensionsInfo":{"io.modelcontextprotocol/events":{}}`},
		{name: "no signing keys", extension: `,"extensionsInfo":{"io.modelcontextprotocol/events":{"webhooks":{"egressIpRanges":["192.0.2.0/24",null,3,"::/0"]}}}`, ranges: []string{"192.0.2.0/24", "::/0"}},
		{name: "raw keys and ranges not array", extension: `,"extensionsInfo":{"io.modelcontextprotocol/events":{"webhooks":{"signingKeys":{"keys": [ ]},"egressIpRanges":{}}}}`, keys: `{"keys": [ ]}`},
		{name: "keys not object and empty ranges", extension: `,"extensionsInfo":{"io.modelcontextprotocol/events":{"webhooks":{"signingKeys":[],"egressIpRanges":[]}}}`, ranges: []string{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := json.RawMessage(`{"remotes":[{"url":"` + cardTestMCPURL + `"` + tt.extension + `}]}`)
			got, code := card.WebhookInfo(body, cardTestMCPURL)
			if code != "" || got.RemoteURL != cardTestMCPURL || string(got.SigningKeys) != tt.keys || !reflect.DeepEqual(got.Egress, tt.ranges) {
				t.Errorf("WebhookInfo = {keys:%s egress:%#v remote:%q}, %q", got.SigningKeys, got.Egress, got.RemoteURL, code)
			}
		})
	}
	if _, code := card.WebhookInfo(json.RawMessage(`{"remotes":{}}`), cardTestMCPURL); code != "no_remote" {
		t.Errorf("WebhookInfo code = %q, want no_remote", code)
	}
}

func TestServerCardFetchRefusalOrder(t *testing.T) {
	elapsed := int64(10001)
	in := card.FetchInput{
		MCPURL: cardTestMCPURL, CardURL: "http://other.example.test/server-card", Status: 399,
		ElapsedMS: &elapsed, Body: bytes.Repeat([]byte{'x'}, card.MaxCardBytes+1),
	}
	// Each step repairs the preceding refusal while leaving the later ones.
	for _, tt := range []struct {
		repair       func(*card.FetchInput)
		code, reason string
	}{
		{nil, "not_https", "scheme_not_https"},
		{func(in *card.FetchInput) { in.CardURL = "https://other.example.test/server-card#fragment" }, "not_https", "fragment"},
		{func(in *card.FetchInput) { in.CardURL = "https://other.example.test/server-card" }, "cross_origin", "origin_mismatch"},
		{func(in *card.FetchInput) { in.CardURL = "https://mcp.example.test/server-card" }, "redirect_refused", "redirect"},
		{func(in *card.FetchInput) { in.Status = 400 }, "http_status", "status"},
		{func(in *card.FetchInput) { in.Status = 299 }, "timeout", "elapsed"},
		{func(in *card.FetchInput) { in.ElapsedMS = nil }, "too_large", "body"},
		{func(in *card.FetchInput) { in.Body = []byte(`{`) }, "bad_json", "json"},
		{func(in *card.FetchInput) { in.Body = []byte(`null`) }, "bad_json", "shape"},
		{func(in *card.FetchInput) { in.Body = []byte(` {}`) }, "no_remote", "no_remote"},
	} {
		if tt.repair != nil {
			tt.repair(&in)
		}
		want := card.FetchError{Code: tt.code, Reason: tt.reason}
		if _, err := card.FetchDecision(in); err == nil || *err != want {
			t.Fatalf("FetchDecision error = %+v, want %+v", err, want)
		}
	}
}

func TestServerCardFetchAcceptedAtLimits(t *testing.T) {
	jwk, _ := cardTestJWK(11)
	server, _ := cardTestJWK(12)
	signingKeys := cardTestJSON(t, map[string]any{"keys": []any{jwk, server}})
	body := cardTestBody(t, map[string]any{
		"signingKeys":    signingKeys,
		"egressIpRanges": []any{"203.0.113.0/24", "203.0.113.1/24", false, "2001:db8::/32"},
	})
	padded := append([]byte(body), bytes.Repeat([]byte{' '}, card.MaxCardBytes-len(body))...)
	elapsed := int64(10000)
	for _, tt := range []struct {
		headers map[string]string
		ttl     int64
	}{
		{map[string]string{"cache-control": "private, max-age=60, max-age=90"}, 60},
		{nil, 300},
	} {
		got, err := card.FetchDecision(card.FetchInput{
			MCPURL: cardTestMCPURL, CardURL: "https://mcp.example.test/server-card", Status: 200,
			Headers: tt.headers, Body: padded, ElapsedMS: &elapsed, Options: card.Options{MCPServerKID: server.Kid},
		})
		if err != nil {
			t.Fatalf("FetchDecision at limits: %+v", err)
		}
		if got.CacheTTL != tt.ttl || !bytes.Equal(got.Keys.Raw, signingKeys) ||
			len(got.Keys.Accepted) != 1 || card.JWKOf(got.Keys.Accepted[0]) != jwk ||
			!reflect.DeepEqual(got.Keys.Rejected, []card.Rejected{{KID: &server.Kid, Reason: "mcp_server_key"}}) ||
			!reflect.DeepEqual(got.Egress, []card.EgressRange{{CIDR: "203.0.113.0/24", Family: "ipv4", Prefix: 24}, {CIDR: "2001:db8::/32", Family: "ipv6", Prefix: 32}}) {
			t.Errorf("unexpected FetchDecision result: %+v (want TTL %d)", got, tt.ttl)
		}
	}
	for _, webhooks := range []any{nil, map[string]any{"signingKeys": map[string]any{"keys": false}}} {
		got, err := card.FetchDecision(card.FetchInput{
			MCPURL: cardTestMCPURL, CardURL: "https://mcp.example.test/server-card", Status: 200,
			Body: cardTestBody(t, webhooks),
		})
		if err != nil || len(got.Keys.Accepted) != 0 || len(got.Keys.Rejected) != 0 {
			t.Errorf("absent JWK array: result %+v, error %+v", got, err)
		}
	}
}

func TestServerCardParseCIDRList(t *testing.T) {
	got, rejected := card.ParseCIDRList([]string{
		"203.0.113.1/24", "203.0.113.0/24", "2001:DB8::/32", "invalid", "0.0.0.0/0", "::/129",
	})
	want := []card.EgressRange{
		{CIDR: "203.0.113.0/24", Family: "ipv4", Prefix: 24},
		{CIDR: "2001:DB8::/32", Family: "ipv6", Prefix: 32},
		{CIDR: "0.0.0.0/0", Family: "ipv4", Prefix: 0},
	}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(rejected, []string{"203.0.113.1/24", "invalid", "::/129"}) {
		t.Errorf("ParseCIDRList = %+v, %q", got, rejected)
	}
}

func TestServerCardCacheTTL(t *testing.T) {
	for _, tt := range []struct {
		header string
		want   int64
	}{
		{"", 300},
		{"max-age=900, max-age=2", 300},
		{"max-age=99999999999999999999999999999999", 300},
		{"private,\t max-age=00060 , max-age=7", 60},
		{"max-age=0", 0},
		{`max-age="60", max-age =5, max-age=+2, max-age=-1, max-age=1.5, max-age=, Max-Age=1`, 300},
		{"max-age=10junk, s-maxage=20, max-age=42", 42},
		{"\uFEFFmax-age=21\u00a0", 21},
	} {
		if got := card.CardCacheTTL(map[string]string{"cache-control": tt.header}); got != tt.want {
			t.Errorf("CardCacheTTL(%q) = %d, want %d", tt.header, got, tt.want)
		}
	}
	if got := card.CardCacheTTL(map[string]string{"Cache-Control": "max-age=0"}); got != 300 {
		t.Errorf("non-normalized header was used: TTL %d", got)
	}
}
