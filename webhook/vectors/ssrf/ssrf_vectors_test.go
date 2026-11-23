package vectors_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/ipaddr"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/urlcheck"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/vector"
)

func TestWebhookSSRFVectors(t *testing.T) {
	corpus, err := vector.Load("ssrf-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	vector.Expect(t, corpus, 120, "ssrf-vectors.json")

	pass := 0
	for _, c := range corpus.Cases {
		if t.Run(c.ID, func(t *testing.T) {
			gotJSON, err := json.Marshal(runSSRF(t, c))
			if err != nil {
				t.Fatalf("%s: marshal result: %v", c.ID, err)
			}
			var got, want any
			if err := json.Unmarshal(gotJSON, &got); err != nil {
				t.Fatalf("%s: decode result: %v", c.ID, err)
			}
			if err := json.Unmarshal(c.Expect, &want); err != nil {
				t.Fatalf("%s: decode expectation: %v", c.ID, err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s:\n got %s\nwant %s", c.ID, gotJSON, c.Expect)
			}
		}) {
			pass++
		}
	}
	if pass != 120 {
		t.Fatalf("ssrf-vectors.json: got %d passes, want 120", pass)
	}
	vector.Summary(t, "ssrf", pass, 0, 0)
}

func runSSRF(t *testing.T, c vector.Case) map[string]any {
	t.Helper()
	var input struct {
		Address       string   `json:"address"`
		Host          string   `json:"host"`
		URL           string   `json:"url"`
		Answers       []string `json:"answers"`
		Recheck       []string `json:"recheck"`
		AllowedRanges []string `json:"allowedRanges"`
		Redirect      *int     `json:"redirect"`
		CIDR          string   `json:"cidr"`
	}
	if err := json.Unmarshal(c.Input, &input); err != nil {
		t.Fatalf("%s: decode input: %v", c.ID, err)
	}

	switch c.Kind {
	case "address":
		v := ipaddr.ClassifyAddress(input.Address)
		got := map[string]any{"result": "reject", "reason": v.Reason}
		if v.Family != "" {
			got["family"] = v.Family
			if v.Allow {
				got["result"] = "accept"
			}
		}
		return got
	case "host":
		h, reason := ipaddr.ParseHost(input.Host)
		if reason != "" {
			return map[string]any{"result": "reject", "reason": reason}
		}
		return map[string]any{"result": "accept", "kind": h.Kind, "normalized": h.Normalized}
	case "url":
		u, err := urlcheck.Check(input.URL)
		if err != nil {
			return ssrfRefusal(err.Code, err.Reason)
		}
		return map[string]any{
			"result":    "accept",
			"canonical": u.Canonical,
			"host":      u.Host,
			"port":      u.Port,
			"path":      u.Path,
			"query":     u.Query,
		}
	case "delivery":
		r := delivery.Check(delivery.CheckInput{
			URL:           input.URL,
			Answers:       input.Answers,
			Recheck:       input.Recheck,
			AllowedRanges: input.AllowedRanges,
			Redirect:      input.Redirect,
		})
		if !r.Allow {
			return ssrfRefusal(r.Code, r.Reason)
		}
		var sni any
		if r.UsesSNI {
			sni = r.SNI
		}
		return map[string]any{
			"result":      "accept",
			"address":     r.Address,
			"reason":      r.Reason,
			"host_header": r.HostHeader,
			"sni":         sni,
		}
	case "cidr":
		rangeCIDR, ok := ipaddr.ParseCIDR(input.CIDR)
		if !ok {
			return map[string]any{"result": "reject"}
		}
		return map[string]any{"result": "accept", "contains": rangeCIDR.Contains(input.Address)}
	default:
		t.Fatalf("%s: unknown kind %q", c.ID, c.Kind)
		return nil
	}
}

func ssrfRefusal(code, reason string) map[string]any {
	got := map[string]any{"result": "reject", "code": code}
	if reason != "" {
		got["reason"] = reason
	}
	return got
}
