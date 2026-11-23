package vectors_test

import (
	"encoding/json"
	"maps"
	"reflect"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/endpoint"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/urlcheck"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/vector"
)

const (
	corpusFile = "webhook-endpoint-verification-vectors.json"
	caseCount  = 93
	hookURL    = "https://hooks.example.test/hooks/alice"
	wellKnown  = "https://hooks.example.test/.well-known/mcp-webhook-receiver.json"
)

// The reference runner forwards only these fields to each SDK operation.
var (
	echoKeys       = []string{"status", "bodyText", "nonce", "maxBody"}
	acceptEchoKeys = []string{"nonce", "expected", "issuedAt", "now", "ttl", "consumed", "pair", "expectedPair"}
	postKeys       = []string{"url", "answers", "allowedRanges", "recheck", "redirect"}
	docFetchKeys   = []string{"status", "bodyText", "maxBody"}
	docRequestKeys = append(postKeys, "status", "bodyText")

	docFetchDefault = fields{
		"url":     json.RawMessage(`"` + wellKnown + `"`),
		"answers": json.RawMessage(`["93.184.216.34"]`),
	}
)

func TestWebhookEndpointVerificationVectors(t *testing.T) {
	corpus, err := vector.Load(corpusFile)
	if err != nil {
		t.Fatal(err)
	}
	vector.Expect(t, corpus, caseCount, corpusFile)

	pass := 0
	for _, c := range corpus.Cases {
		t.Run(c.ID, func(t *testing.T) {
			got := run(t, c)
			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("%s: encode result: %v", c.ID, err)
			}
			var actual, want any
			if err := json.Unmarshal(gotJSON, &actual); err != nil {
				t.Fatalf("%s: decode result: %v", c.ID, err)
			}
			if err := json.Unmarshal(c.Expect, &want); err != nil {
				t.Fatalf("%s: decode expectation: %v", c.ID, err)
			}
			if !reflect.DeepEqual(actual, want) {
				t.Fatalf("%s:\n got %s\nwant %s", c.ID, gotJSON, c.Expect)
			}
			pass++
		})
	}
	if pass != caseCount {
		t.Fatalf("%s: passed %d cases, want %d", corpusFile, pass, caseCount)
	}
	vector.Summary(t, "webhook-endpoint-verification", pass, 0, 0)
}

func run(t *testing.T, c vector.Case) map[string]any {
	t.Helper()
	var input fields
	if err := json.Unmarshal(c.Input, &input); err != nil {
		t.Fatalf("%s: decode input: %v", c.ID, err)
	}

	switch c.Kind {
	case "nonce":
		return map[string]any{"result": result(endpoint.NonceOK(input.text("value")))}
	case "echo":
		return challengeResult(challengeEcho(t, only(input, echoKeys)))
	case "accept-echo":
		in := only(input, acceptEchoKeys)
		ttl := int64(600)
		if raw, ok := in["ttl"]; ok {
			ttl, _ = vector.Int(raw)
		}
		return challengeResult(endpoint.AcceptEcho(endpoint.EchoInput{
			Nonce:        in.text("nonce"),
			Expected:     in.text("expected"),
			IssuedAt:     in.integer("issuedAt"),
			Now:          in.integer("now"),
			TTL:          ttl,
			Consumed:     decode[bool](in["consumed"]),
			Pair:         decode[any](in["pair"]),
			ExpectedPair: decode[any](in["expectedPair"]),
		}))
	case "doc":
		return documentResult(endpoint.ParseReceiverDoc(input.text("text")))
	case "covers":
		receivers, err := endpoint.ParseReceiverDoc(input.text("text"))
		if err != nil {
			return map[string]any{"covered": false, "entry": nil}
		}
		entry, covered := endpoint.ReceiverDocCovers(receivers, input.text("path"))
		return map[string]any{"covered": covered, "entry": nullable(entry)}
	case "allowlist-entry":
		return allowlistResult(endpoint.ParseAllowlistEntry(input.text("entry")))
	case "allowlist":
		return allowlistResult(endpoint.AllowlistMatches(decode[[]string](input["entries"]), input.text("url")))
	case "ttl":
		var maxAge *int64
		if value, ok := vector.Int(input["maxAge"]); ok {
			maxAge = &value
		}
		return map[string]any{"result": "accept", "ttl": endpoint.DocCacheTTL(maxAge)}
	case "wellknown-url":
		url, ok := endpoint.WellKnownURL(input.text("url"))
		if !ok {
			return map[string]any{"result": "reject"}
		}
		return map[string]any{"result": "accept", "url": url}
	case "route":
		verdict := endpoint.VerificationRoute(routeInput(t, input))
		return map[string]any{
			"result": result(verdict.Verified),
			"route":  nullable(verdict.Route),
			"reason": nullable(verdict.Reason),
		}
	case "gate":
		return map[string]any{"action": endpoint.DeliveryAction(endpoint.GateInput{
			Verified: decode[bool](input["verified"]),
			Message:  input.text("message"),
		})}
	case "url-check":
		checked, err := urlcheck.Check(input.text("url"))
		if err != nil {
			return refusal(err.Code, err.Reason)
		}
		return map[string]any{"result": "accept", "canonical": checked.Canonical}
	case "verification-post":
		checked := delivery.Check(postInput(only(input, postKeys)))
		if !checked.Allow {
			return refusal(checked.Code, checked.Reason)
		}
		return map[string]any{"result": "accept", "address": checked.Address}
	case "doc-fetch":
		if _, present := input["url"]; present {
			return documentResult(docRequest(only(input, docRequestKeys)))
		}
		in := only(input, docFetchKeys)
		maxBody := int64(8192)
		if raw, ok := in["maxBody"]; ok {
			maxBody, _ = vector.Int(raw)
		}
		return documentResult(endpoint.CheckReceiverDocFetch(int(in.integer("status")), in.text("bodyText"), maxBody))
	default:
		t.Fatalf("%s: unknown kind %q", c.ID, c.Kind)
		return nil
	}
}

type fields map[string]json.RawMessage

func only(source fields, keys []string) fields {
	out := make(fields, len(keys))
	for _, key := range keys {
		if value, ok := source[key]; ok {
			out[key] = value
		}
	}
	return out
}

func (in fields) text(key string) string {
	value, _ := vector.String(in[key])
	return value
}

func (in fields) integer(key string) int64 {
	value, _ := vector.Int(in[key])
	return value
}

// decode returns the zero value for absent or incompatible fields. In
// particular, decoding as any preserves the JSON shape of pair inputs.
func decode[T any](raw json.RawMessage) T {
	var value T
	if !vector.Null(raw) && json.Unmarshal(raw, &value) == nil {
		return value
	}
	var zero T
	return zero
}

func challengeEcho(t *testing.T, in fields) *endpoint.Error {
	t.Helper()
	// ChallengeEcho enforces the profile's fixed limit. The corpus uses that
	// limit; fail explicitly if a future vector requests a different one.
	if maxBody := in.integer("maxBody"); maxBody != 0 && maxBody != endpoint.MaxChallengeBytes {
		t.Fatalf("challenge maxBody %d cannot be passed to endpoint.ChallengeEcho", maxBody)
	}
	return endpoint.ChallengeEcho(int(in.integer("status")), in.text("bodyText"), in.text("nonce"))
}

func routeInput(t *testing.T, input fields) endpoint.RouteInput {
	t.Helper()
	in := endpoint.RouteInput{
		Cache: decode[bool](input["cache"]),
		Hook:  decode[bool](input["hook"]),
		URL:   hookURL,
	}
	if !vector.Null(input["url"]) {
		in.URL = input.text("url")
	}
	if allowlist := decode[fields](input["allowlist"]); allowlist != nil {
		// VerificationRoute calls AllowlistMatches using these entries and URL.
		in.Allowlist = decode[[]string](allowlist["entries"])
	}
	in.Doc, in.DocPath = docEvidence(decode[fields](input["doc"]))
	if challenge := decode[fields](input["challenge"]); challenge != nil {
		in.Challenge = challengeEcho(t, only(challenge, echoKeys))
		if in.Challenge == nil {
			// A non-nil zero error marks a successful attempt, not absent evidence.
			in.Challenge = &endpoint.Error{}
		}
	}
	return in
}

func docEvidence(doc fields) ([]string, string) {
	if doc == nil {
		return nil, ""
	}
	merged := maps.Clone(docFetchDefault)
	maps.Copy(merged, doc)
	receivers, err := docRequest(only(merged, docRequestKeys))
	if err != nil {
		return nil, ""
	}
	return receivers, doc.text("path")
}

func postInput(in fields) delivery.CheckInput {
	return delivery.CheckInput{
		URL:           in.text("url"),
		Answers:       decode[[]string](in["answers"]),
		AllowedRanges: decode[[]string](in["allowedRanges"]),
		Recheck:       decode[[]string](in["recheck"]),
		Redirect:      decode[*int](in["redirect"]),
	}
}

func docRequest(in fields) ([]string, *endpoint.Error) {
	post := postInput(in)
	return endpoint.ReceiverDocRequest(post.URL, post.Answers, post.AllowedRanges, post.Recheck, post.Redirect,
		int(in.integer("status")), in.text("bodyText"))
}

func result(ok bool) string {
	if ok {
		return "accept"
	}
	return "reject"
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func challengeResult(err *endpoint.Error) map[string]any {
	if err != nil {
		return map[string]any{"result": "reject", "code": err.Code, "reason": err.Reason}
	}
	return map[string]any{"result": "accept"}
}

func documentResult(receivers []string, err *endpoint.Error) map[string]any {
	if err != nil {
		return map[string]any{"result": "reject", "code": err.Code, "reason": err.Reason}
	}
	return map[string]any{"result": "accept", "receivers": receivers}
}

func allowlistResult(entry endpoint.AllowlistEntry, ok bool) map[string]any {
	if !ok {
		return map[string]any{"result": "reject"}
	}
	return map[string]any{
		"result":       "accept",
		"host_pattern": entry.HostPattern,
		"port":         entry.Port,
		"path":         entry.Path,
	}
}

func refusal(code, reason string) map[string]any {
	out := map[string]any{"result": "reject", "code": code}
	if reason != "" {
		out["reason"] = reason
	}
	return out
}
