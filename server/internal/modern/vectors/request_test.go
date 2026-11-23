package modernvectors

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/server/internal/modern"
	"github.com/PHPCraftdream/mcp-jack/server/internal/rpcbody"
	spec "github.com/PHPCraftdream/mcp-jack/spec"
)

// requestCase is one request-level case of modern-request-vectors.json.
type requestCase struct {
	ID      string `json:"id"`
	Rule    string `json:"rule"`
	Profile string `json:"profile"`
	Request struct {
		Method   string      `json:"method"`
		Target   string      `json:"target"`
		BodyText *string     `json:"body_text"`
		Headers  [][2]string `json:"headers"`
	} `json:"request"`
	Expect json.RawMessage `json:"expect"`
}

// byReferenceCase is the cache-replay entry of modern-request-vectors.json.
type byReferenceCase struct {
	ID          string   `json:"id"`
	Rule        string   `json:"rule"`
	File        string   `json:"file"`
	Vectors     []string `json:"vectors"`
	Description string   `json:"description"`
}

// requestVectorFile is modern-request-vectors.json.
type requestVectorFile struct {
	Cases       []requestCase     `json:"cases"`
	ByReference []byReferenceCase `json:"by_reference"`
}

func TestModernRequestVectors(t *testing.T) {
	raw := fixtureFile(t, "modern-request-vectors.json")
	var corpus requestVectorFile
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("decode modern-request-vectors.json: %v", err)
	}
	if len(corpus.Cases) != 98 {
		t.Fatalf("modern-request-vectors.json: got %d cases, want 98", len(corpus.Cases))
	}
	if len(corpus.ByReference) != 1 {
		t.Fatalf("modern-request-vectors.json: got %d by_reference entries, want 1", len(corpus.ByReference))
	}
	ref := corpus.ByReference[0]
	if ref.ID != "cache-replay" {
		t.Fatalf("by_reference id = %q, want %q", ref.ID, "cache-replay")
	}
	if ref.Rule != "C8" {
		t.Fatalf("by_reference rule = %q, want %q", ref.Rule, "C8")
	}
	if ref.File != "fixtures/response-vectors.json" {
		t.Fatalf("by_reference file = %q, want %q", ref.File, "fixtures/response-vectors.json")
	}
	wantRefs := []string{"res-wrong-request-binding", "res-accept"}
	if !reflect.DeepEqual(ref.Vectors, wantRefs) {
		t.Fatalf("by_reference vectors = %v, want %v", ref.Vectors, wantRefs)
	}

	pass := 0
	for i := range corpus.Cases {
		c := corpus.Cases[i]
		t.Run(c.ID, func(t *testing.T) {
			var body []byte
			if c.Request.BodyText != nil {
				body = []byte(*c.Request.BodyText)
			}
			refusal := modern.BodyRefusalNone
			if len(body) > 0 {
				_, refusal = rpcbody.ClassifyReason(body)
			}
			headers := make([]modern.Header, 0, len(c.Request.Headers))
			for _, h := range c.Request.Headers {
				headers = append(headers, modern.Header{Name: h[0], Value: h[1]})
			}
			got := modern.Classify(modern.Profile(c.Profile), modern.Request{
				Method:      c.Request.Method,
				Target:      c.Request.Target,
				Headers:     headers,
				Body:        body,
				BodyRefusal: refusal,
			})
			assertCase(t, c.ID, c.Expect, got.Wire())
			pass++
		})
	}
	summary(t, "modern-request", pass)

	t.Run("cache-replay", func(t *testing.T) {
		vectors, err := spec.LoadResponseVectors()
		if err != nil {
			t.Fatalf("LoadResponseVectors: %v", err)
		}
		byID := make(map[string]spec.ResponseCase, len(vectors.Cases))
		for _, tc := range vectors.Cases {
			byID[tc.ID] = tc
		}

		accept, ok := byID["res-accept"]
		if !ok {
			t.Fatalf("response-vectors.json: res-accept not found")
		}
		if err := verifyResponseCase(t, accept); err != nil {
			t.Fatalf("res-accept: got error %v, want accept", err)
		}

		wrong, ok := byID["res-wrong-request-binding"]
		if !ok {
			t.Fatalf("response-vectors.json: res-wrong-request-binding not found")
		}
		err = verifyResponseCase(t, wrong)
		if err == nil {
			t.Fatalf("res-wrong-request-binding: got nil error, want reject %q", jack.CodeBadSignature)
		}
		var jackErr *jack.Error
		if !errors.As(err, &jackErr) {
			t.Fatalf("res-wrong-request-binding: got error %v, not a *jack.Error", err)
		}
		if jackErr.Code != jack.CodeBadSignature {
			t.Fatalf("res-wrong-request-binding: code = %q, want %q", jackErr.Code, jack.CodeBadSignature)
		}
	})
}

// verifyResponseCase runs client.VerifyResponse exactly as
// client/internal/apitest/verify_test.go does.
func verifyResponseCase(t *testing.T, tc spec.ResponseCase) error {
	t.Helper()
	serverKey, err := jack.DecodeBase64URLFixed(tc.State.PinnedServerPublicKey, 32)
	if err != nil {
		t.Fatalf("%s: decode server key: %v", tc.ID, err)
	}
	var headerValues []string
	for _, p := range tc.Response.Headers {
		if strings.EqualFold(p.Name, "Jack-Auth") {
			headerValues = append(headerValues, p.Value)
		}
	}
	body, err := tc.Response.Body()
	if err != nil {
		t.Fatalf("%s: decode body: %v", tc.ID, err)
	}
	window := time.Duration(tc.State.WindowSeconds) * time.Second
	return client.VerifyResponse(serverKey, tc.Response.Status, headerValues, tc.State.RequestSig, body, time.Unix(tc.State.Now, 0), window)
}
