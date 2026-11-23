package modernvectors

import (
	"encoding/json"
	"testing"

	clientmodern "github.com/PHPCraftdream/mcp-jack/client/modern"
)

// eraResponse is the response under test of era-detection-vectors.json.
type eraResponse struct {
	BodyText *string `json:"body_text"`
	Status   int     `json:"status"`
	Verified bool    `json:"verified"`
}

// eraCase is one case of era-detection-vectors.json.
type eraCase struct {
	ID             string          `json:"id"`
	Rule           string          `json:"rule"`
	Description    string          `json:"description"`
	ClientVersions []string        `json:"clientVersions"`
	Response       eraResponse     `json:"response"`
	Expect         json.RawMessage `json:"expect"`
}

// eraVectorFile is era-detection-vectors.json.
type eraVectorFile struct {
	Cases []eraCase `json:"cases"`
}

func TestModernEraDetectionVectors(t *testing.T) {
	raw := fixtureFile(t, "era-detection-vectors.json")
	var corpus eraVectorFile
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("decode era-detection-vectors.json: %v", err)
	}
	if len(corpus.Cases) != 38 {
		t.Fatalf("era-detection-vectors.json: got %d cases, want 38", len(corpus.Cases))
	}

	pass := 0
	for i := range corpus.Cases {
		c := corpus.Cases[i]
		t.Run(c.ID, func(t *testing.T) {
			var body []byte
			if c.Response.BodyText != nil {
				body = []byte(*c.Response.BodyText)
			}
			d := clientmodern.DetectEra(c.Response.Status, c.Response.Verified, body, c.ClientVersions)
			got := map[string]any{
				"era":    string(d.Era),
				"action": string(d.Action),
				"reason": nil,
			}
			if d.Reason != "" {
				got["reason"] = d.Reason
			}
			if d.Action == clientmodern.ActionRetryWithSupported {
				got["supported"] = d.Supported
			}
			assertCase(t, c.ID, c.Expect, got)
			pass++
		})
	}
	summary(t, "era-detection", pass)
}
