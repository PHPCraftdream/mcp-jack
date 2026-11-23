package modernvectors

import (
	"encoding/json"
	"testing"

	clientmodern "github.com/PHPCraftdream/mcp-jack/client/modern"
)

// annotationDefinition is a tool or event descriptor of
// x-mcp-header-vectors.json.
type annotationDefinition struct {
	Name        string          `json:"name"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// annotationCase is one case of x-mcp-header-vectors.json.
type annotationCase struct {
	ID          string                `json:"id"`
	Kind        string                `json:"kind"`
	Rule        string                `json:"rule"`
	Description string                `json:"description"`
	Tool        *annotationDefinition `json:"tool"`
	Event       *annotationDefinition `json:"event"`
	Arguments   json.RawMessage       `json:"arguments"`
	Expect      json.RawMessage       `json:"expect"`
}

// annotationVectorFile is x-mcp-header-vectors.json.
type annotationVectorFile struct {
	Cases []annotationCase `json:"cases"`
}

func TestModernXMcpHeaderVectors(t *testing.T) {
	raw := fixtureFile(t, "x-mcp-header-vectors.json")
	var corpus annotationVectorFile
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("decode x-mcp-header-vectors.json: %v", err)
	}
	if len(corpus.Cases) != 84 {
		t.Fatalf("x-mcp-header-vectors.json: got %d cases, want 84", len(corpus.Cases))
	}

	pass := 0
	for i := range corpus.Cases {
		c := corpus.Cases[i]
		t.Run(c.ID, func(t *testing.T) {
			var schema json.RawMessage
			switch c.Kind {
			case "validate", "project":
				if c.Tool == nil {
					t.Fatalf("case kind %q has no tool", c.Kind)
				}
				schema = c.Tool.InputSchema
			case "validate-event", "project-event":
				if c.Event == nil {
					t.Fatalf("case kind %q has no event", c.Kind)
				}
				schema = c.Event.InputSchema
			default:
				t.Fatalf("unknown kind %q", c.Kind)
			}

			switch c.Kind {
			case "validate", "validate-event":
				check := clientmodern.ValidateAnnotations(schema)
				got := map[string]any{"valid": check.Valid, "reason": nil}
				if !check.Valid {
					got["reason"] = check.Reason
				}
				assertCase(t, c.ID, c.Expect, got)

			case "project", "project-event":
				headers, err := clientmodern.ProjectArguments(schema, c.Arguments)
				var got map[string]any
				if err != nil {
					got = map[string]any{"outcome": "refuse", "reason": clientmodern.ProjectionReason}
				} else {
					got = map[string]any{"outcome": "headers", "headers": headerPairs(headers)}
				}
				assertCase(t, c.ID, c.Expect, got)
			}
			pass++
		})
	}
	summary(t, "x-mcp-header", pass)
}
