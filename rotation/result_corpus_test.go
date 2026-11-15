package rotation_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

// Один result-body кейс общего дифференциального corpus
// rust/tests/rotation-property-corpus.json (его же читает TS-тест).
type corpusResultCase struct {
	ID          string   `json:"id"`
	IDJSON      string   `json:"id_json"`
	Body        string   `json:"body"`
	Accept      bool     `json:"accept"`
	KID         string   `json:"kid"`
	PublicKey   string   `json:"public_key"`
	Records     []string `json:"records"`
	HeadOrdinal uint64   `json:"head_ordinal"`
	HeadHash    string   `json:"head_hash"`
	Complete    bool     `json:"complete"`
}

type corpusDocument struct {
	Format       string             `json:"format"`
	ResultBodies []corpusResultCase `json:"result_bodies"`
}

func loadRotationCorpus(t *testing.T) corpusDocument {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "rust", "tests", "rotation-property-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document corpusDocument
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func TestDecodeResultMatchesSharedRotationCorpus(t *testing.T) {
	document := loadRotationCorpus(t)
	if document.Format != "mcp-jack-rotation-property-corpus-v1" {
		t.Fatalf("unexpected corpus format: %s", document.Format)
	}
	accepted, rejected := 0, 0
	for _, entry := range document.ResultBodies {
		decoded, err := rotation.DecodeResult([]byte(entry.Body), json.RawMessage(entry.IDJSON))
		if !entry.Accept {
			rejected++
			var failure *rotation.Error
			if !errors.As(err, &failure) || failure.Code != "rotation_result_invalid" {
				t.Fatalf("case %s: expected rotation_result_invalid, got %v", entry.ID, err)
			}
			continue
		}
		accepted++
		if err != nil {
			t.Fatalf("case %s: %v", entry.ID, err)
		}
		public, err := jack.DecodeBase64URLFixed(entry.PublicKey, 32)
		if err != nil {
			t.Fatalf("case %s: corpus public key: %v", entry.ID, err)
		}
		if decoded.Current.KID != entry.KID ||
			!bytes.Equal(decoded.Current.PublicKey[:], public) ||
			decoded.Head.Ordinal != entry.HeadOrdinal ||
			decoded.Head.Hash != entry.HeadHash ||
			decoded.Complete != entry.Complete ||
			len(decoded.Records) != len(entry.Records) {
			t.Fatalf("case %s: decoded fields differ from corpus expectations", entry.ID)
		}
		for index, record := range entry.Records {
			if decoded.Records[index] != record {
				t.Fatalf("case %s: record %d differs", entry.ID, index)
			}
		}
	}
	if len(document.ResultBodies) != 54 || accepted != 14 || rejected != 40 {
		t.Fatalf("corpus size drift: %d cases, %d accepted, %d rejected", len(document.ResultBodies), accepted, rejected)
	}
}
