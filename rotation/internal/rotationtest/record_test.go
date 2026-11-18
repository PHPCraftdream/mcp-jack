package rotation_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

type recordSigner struct {
	key   ed25519.PrivateKey
	calls int
	fail  bool
	forge bool
}

func namedRecordSigner(name string) *recordSigner {
	seed := sha256.Sum256([]byte("mcp-jack test key: candidate-server-" + name))
	return &recordSigner{key: ed25519.NewKeyFromSeed(seed[:])}
}

func (s *recordSigner) PublicKey() []byte {
	return append([]byte(nil), s.key.Public().(ed25519.PublicKey)...)
}

func (s *recordSigner) Sign(message []byte) ([]byte, error) {
	s.calls++
	if s.fail {
		return nil, errors.New("test signer unavailable")
	}
	if s.forge {
		message[0] ^= 1
	}
	return ed25519.Sign(s.key, message), nil
}

func TestIndependentNegativeVectors(t *testing.T) {
	v, binding, anchor, keys := fixture(t)
	if len(v.Malformed) != 19 {
		t.Fatalf("negative vectors: %d", len(v.Malformed))
	}
	for _, row := range v.Malformed {
		t.Run(row.ID, func(t *testing.T) {
			wire, err := jack.DecodeBase64URL(row.Wire)
			if err != nil {
				t.Fatal(err)
			}
			switch row.Setup {
			case "chain":
				_, err = rotation.VerifyChain([][]byte{wire}, binding, anchor, nil)
			case "after-r1":
				_, err = rotation.VerifyChain([][]byte{[]byte(v.Chains["overlapping"][0]), wire}, binding, anchor, nil)
			case "decreasing":
				_, err = rotation.VerifyChain([][]byte{[]byte(v.Controls.DecreasingPrefix), wire}, binding, anchor, nil)
			default:
				_, err = rotation.Parse(wire, rotation.Binding{Endpoint: row.Binding.Endpoint, Audience: row.Binding.Audience}, keys)
			}
			var rejection *rotation.Error
			if !errors.As(err, &rejection) || rejection.Code != row.Expected {
				t.Fatalf("got %v, want %s", err, row.Expected)
			}
		})
	}
}

func TestIndependentPositiveBytesAndSignatures(t *testing.T) {
	v, binding, anchor, _ := fixture(t)
	for name, chain := range v.Chains {
		t.Run(name, func(t *testing.T) {
			records, err := rotation.VerifyChain(wires(chain), binding, anchor, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 2 {
				t.Fatalf("records: %d", len(records))
			}
			for i, record := range records {
				if record.Wire != chain[i] || record.Hash != jack.BodyHash([]byte(chain[i])) {
					t.Fatal("exact record bytes/hash changed")
				}
				lines := strings.Split(record.Wire, "\n")
				body := strings.Join(lines[:10], "\n")
				seed := sha256.Sum256([]byte("mcp-jack test key: candidate-server-next" + string(rune('1'+i))))
				key := ed25519.NewKeyFromSeed(seed[:])
				proof := ed25519.Sign(key, []byte(rotation.Domain+"/next-proof\n"+body))
				if jack.EncodeBase64URL(proof) != lines[10] {
					t.Fatal("Go signature differs from independent fixture")
				}
			}
			if rotation.SelectedOrdinal(records, 173799) != 0 {
				t.Fatal("early activation")
			}
			if name == "tie" {
				if rotation.SelectedOrdinal(records, 173800) != 2 || rotation.AssignmentValid(records, 1, 173800, 173800) {
					t.Fatal("equal-time ordinal rule")
				}
			} else {
				if !rotation.AssignmentValid(records, 1, 173800, 173800) {
					t.Fatal("inclusive lower bound")
				}
				if rotation.AssignmentValid(records, 1, 177399, 177400) {
					t.Fatal("old signer survived strict cutoff")
				}
			}
		})
	}
}

func TestCreateRecordMatchesIndependentCompleteRecordBytes(t *testing.T) {
	v, binding, anchor, _ := fixture(t)
	for name, wires := range v.Chains {
		t.Run(name, func(t *testing.T) {
			previous := anchor
			for index, expected := range wires {
				oldName := "anchor"
				if index > 0 {
					oldName = "next" + strconv.Itoa(index)
				}
				oldSigner := namedRecordSigner(oldName)
				nextSigner := namedRecordSigner("next" + strconv.Itoa(index+1))
				published := int64(1000)
				if name == "overlapping" && index == 1 {
					published = 4600
				}
				record, err := rotation.CreateRecord(binding, previous, oldSigner, nextSigner, published)
				if err != nil {
					t.Fatal(err)
				}
				if record.Wire != expected {
					t.Fatal("complete Go-signed record differs from independent fixture")
				}
				if oldSigner.calls != 1 || nextSigner.calls != 1 {
					t.Fatal("signer was retried")
				}
				previous = rotation.Checkpoint{Ordinal: record.Ordinal, Hash: record.Hash, KID: record.NewKID, PublicKey: record.PublicKey, PublishedAt: record.PublishedAt}
			}
		})
	}
}

func TestCreateRecordRejectsBeforeSignerSideEffects(t *testing.T) {
	_, binding, anchor, _ := fixture(t)
	oldSigner, nextSigner := namedRecordSigner("anchor"), namedRecordSigner("next1")
	invalidBinding := binding
	invalidBinding.Endpoint = ""
	if _, err := rotation.CreateRecord(invalidBinding, anchor, oldSigner, nextSigner, 1000); err == nil {
		t.Fatal("empty binding accepted")
	}
	if _, err := rotation.CreateRecord(binding, anchor, oldSigner, oldSigner, 1000); err == nil {
		t.Fatal("adjacent key reuse accepted")
	}
	if _, err := rotation.CreateRecord(binding, anchor, oldSigner, nextSigner, rotation.MaxTimestamp); err == nil {
		t.Fatal("activation overflow accepted")
	}
	if oldSigner.calls != 0 || nextSigner.calls != 0 {
		t.Fatal("invalid input invoked signer")
	}
}

func TestHistoryCapacityIncludesImplicitCheckpointKey(t *testing.T) {
	_, binding, anchor, _ := fixture(t)
	retained := make(map[string][]byte, rotation.MaxRetainedKeys)
	for index := 0; index < rotation.MaxRetainedKeys; index++ {
		retained["unvalidated-"+strconv.Itoa(index)] = nil
	}
	_, err := rotation.VerifyChain(nil, binding, anchor, retained)
	var rejection *rotation.Error
	if !errors.As(err, &rejection) || rejection.Code != "capacity" {
		t.Fatalf("implicit checkpoint exceeded capacity: %v", err)
	}
}

func TestAssignmentRejectsOutOfDomainOrdinal(t *testing.T) {
	ordinal := rotation.MaxOrdinal + 1
	if rotation.AssignmentValid([]rotation.Record{{Ordinal: ordinal, ActivatesAt: 100}}, ordinal, 100, 100) {
		t.Fatal("out-of-domain ordinal assigned")
	}
}

func TestCreateRecordChecksNewProofBeforeOldAuthorization(t *testing.T) {
	_, binding, anchor, _ := fixture(t)
	for _, forged := range []bool{false, true} {
		oldSigner, nextSigner := namedRecordSigner("anchor"), namedRecordSigner("next1")
		nextSigner.fail = !forged
		nextSigner.forge = forged
		if _, err := rotation.CreateRecord(binding, anchor, oldSigner, nextSigner, 1000); err == nil {
			t.Fatal("failed or altered new proof accepted")
		}
		if oldSigner.calls != 0 || nextSigner.calls != 1 {
			t.Fatal("old signer authorized an unverified proof or signer retried")
		}
	}
}
