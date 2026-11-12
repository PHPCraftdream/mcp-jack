package rotation_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strconv"
	"testing"

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
