package rotation

import (
	"bytes"
	"strconv"
	"strings"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// Signer provides an Ed25519 signature without exporting private material.
type Signer interface {
	PublicKey() []byte
	Sign([]byte) ([]byte, error)
}

// CreateRecord creates a statement but does not publish it or change trust.
// Previous must be an independently trusted checkpoint or an ACKed tail.
// The publication owner performs the full retained-key reuse check and durable ACK.
func CreateRecord(binding Binding, previous Checkpoint, oldSigner, nextSigner Signer, publishedAt int64) (Record, error) {
	if !validBinding(binding) {
		return Record{}, invalid("binding_size")
	}
	if previous.Ordinal >= MaxOrdinal {
		return Record{}, invalid("ordinal")
	}
	if previous.PublishedAt < 0 || previous.PublishedAt > MaxTimestamp || publishedAt < previous.PublishedAt {
		return Record{}, invalid("publication_order")
	}
	if publishedAt > MaxTimestamp-GraceSeconds {
		return Record{}, invalid("activation")
	}
	if previous.Ordinal == 0 {
		if previous.Hash != "-" {
			return Record{}, invalid("previous_hash")
		}
	} else if _, err := jack.DecodeBase64URLFixed(previous.Hash, 32); err != nil {
		return Record{}, invalid("previous_hash")
	}
	if oldSigner == nil || nextSigner == nil {
		return Record{}, invalid("signer_unavailable")
	}
	oldPublic := append([]byte(nil), oldSigner.PublicKey()...)
	nextPublic := append([]byte(nil), nextSigner.PublicKey()...)
	if jack.ValidatePublicKey(oldPublic) != nil || jack.KeyID(oldPublic) != previous.KID || !bytes.Equal(oldPublic, previous.PublicKey[:]) {
		return Record{}, invalid("unknown_authorizer")
	}
	if jack.ValidatePublicKey(nextPublic) != nil {
		return Record{}, invalid("new_key")
	}
	nextKID := jack.KeyID(nextPublic)
	if nextKID == previous.KID {
		return Record{}, invalid("key_reuse")
	}
	body := strings.Join([]string{
		Domain,
		jack.EncodeBase64URL([]byte(binding.Endpoint)),
		jack.EncodeBase64URL([]byte(binding.Audience)),
		strconv.FormatUint(previous.Ordinal+1, 10),
		previous.Hash,
		previous.KID,
		nextKID,
		jack.EncodeBase64URL(nextPublic),
		strconv.FormatInt(publishedAt, 10),
		strconv.FormatInt(publishedAt+GraceSeconds, 10),
	}, "\n")
	nextMessage := []byte(Domain + "/next-proof\n" + body)
	proof, err := nextSigner.Sign(append([]byte(nil), nextMessage...))
	if err != nil {
		return Record{}, invalid("signer_unavailable")
	}
	proof = append([]byte(nil), proof...)
	if !jack.Verify(nextPublic, nextMessage, proof) {
		return Record{}, invalid("new_proof")
	}
	proofText := jack.EncodeBase64URL(proof)
	oldMessage := []byte(Domain + "/authorize\n" + body + "\n" + proofText)
	authorization, err := oldSigner.Sign(append([]byte(nil), oldMessage...))
	if err != nil {
		return Record{}, invalid("signer_unavailable")
	}
	authorization = append([]byte(nil), authorization...)
	if !jack.Verify(oldPublic, oldMessage, authorization) {
		return Record{}, invalid("old_authorization")
	}
	wire := []byte(body + "\n" + proofText + "\n" + jack.EncodeBase64URL(authorization))
	return Parse(wire, binding, map[string][]byte{previous.KID: oldPublic})
}
