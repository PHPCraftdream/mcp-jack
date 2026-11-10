package client_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
)

func carrierKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("mcp-jack public rotation carrier fixture " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func carrierHeader(key ed25519.PrivateKey, status int, requestSig string, ts int64, body []byte) []string {
	kid := jack.KeyID(key.Public().(ed25519.PublicKey))
	message := jack.ResponseSigningString(status, requestSig, kid, ts, body)
	return []string{jack.FormatResponseAuth(jack.ResponseAuth{Kid: kid, TS: ts, Sig: jack.EncodeBase64URL(ed25519.Sign(key, []byte(message)))})}
}

func TestRotationCarrierKnownMapPrecedesFreshnessSignatureAndPayload(t *testing.T) {
	key := carrierKey("known")
	other := carrierKey("unknown")
	user := carrierKey("user")
	userKID := jack.KeyID(user.Public().(ed25519.PublicKey))
	request := jack.RequestSigningString("POST", "/mcp", "public-aud", userKID, 100, jack.EncodeBase64URL(make([]byte, 16)), nil)
	requestSig := jack.EncodeBase64URL(ed25519.Sign(user, []byte(request)))
	kid := jack.KeyID(key.Public().(ed25519.PublicKey))
	var pub [32]byte
	copy(pub[:], key.Public().(ed25519.PublicKey))
	cutoff := int64(110)
	known := map[string]client.RotationResponseKey{kid: {PublicKey: pub, NotBefore: 0, KnownCutoff: &cutoff}}
	body := []byte("{not-json")
	deny := func(headers []string, body []byte, now int64, want string) {
		t.Helper()
		_, err := client.VerifyRotationCarrier(known, 200, headers, requestSig, body, time.Unix(now, 0), 30*time.Second)
		var rejection *jack.Error
		if !errors.As(err, &rejection) || rejection.Code != want || rejection.HTTPStatus != 0 {
			t.Fatalf("got %v want %s", err, want)
		}
	}
	// Exact bytes аутентифицируются без eager JSON parsing.
	metadata, err := client.VerifyRotationCarrier(known, 200, carrierHeader(key, 200, requestSig, 109, body), requestSig, body, time.Unix(109, 0), 30*time.Second)
	if err != nil || metadata.KID != kid || metadata.Timestamp != 109 {
		t.Fatalf("valid known carrier: %+v %v", metadata, err)
	}
	unknownKID := jack.KeyID(other.Public().(ed25519.PublicKey))
	unknown := []string{jack.FormatResponseAuth(jack.ResponseAuth{Kid: unknownKID, TS: 0, Sig: jack.EncodeBase64URL(make([]byte, 64))})}
	deny(unknown, body, 1000, jack.CodeUnknownServerKey)
	staleBadSignature := []string{jack.FormatResponseAuth(jack.ResponseAuth{Kid: kid, TS: 0, Sig: jack.EncodeBase64URL(make([]byte, 64))})}
	deny(staleBadSignature, body, 1000, jack.CodeTimestampOutOfWindow)
	badSignature := []string{jack.FormatResponseAuth(jack.ResponseAuth{Kid: kid, TS: 109, Sig: jack.EncodeBase64URL(make([]byte, 64))})}
	deny(badSignature, body, 109, jack.CodeBadSignature)
	deny(carrierHeader(key, 200, requestSig, 109, body), []byte("changed body"), 109, jack.CodeBadSignature)
	deny(carrierHeader(key, 200, requestSig, 109, body), body, 110, "rotation_key_interval")
	deny(carrierHeader(key, 200, requestSig, 110, body), body, 109, "rotation_key_interval")
	known[kid] = client.RotationResponseKey{PublicKey: pub, NotBefore: 100}
	deny(carrierHeader(key, 200, requestSig, 99, body), body, 100, "rotation_key_interval")
	if _, err := client.VerifyRotationCarrier(known, 200, carrierHeader(key, 200, requestSig, 100, body), requestSig, body, time.Unix(100, 0), 30*time.Second); err != nil {
		t.Fatal("inclusive new-key lower bound:", err)
	}
	known[kid] = client.RotationResponseKey{PublicKey: pub, NotBefore: 110, KnownCutoff: &cutoff}
	deny(carrierHeader(key, 200, requestSig, 110, body), body, 110, "rotation_key_interval")
}

func TestRotationCarrierRejectsInvalidWindowOrLocalKeySnapshot(t *testing.T) {
	key := carrierKey("configuration")
	kid := jack.KeyID(key.Public().(ed25519.PublicKey))
	var pub [32]byte
	copy(pub[:], key.Public().(ed25519.PublicKey))
	known := map[string]client.RotationResponseKey{kid: {PublicKey: pub}}
	body := []byte("public body")
	headers := carrierHeader(key, 200, "request-signature", 100, body)
	for _, window := range []time.Duration{0, time.Millisecond, 121 * time.Second} {
		if _, err := client.VerifyRotationCarrier(known, 200, headers, "request-signature", body, time.Unix(100, 0), window); err == nil {
			t.Fatal("invalid immutable candidate window accepted")
		}
	}
	known[kid] = client.RotationResponseKey{}
	if _, err := client.VerifyRotationCarrier(known, 200, headers, "request-signature", body, time.Unix(100, 0), 30*time.Second); err == nil {
		t.Fatal("invalid local public identity accepted")
	}
}
