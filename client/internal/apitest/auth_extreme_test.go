package client_test

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
)

func TestResponseFreshnessExtremeClockDoesNotWrap(t *testing.T) {
	const minimum int64 = -1 << 63
	key := carrierKey("extreme-clock")
	body := []byte("public response")
	requestSig := "bound-request-signature"
	headers := carrierHeader(key, 200, requestSig, 0, body)
	public := key.Public().(ed25519.PublicKey)
	var raw [32]byte
	copy(raw[:], public)
	known := map[string]client.RotationResponseKey{jack.KeyID(public): {PublicKey: raw}}
	for _, sample := range []int64{minimum, minimum + 1, -31, 31} {
		now := time.Unix(sample, 0)
		if now.Unix() != sample {
			t.Fatal("fixture clock sample is not representable")
		}
		err := client.VerifyResponse(public, 200, headers, requestSig, body, now, 30*time.Second)
		var rejection *jack.Error
		if !errors.As(err, &rejection) || rejection.Code != jack.CodeTimestampOutOfWindow {
			t.Fatalf("stale response accepted at raw clock %d: %v", sample, err)
		}
		_, err = client.VerifyRotationCarrier(known, 200, headers, requestSig, body, now, 30*time.Second)
		if !errors.As(err, &rejection) || rejection.Code != jack.CodeTimestampOutOfWindow {
			t.Fatalf("candidate carrier bypassed freshness at %d: %v", sample, err)
		}
	}
	for _, sample := range []int64{-30, 0, 30} {
		if err := client.VerifyResponse(public, 200, headers, requestSig, body, time.Unix(sample, 0), 30*time.Second); err != nil {
			t.Fatalf("inclusive ordinary freshness boundary changed at %d: %v", sample, err)
		}
	}
}
