package client

import (
	"errors"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

// RotationResponseKey comes only from an independently trusted/ACKed snapshot.
// NotBefore — signing-time lower bound; KnownCutoff nil means an unknown successor.
type RotationResponseKey struct {
	PublicKey   [32]byte
	NotBefore   int64
	KnownCutoff *int64
}

// RotationCarrier is crypto/interval metadata, not ClockGuard readiness or a trust ACK.
type RotationCarrier struct {
	KID       string
	Timestamp int64
}

// VerifyRotationCarrier preserves the unknown-key → freshness → signature order.
// Transport bounds the body; the function checks its exact bytes, not JSON/payload.
// Caller must then run the durable ClockGuard before DecodeResult, the final
// interval/bridge/revision checks, and whole-state CAS. No fetch, retry, or mutation.
func VerifyRotationCarrier(known map[string]RotationResponseKey, status int, headerValues []string, requestSig string, body []byte, now time.Time, window time.Duration) (RotationCarrier, error) {
	refuse := func(code string) (RotationCarrier, error) {
		return RotationCarrier{}, &jack.Error{HTTPStatus: 0, Code: code, Message: "rotation response verification refused"}
	}
	if window < time.Second || window > 120*time.Second || window%time.Second != 0 {
		return refuse("rotation_state_unknown")
	}
	auth, err := jack.ParseResponseAuth(headerValues)
	if err != nil {
		var parsed *jack.Error
		if errors.As(err, &parsed) {
			return RotationCarrier{}, &jack.Error{HTTPStatus: 0, Code: parsed.Code, Message: parsed.Message}
		}
		return RotationCarrier{}, err
	}
	key, exists := known[auth.Kid]
	if !exists {
		return refuse(jack.CodeUnknownServerKey)
	}
	if jack.ValidatePublicKey(key.PublicKey[:]) != nil || jack.KeyID(key.PublicKey[:]) != auth.Kid || key.NotBefore < 0 || key.NotBefore > rotation.MaxTimestamp {
		return refuse("rotation_state_unknown")
	}
	var cutoff int64
	limited := key.KnownCutoff != nil
	if limited {
		cutoff = *key.KnownCutoff
		if cutoff < key.NotBefore || cutoff > rotation.MaxTimestamp {
			return refuse("rotation_state_unknown")
		}
	}
	if err := VerifyResponse(key.PublicKey[:], status, headerValues, requestSig, body, now, window); err != nil {
		return RotationCarrier{}, err
	}
	if auth.TS < key.NotBefore || (limited && (auth.TS >= cutoff || now.Unix() >= cutoff)) {
		return refuse("rotation_key_interval")
	}
	return RotationCarrier{KID: auth.Kid, Timestamp: auth.TS}, nil
}
