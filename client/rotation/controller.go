// Package rotationclient соединяет candidate client gates с concrete durable store.
package rotationclient

import (
	"bytes"
	"errors"
	"sync/atomic"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

// Controller не владеет lifecycle store и не делает network fetch/retry.
type Controller struct {
	store      *durable.TrustStore
	binding    rotation.Binding
	window     int64
	checkpoint rotation.Checkpoint
	writer     atomic.Bool
}

// Response bytes и header values копируются перед cryptographic processing.
type Response struct {
	Status           int
	Headers          []string
	RequestSignature string
	Body             []byte
}

func localError(code string) error {
	return &jack.Error{HTTPStatus: 0, Code: code, Message: "rotation response refused"}
}

func mappedError(err error, fallback string) error {
	var candidate *rotation.Error
	if errors.As(err, &candidate) {
		return localError(candidate.Code)
	}
	var outer *jack.Error
	if errors.As(err, &outer) {
		return &jack.Error{HTTPStatus: 0, Code: outer.Code, Message: outer.Message}
	}
	return localError(fallback)
}

func New(store *durable.TrustStore) (*Controller, error) {
	if store == nil {
		return nil, localError("rotation_state_unknown")
	}
	snapshot, _, err := store.Snapshot()
	if err != nil {
		return nil, mappedError(err, "rotation_state_unknown")
	}
	if _, err := store.CheckSnapshotClock(snapshot); err != nil {
		return nil, mappedError(err, "rotation_clock_unavailable")
	}
	return &Controller{store: store, binding: snapshot.Binding, window: snapshot.Window, checkpoint: snapshot.Checkpoint}, nil
}

func knownKeys(snapshot rotation.TrustSnapshot) map[string]client.RotationResponseKey {
	known := make(map[string]client.RotationResponseKey, len(snapshot.Keys))
	for _, key := range snapshot.Keys {
		known[key.KID] = client.RotationResponseKey{PublicKey: key.PublicKey, NotBefore: key.NotBefore, KnownCutoff: key.KnownCutoff}
	}
	return known
}

func (controller *Controller) state() (rotation.TrustSnapshot, error) {
	snapshot, _, err := controller.store.Snapshot()
	if err != nil {
		return rotation.TrustSnapshot{}, mappedError(err, "rotation_state_unknown")
	}
	if snapshot.Binding != controller.binding || snapshot.Window != controller.window || snapshot.Checkpoint != controller.checkpoint {
		return rotation.TrustSnapshot{}, localError("rotation_state_unknown")
	}
	return snapshot, nil
}

func (controller *Controller) equal(left, right rotation.TrustSnapshot) bool {
	a, err := rotation.EncodeTrustSnapshot(left, controller.binding, controller.window, controller.checkpoint)
	if err != nil {
		return false
	}
	b, err := rotation.EncodeTrustSnapshot(right, controller.binding, controller.window, controller.checkpoint)
	return err == nil && bytes.Equal(a, b)
}

func (controller *Controller) carrier(snapshot rotation.TrustSnapshot, response Response, now int64) (client.RotationCarrier, error) {
	return client.VerifyRotationCarrier(knownKeys(snapshot), response.Status, response.Headers, response.RequestSignature, response.Body, time.Unix(now, 0), time.Duration(controller.window)*time.Second)
}

func (controller *Controller) outer(response Response) (Response, rotation.TrustSnapshot, client.RotationCarrier, error) {
	snapshot, err := controller.state()
	if err != nil {
		return Response{}, rotation.TrustSnapshot{}, client.RotationCarrier{}, err
	}
	response.Headers = append([]string(nil), response.Headers...)
	auth, err := jack.ParseResponseAuth(response.Headers)
	if err != nil {
		return Response{}, snapshot, client.RotationCarrier{}, mappedError(err, "rotation_state_unknown")
	}
	if _, known := knownKeys(snapshot)[auth.Kid]; !known {
		return Response{}, snapshot, client.RotationCarrier{}, localError(jack.CodeUnknownServerKey)
	}
	if len(response.Body) > 1<<20 {
		return Response{}, snapshot, client.RotationCarrier{}, localError("rotation_result_invalid")
	}
	response.Body = append([]byte(nil), response.Body...)
	raw, err := controller.store.RawClock()
	if err != nil {
		return Response{}, snapshot, client.RotationCarrier{}, mappedError(err, "rotation_clock_unavailable")
	}
	carrier, err := controller.carrier(snapshot, response, raw)
	if err != nil {
		return Response{}, snapshot, client.RotationCarrier{}, mappedError(err, "rotation_state_unknown")
	}
	clock, err := controller.store.CheckSnapshotClock(snapshot)
	if err != nil {
		return Response{}, snapshot, client.RotationCarrier{}, mappedError(err, "rotation_clock_unavailable")
	}
	if err := controller.timeValid(snapshot, carrier, clock.HighWater); err != nil {
		return Response{}, snapshot, client.RotationCarrier{}, err
	}
	return response, snapshot, carrier, nil
}

func (controller *Controller) timeValid(snapshot rotation.TrustSnapshot, carrier client.RotationCarrier, now int64) error {
	var distance uint64
	if now < carrier.Timestamp {
		distance = uint64(carrier.Timestamp) - uint64(now)
	} else {
		distance = uint64(now) - uint64(carrier.Timestamp)
	}
	if distance > uint64(controller.window) {
		return localError(jack.CodeTimestampOutOfWindow)
	}
	key, known := knownKeys(snapshot)[carrier.KID]
	if !known {
		return localError(jack.CodeUnknownServerKey)
	}
	if carrier.Timestamp < key.NotBefore || key.KnownCutoff != nil && (carrier.Timestamp >= *key.KnownCutoff || now >= *key.KnownCutoff) {
		return localError("rotation_key_interval")
	}
	if !capacityValid(snapshot, now) {
		return localError("rotation_state_changed")
	}
	return nil
}

func capacityValid(snapshot rotation.TrustSnapshot, now int64) bool {
	if snapshot.Revision == 0 || snapshot.Revision > rotation.MaxOrdinal || len(snapshot.Keys) > rotation.MaxRetainedKeys {
		return false
	}
	pending, retired := 0, 0
	for _, retained := range snapshot.Keys {
		if retained.NotBefore > now {
			pending++
		} else if retained.KnownCutoff != nil && *retained.KnownCutoff <= now {
			retired++
		}
	}
	return pending <= 128 && retired <= 1024
}

func (controller *Controller) final(carrier client.RotationCarrier, expected rotation.TrustSnapshot) error {
	clock, err := controller.store.CheckSnapshotClock(expected)
	if err != nil {
		return mappedError(err, "rotation_clock_unavailable")
	}
	return controller.timeValid(expected, carrier, clock.HighWater)
}

// VerifyResponse возвращает owned body только после final clock/revision/interval gate.
func (controller *Controller) VerifyResponse(response Response) ([]byte, error) {
	owned, snapshot, carrier, err := controller.outer(response)
	if err != nil {
		return nil, err
	}
	if err := controller.final(carrier, snapshot); err != nil {
		return nil, err
	}
	return owned.Body, nil
}
