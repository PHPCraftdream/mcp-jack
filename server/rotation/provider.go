// Package rotationserver связывает concrete server store с explicit ResponseKeys profile.
package rotationserver

import (
	"errors"
	"sync/atomic"
	"unicode/utf8"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	"github.com/PHPCraftdream/mcp-jack/server"
)

var ErrUnavailable = errors.New("rotation server: response authorization unavailable")

// Key задаётся независимо от remote payload; Reference не заменяет проверку PublicKey.
// Signer callbacks должны быть bounded; custody и Close принадлежат caller.
type Key struct {
	Reference string
	Signer    server.ResponseSigner
}

type keyIdentity struct {
	reference string
	kid       string
}

type pinnedSigner struct {
	public [32]byte
	signer server.ResponseSigner
}

func (signer pinnedSigner) PublicKey() []byte                   { return append([]byte{}, signer.public[:]...) }
func (signer pinnedSigner) Sign(message []byte) ([]byte, error) { return signer.signer.Sign(message) }

// Provider копирует public identities; приватные handles не экспортируются и не закрываются.
type Provider struct {
	store       *durable.ServerStore
	keys        map[keyIdentity]pinnedSigner
	publication atomic.Bool
}

func pinKey(input Key) (output pinnedSigner, result error) {
	complete := false
	defer func() {
		if !complete {
			_ = recover()
			result = ErrUnavailable
		}
	}()
	if input.Signer == nil || input.Reference == "" || !utf8.ValidString(input.Reference) || len(input.Reference) > rotation.MaxSignerReferenceBytes {
		return output, ErrUnavailable
	}
	public := append([]byte{}, input.Signer.PublicKey()...)
	if len(public) != len(output.public) || jack.ValidatePublicKey(public) != nil {
		return output, ErrUnavailable
	}
	copy(output.public[:], public)
	output.signer = input.Signer
	complete = true
	return output, nil
}

// New не создаёт state и не разрешает publication; signer inventory только OOB.
func New(store *durable.ServerStore, keys []Key) (*Provider, error) {
	if store == nil || len(keys) == 0 || len(keys) > rotation.MaxRetainedKeys {
		return nil, ErrUnavailable
	}
	provider := &Provider{store: store, keys: make(map[keyIdentity]pinnedSigner, len(keys))}
	for _, key := range keys {
		pinned, err := pinKey(key)
		if err != nil {
			return nil, ErrUnavailable
		}
		identity := keyIdentity{reference: key.Reference, kid: jack.KeyID(pinned.public[:])}
		if _, exists := provider.keys[identity]; exists {
			return nil, ErrUnavailable
		}
		provider.keys[identity] = pinned
	}
	lease, err := provider.AuthorizeResponse(server.ResponseKeyRequest{})
	if err != nil {
		return nil, err
	}
	lease.Release()
	return provider, nil
}

// selectSigner требует все pending handles и текущий signer; retired handles необязательны.
func (provider *Provider) selectSigner(snapshot rotation.ServerSnapshot, clock rotation.ClockTuple) (pinnedSigner, error) {
	// Snapshot уже полностью проверен; после fresh sample — только interval arithmetic.
	var selected pinnedSigner
	found := false
	pendingCount, retiredCount := 0, 0
	for index, key := range snapshot.Public.Keys {
		eligible := key.NotBefore <= clock.HighWater && (key.KnownCutoff == nil || clock.HighWater < *key.KnownCutoff)
		pending := key.NotBefore > clock.HighWater
		if pending {
			pendingCount++
		}
		if key.KnownCutoff != nil && *key.KnownCutoff <= clock.HighWater {
			retiredCount++
		}
		if pendingCount > 128 || retiredCount > 1024 {
			return pinnedSigner{}, ErrUnavailable
		}
		if !eligible && !pending {
			continue
		}
		reference := snapshot.SignerReferences[index]
		signer, exists := provider.keys[keyIdentity{reference: reference.Reference, kid: key.KID}]
		if !exists || signer.public != key.PublicKey {
			return pinnedSigner{}, ErrUnavailable
		}
		if eligible {
			selected, found = signer, true
		}
	}
	if !found {
		return pinnedSigner{}, ErrUnavailable
	}
	return selected, nil
}

// AuthorizeResponse не доверяет body/tool при выборе identity и не делает fallback.
// Final однократен; Release обязателен после physical write, также при любой ошибке.
func (provider *Provider) AuthorizeResponse(input server.ResponseKeyRequest) (server.ResponseKeyAuthorization, error) {
	if provider == nil || provider.store == nil {
		return server.ResponseKeyAuthorization{}, ErrUnavailable
	}
	page, err := decodeNativeResponse(input)
	if err != nil {
		return server.ResponseKeyAuthorization{}, ErrUnavailable
	}
	release, err := provider.store.AcquireServingLease()
	if err != nil {
		return server.ResponseKeyAuthorization{}, ErrUnavailable
	}
	ready := false
	defer func() {
		if !ready {
			release()
		}
	}()
	snapshot, _, err := provider.store.Snapshot()
	if err != nil {
		return server.ResponseKeyAuthorization{}, ErrUnavailable
	}
	clock, err := provider.store.CheckSnapshotClock(snapshot)
	if err != nil {
		return server.ResponseKeyAuthorization{}, ErrUnavailable
	}
	signer, err := provider.selectSigner(snapshot, clock)
	if err != nil {
		return server.ResponseKeyAuthorization{}, ErrUnavailable
	}
	if !matchesNativeResponse(page, snapshot, signer) {
		return server.ResponseKeyAuthorization{}, ErrUnavailable
	}
	var finalized, released atomic.Bool
	authorization := server.ResponseKeyAuthorization{
		Signer:    signer,
		Timestamp: clock.HighWater,
		Release: func() {
			if released.CompareAndSwap(false, true) {
				release()
			}
		},
		Final: func() error {
			if released.Load() || !finalized.CompareAndSwap(false, true) {
				return ErrUnavailable
			}
			final, err := provider.store.CheckSnapshotClock(snapshot)
			if err != nil || final.HighWater < clock.HighWater || final.HighWater-clock.HighWater > snapshot.Public.Window {
				return ErrUnavailable
			}
			current, err := provider.selectSigner(snapshot, final)
			if err != nil || current.public != signer.public || released.Load() {
				return ErrUnavailable
			}
			return nil
		},
	}
	ready = true
	return authorization, nil
}

var _ server.ResponseKeyProvider = (*Provider)(nil)
