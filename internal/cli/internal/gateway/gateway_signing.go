package gateway

import (
	"crypto/ed25519"
	"sync"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gatewayconfig"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/serverkey"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
	rotationserver "github.com/PHPCraftdream/mcp-jack/server/rotation"
)

type gatewaySigning struct {
	key        ed25519.PrivateKey
	provider   *rotationserver.Provider
	anchorKID  string
	serverKIDs map[string]bool
	close      func() error
}

// No profile creates a store or falls back to another one on failure.
func selectGatewaySigning(config gatewayconfig.Config) (*gatewaySigning, error) {
	if (config.ServerSeedFile == "") == (string(config.ServerRotationFile) == "") {
		return nil, command.ErrConfig
	}
	if config.ServerRotationFile == "" {
		seed, err := storage.ReadPrivate(config.ServerSeedFile, ed25519.SeedSize)
		if err != nil || len(seed) != ed25519.SeedSize {
			clear(seed)
			return nil, command.ErrConfig
		}
		key := ed25519.NewKeyFromSeed(seed)
		clear(seed)
		kid := jack.KeyID(key.Public().(ed25519.PublicKey))
		var once sync.Once
		return &gatewaySigning{
			key: key, anchorKID: kid, serverKIDs: map[string]bool{kid: true},
			close: func() error { once.Do(func() { clear(key) }); return nil },
		}, nil
	}
	profile, options, err := serverkey.OfflineServerKeyProfile(string(config.ServerRotationFile))
	if err != nil || profile.Aud != config.Aud || config.DurableNonces == nil ||
		config.DurableNonces.Validate(config.MaxConcurrent) != nil || profile.Window != config.DurableNonces.Window ||
		profile.StoreFile == config.DurableNonces.Path || profile.StoreFile == config.StateFile {
		return nil, command.ErrConfig
	}
	keys, clearKeys, err := serverkey.LoadServerKeyInventory(profile.Signers)
	if err != nil {
		return nil, command.ErrConfig
	}
	store, err := durable.OpenServer(profile.StoreFile, options)
	if err != nil {
		clearKeys()
		return nil, command.ErrConfig
	}
	ready := false
	defer func() {
		if !ready {
			_ = store.Close()
			clearKeys()
		}
	}()
	provider, err := rotationserver.New(store, keys)
	if err != nil {
		return nil, command.ErrConfig
	}
	snapshot, _, err := store.Snapshot()
	if err != nil {
		return nil, command.ErrConfig
	}
	identities := make(map[string]bool, len(snapshot.Public.Keys)+len(profile.Signers))
	for _, key := range snapshot.Public.Keys {
		identities[key.KID] = true
	}
	for _, key := range profile.Signers {
		identities[key.KID] = true
	}
	var once sync.Once
	var closeErr error
	selected := &gatewaySigning{
		provider: provider, anchorKID: profile.AnchorKID, serverKIDs: identities,
		close: func() error {
			once.Do(func() {
				closeErr = store.Close()
				clearKeys()
			})
			return closeErr
		},
	}
	ready = true
	return selected, nil
}
