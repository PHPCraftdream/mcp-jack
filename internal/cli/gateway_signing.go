package cli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"sync"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	rotationserver "github.com/PHPCraftdream/mcp-jack/server/rotation"
)

type rotationProfilePath string

func (path *rotationProfilePath) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	var value string
	if len(data) == 0 || data[0] != '"' || json.Unmarshal(data, &value) != nil {
		return errConfig
	}
	*path = rotationProfilePath(value)
	return nil
}

type gatewaySigning struct {
	key        ed25519.PrivateKey
	provider   *rotationserver.Provider
	anchorKID  string
	serverKIDs map[string]bool
	close      func() error
}

// Ни один profile не создаёт store и не переключается на другой при отказе.
func selectGatewaySigning(config gatewayConfig) (*gatewaySigning, error) {
	if (config.ServerSeedFile == "") == (config.ServerRotationFile == "") {
		return nil, errConfig
	}
	if config.ServerRotationFile == "" {
		seed, err := readPrivate(config.ServerSeedFile, ed25519.SeedSize)
		if err != nil || len(seed) != ed25519.SeedSize {
			clear(seed)
			return nil, errConfig
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
	profile, options, err := offlineServerKeyProfile(string(config.ServerRotationFile))
	if err != nil || profile.Aud != config.Aud || config.DurableNonces == nil ||
		config.DurableNonces.validate(config.MaxConcurrent) != nil || profile.Window != config.DurableNonces.Window ||
		profile.StoreFile == config.DurableNonces.Path || profile.StoreFile == config.StateFile {
		return nil, errConfig
	}
	keys, clearKeys, err := loadServerKeyInventory(profile.Signers)
	if err != nil {
		return nil, errConfig
	}
	store, err := durable.OpenServer(profile.StoreFile, options)
	if err != nil {
		clearKeys()
		return nil, errConfig
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
		return nil, errConfig
	}
	snapshot, _, err := store.Snapshot()
	if err != nil {
		return nil, errConfig
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
