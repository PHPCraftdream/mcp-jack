package cli

import (
	"encoding/json"
	"io"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	rotationserver "github.com/PHPCraftdream/mcp-jack/server/rotation"
)

type serverKeyPublication struct {
	Ordinal       uint64 `json:"ordinal"`
	Hash          string `json:"hash"`
	PublishedAt   int64  `json:"published_at"`
	ActivatesAt   int64  `json:"activates_at"`
	StateRevision uint64 `json:"state_revision"`
	Record        string `json:"record"`
}

// Offline exclusive owner; stdout/Close failure не откатывает committed publication.
func serverKeyAnnounce(configPath, reference, kid string, output io.Writer) error {
	if output == nil {
		return errConfig
	}
	config, options, err := offlineServerKeyProfile(configPath)
	if err != nil {
		return errConfig
	}
	if _, err := jack.DecodeBase64URLFixed(kid, 32); err != nil {
		return errConfig
	}
	found := false
	for _, entry := range config.Signers {
		if entry.Reference == reference && entry.KID == kid {
			found = true
		}
	}
	if !found {
		return errConfig
	}
	keys, clearKeys, err := loadServerKeyInventory(config.Signers)
	if err != nil {
		return errConfig
	}
	defer clearKeys()
	store, err := durable.OpenServer(config.StoreFile, options)
	if err != nil {
		return errConfig
	}
	defer store.Close()
	provider, err := rotationserver.New(store, keys)
	if err != nil {
		return errConfig
	}
	publication, err := provider.Announce(reference, kid)
	if err != nil {
		return errConfig
	}
	if err := store.Close(); err != nil {
		return errConfig
	}
	return json.NewEncoder(output).Encode(serverKeyPublication{
		Ordinal: publication.Record.Ordinal, Hash: publication.Record.Hash,
		PublishedAt: publication.Record.PublishedAt, ActivatesAt: publication.Record.ActivatesAt,
		StateRevision: publication.Revision, Record: publication.Record.Wire,
	})
}
