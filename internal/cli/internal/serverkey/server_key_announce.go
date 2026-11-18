package serverkey

import (
	"encoding/json"
	"io"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	rotationserver "github.com/PHPCraftdream/mcp-jack/server/rotation"
)

type ServerKeyPublication struct {
	Ordinal       uint64 `json:"ordinal"`
	Hash          string `json:"hash"`
	PublishedAt   int64  `json:"published_at"`
	ActivatesAt   int64  `json:"activates_at"`
	StateRevision uint64 `json:"state_revision"`
	Record        string `json:"record"`
}

// Offline exclusive owner; stdout/Close failure does not roll back the committed publication.
func ServerKeyAnnounce(configPath, reference, kid string, output io.Writer) error {
	if output == nil {
		return command.ErrConfig
	}
	config, options, err := OfflineServerKeyProfile(configPath)
	if err != nil {
		return command.ErrConfig
	}
	if _, err := jack.DecodeBase64URLFixed(kid, 32); err != nil {
		return command.ErrConfig
	}
	found := false
	for _, entry := range config.Signers {
		if entry.Reference == reference && entry.KID == kid {
			found = true
		}
	}
	if !found {
		return command.ErrConfig
	}
	keys, clearKeys, err := LoadServerKeyInventory(config.Signers)
	if err != nil {
		return command.ErrConfig
	}
	defer clearKeys()
	store, err := durable.OpenServer(config.StoreFile, options)
	if err != nil {
		return command.ErrConfig
	}
	defer store.Close()
	provider, err := rotationserver.New(store, keys)
	if err != nil {
		return command.ErrConfig
	}
	publication, err := provider.Announce(reference, kid)
	if err != nil {
		return command.ErrConfig
	}
	if err := store.Close(); err != nil {
		return command.ErrConfig
	}
	return json.NewEncoder(output).Encode(ServerKeyPublication{
		Ordinal: publication.Record.Ordinal, Hash: publication.Record.Hash,
		PublishedAt: publication.Record.PublishedAt, ActivatesAt: publication.Record.ActivatesAt,
		StateRevision: publication.Revision, Record: publication.Record.Wire,
	})
}
