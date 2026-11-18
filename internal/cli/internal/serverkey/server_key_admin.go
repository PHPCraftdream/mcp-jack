package serverkey

import (
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"unicode/utf8"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/gatewayconfig"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/storage"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

// Separate private OOB profile; init/status do not load private signer material.
type ServerKeyConfig struct {
	Version         int                     `json:"version"`
	StoreFile       string                  `json:"store_file"`
	Endpoint        string                  `json:"endpoint"`
	Aud             string                  `json:"aud"`
	Window          int64                   `json:"window"`
	AnchorKID       string                  `json:"anchor_kid"`
	AnchorPublicKey string                  `json:"anchor_public_key"`
	AnchorReference string                  `json:"anchor_reference"`
	Signers         []ServerKeySignerConfig `json:"signers,omitempty"`
}

func OfflineServerKeyProfile(path string) (ServerKeyConfig, durable.ServerOptions, error) {
	var config ServerKeyConfig
	if storage.DecodeConfig(path, &config) != nil || config.Version != 1 || storage.PrivateParent(config.StoreFile) != nil || !validServerKeyInventory(config.Signers) ||
		config.Endpoint == "" || len(config.Endpoint) > 2048 || !utf8.ValidString(config.Endpoint) ||
		config.Aud == "" || len(config.Aud) > 1024 || !utf8.ValidString(config.Aud) || config.Window < 1 || config.Window > gatewayconfig.MaxDurableWindow ||
		config.AnchorReference == "" || len(config.AnchorReference) > rotation.MaxSignerReferenceBytes || !utf8.ValidString(config.AnchorReference) {
		return ServerKeyConfig{}, durable.ServerOptions{}, command.ErrConfig
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || !endpoint.IsAbs() || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" || endpoint.User != nil || endpoint.Opaque != "" || endpoint.Fragment != "" || strings.ContainsAny(config.Endpoint, "\r\n\\") {
		return ServerKeyConfig{}, durable.ServerOptions{}, command.ErrConfig
	}
	public, err := jack.DecodeBase64URLFixed(config.AnchorPublicKey, 32)
	if err != nil || jack.ValidatePublicKey(public) != nil || jack.KeyID(public) != config.AnchorKID {
		return ServerKeyConfig{}, durable.ServerOptions{}, command.ErrConfig
	}
	checkpoint := rotation.Checkpoint{Hash: "-", KID: config.AnchorKID}
	copy(checkpoint.PublicKey[:], public)
	options := durable.ServerOptions{
		TrustOptions:    durable.TrustOptions{Binding: rotation.Binding{Endpoint: config.Endpoint, Audience: config.Aud}, Window: config.Window, Checkpoint: checkpoint},
		AnchorReference: config.AnchorReference,
	}
	return config, options, nil
}

// Confirmation is an assertion of a never-used binding, not migration/recovery proof.
func ServerKeyInitializeUnused(configPath, confirmedEndpoint, confirmedAudience string) error {
	config, options, err := OfflineServerKeyProfile(configPath)
	if err != nil || confirmedEndpoint != config.Endpoint || confirmedAudience != config.Aud {
		return command.ErrConfig
	}
	if err := durable.InitializeServerUnused(config.StoreFile, options); err != nil {
		return command.ErrConfig
	}
	return nil
}

func ServerKeyStatus(configPath string, output io.Writer) error {
	if output == nil {
		return command.ErrConfig
	}
	config, options, err := OfflineServerKeyProfile(configPath)
	if err != nil {
		return command.ErrConfig
	}
	report, err := durable.InspectServer(config.StoreFile, options)
	if err != nil {
		return command.ErrConfig
	}
	return json.NewEncoder(output).Encode(report)
}
