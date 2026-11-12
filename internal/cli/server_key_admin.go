package cli

import (
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"unicode/utf8"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

// Отдельный private OOB profile; init/status не загружают private signer material.
type serverKeyConfig struct {
	Version         int                     `json:"version"`
	StoreFile       string                  `json:"store_file"`
	Endpoint        string                  `json:"endpoint"`
	Aud             string                  `json:"aud"`
	Window          int64                   `json:"window"`
	AnchorKID       string                  `json:"anchor_kid"`
	AnchorPublicKey string                  `json:"anchor_public_key"`
	AnchorReference string                  `json:"anchor_reference"`
	Signers         []serverKeySignerConfig `json:"signers,omitempty"`
}

func offlineServerKeyProfile(path string) (serverKeyConfig, durable.ServerOptions, error) {
	var config serverKeyConfig
	if decodeConfig(path, &config) != nil || config.Version != 1 || privateParent(config.StoreFile) != nil || !validServerKeyInventory(config.Signers) ||
		config.Endpoint == "" || len(config.Endpoint) > 2048 || !utf8.ValidString(config.Endpoint) ||
		config.Aud == "" || len(config.Aud) > 1024 || !utf8.ValidString(config.Aud) || config.Window < 1 || config.Window > 120 ||
		config.AnchorReference == "" || len(config.AnchorReference) > rotation.MaxSignerReferenceBytes || !utf8.ValidString(config.AnchorReference) {
		return serverKeyConfig{}, durable.ServerOptions{}, errConfig
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || !endpoint.IsAbs() || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" || endpoint.User != nil || endpoint.Opaque != "" || endpoint.Fragment != "" || strings.ContainsAny(config.Endpoint, "\r\n\\") {
		return serverKeyConfig{}, durable.ServerOptions{}, errConfig
	}
	public, err := jack.DecodeBase64URLFixed(config.AnchorPublicKey, 32)
	if err != nil || jack.ValidatePublicKey(public) != nil || jack.KeyID(public) != config.AnchorKID {
		return serverKeyConfig{}, durable.ServerOptions{}, errConfig
	}
	checkpoint := rotation.Checkpoint{Hash: "-", KID: config.AnchorKID}
	copy(checkpoint.PublicKey[:], public)
	options := durable.ServerOptions{
		TrustOptions:    durable.TrustOptions{Binding: rotation.Binding{Endpoint: config.Endpoint, Audience: config.Aud}, Window: config.Window, Checkpoint: checkpoint},
		AnchorReference: config.AnchorReference,
	}
	return config, options, nil
}

// Подтверждение — заявление never-used binding, не migration/recovery proof.
func serverKeyInitializeUnused(configPath, confirmedEndpoint, confirmedAudience string) error {
	config, options, err := offlineServerKeyProfile(configPath)
	if err != nil || confirmedEndpoint != config.Endpoint || confirmedAudience != config.Aud {
		return errConfig
	}
	if err := durable.InitializeServerUnused(config.StoreFile, options); err != nil {
		return errConfig
	}
	return nil
}

func serverKeyStatus(configPath string, output io.Writer) error {
	if output == nil {
		return errConfig
	}
	config, options, err := offlineServerKeyProfile(configPath)
	if err != nil {
		return errConfig
	}
	report, err := durable.InspectServer(config.StoreFile, options)
	if err != nil {
		return errConfig
	}
	return json.NewEncoder(output).Encode(report)
}
