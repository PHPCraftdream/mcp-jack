// Package gatewayconfig holds the strict gateway configuration schema shared
// by the gateway runtime and the offline nonce operations, so both apply
// identical decoding and validation rules.
package gatewayconfig

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"unicode/utf8"

	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
)

// The durable window is bounded so rate*(2*window+1) does not fill nonce
// capacity before cleanup; the admission budget relies on the relation.
const MaxDurableWindow = 30

type RotationProfilePath string

func (path *RotationProfilePath) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	var value string
	if len(data) == 0 || data[0] != '"' || json.Unmarshal(data, &value) != nil {
		return command.ErrConfig
	}
	*path = RotationProfilePath(value)
	return nil
}

type NativeAdminFlag bool

func (flag *NativeAdminFlag) UnmarshalJSON(data []byte) error {
	switch string(bytes.TrimSpace(data)) {
	case "true":
		*flag = true
	case "false":
		*flag = false
	default:
		return command.ErrConfig
	}
	return nil
}

type DurableConfig struct {
	Path         string `json:"path"`
	DeploymentID string `json:"deployment_id"`
	Window       int64  `json:"window"`
}

// Validate accepts a nil receiver: a nil profile means the volatile in-memory
// nonce store, which is always valid.
func (c *DurableConfig) Validate(maxConcurrent int) error {
	if c == nil {
		return nil
	}
	if !filepath.IsAbs(c.Path) || filepath.Clean(c.Path) != c.Path || !utf8.ValidString(c.DeploymentID) || len(c.DeploymentID) == 0 || len(c.DeploymentID) > 1024 || c.Window < 1 || c.Window > MaxDurableWindow || maxConcurrent < 1 || maxConcurrent > 32 {
		return command.ErrConfig
	}
	return nil
}

type StreamConfig struct {
	FrameMaxBytes        int64 `json:"frame_max_bytes,omitempty"`
	MaxConcurrentStreams int   `json:"max_concurrent_streams,omitempty"`
	MaxStreamDurationMS  int64 `json:"max_stream_duration_ms,omitempty"`
	HeartbeatMS          int64 `json:"heartbeat_ms,omitempty"`
}

type WebhookKey struct {
	KID       string `json:"kid"`
	PublicKey string `json:"public_key"`
}

type Config struct {
	Version               int                 `json:"version"`
	Aud                   string              `json:"aud"`
	ServerSeedFile        string              `json:"server_seed_file"`
	ServerRotationFile    RotationProfilePath `json:"server_rotation_file,omitempty"`
	StateFile             string              `json:"state_file"`
	Listen                string              `json:"listen"`
	UpstreamSocket        string              `json:"upstream_socket"`
	UpstreamURL           string              `json:"upstream_url"`
	CallTimeoutMS         int                 `json:"call_timeout_ms"`
	MaxConcurrent         int                 `json:"max_concurrent"`
	DurableNonces         *DurableConfig      `json:"durable_nonces,omitempty"`
	NativeAdmin           NativeAdminFlag     `json:"native_admin,omitempty"`
	WebhookKeys           []WebhookKey        `json:"webhook_keys,omitempty"`
	WebhookEgressIPRanges []string            `json:"webhook_egress_ip_ranges,omitempty"`
	Profile               string              `json:"profile,omitempty"`
	Streams               *StreamConfig       `json:"streams,omitempty"`
}
