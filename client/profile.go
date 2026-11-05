package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	jack "github.com/PHPCraftdream/mcp-jack"
)

// Profile is a client configuration file holding ONLY public data: it
// deliberately has no private-key field, since private keys must never live
// in config files (spec 01 section 6, README principle 5).
type Profile struct {
	URL string `json:"url"`
	Aud string `json:"aud"`
	// ServerPublicKey is the unpadded base64url of the 32-byte server key.
	ServerPublicKey string `json:"server_public_key"`
	// KID is the client key's identifier (kid), never a private key.
	KID string `json:"kid,omitempty"`
	// Name is the client key's label.
	Name string `json:"name,omitempty"`
}

// LoadProfile reads and validates a profile from r.
func LoadProfile(r io.Reader) (Profile, error) {
	if r == nil {
		return Profile{}, fmt.Errorf("jack client: nil profile reader")
	}
	var p Profile
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Profile{}, fmt.Errorf("jack client: profile: %w", err)
	}
	// Trailing data would silently hide a second document.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Profile{}, fmt.Errorf("jack client: profile: trailing data after JSON object")
	}
	if err := validateProfile(p); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// validateProfile enforces spec 01 sections 3 and 6 field rules.
func validateProfile(p Profile) error {
	u, err := url.Parse(p.URL)
	if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("jack client: profile url must be an absolute http/https URL with a host")
	}
	if p.Aud == "" {
		return fmt.Errorf("jack client: profile aud must be non-empty")
	}
	serverKey, err := jack.DecodeBase64URLFixed(p.ServerPublicKey, 32)
	if err != nil {
		return fmt.Errorf("jack client: profile server_public_key: %w", jack.ErrBadBase64URL)
	}
	if err := jack.ValidatePublicKey(serverKey); err != nil {
		// Local validation never becomes an HTTP response: zero the
		// validator's wire admission status (400) per the Error.HTTPStatus
		// contract, matching VerifyResponse's client-side remap.
		var jErr *jack.Error
		if errors.As(err, &jErr) {
			return &jack.Error{HTTPStatus: 0, Code: jErr.Code, Message: jErr.Message}
		}
		return err
	}
	if p.KID != "" {
		if _, err := jack.DecodeBase64URLFixed(p.KID, 32); err != nil {
			return fmt.Errorf("jack client: profile kid: %w", jack.ErrBadBase64URL)
		}
	}
	return nil
}

// SaveProfile writes p as indented JSON with a trailing newline.
func SaveProfile(w io.Writer, p Profile) error {
	if w == nil {
		return fmt.Errorf("jack client: nil profile writer")
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

// ServerKeyBytes returns the decoded 32-byte server public key.
func (p Profile) ServerKeyBytes() ([]byte, error) {
	return jack.DecodeBase64URLFixed(p.ServerPublicKey, 32)
}

// NewClientFromProfile validates p and builds a Client for it. httpc is the
// optional caller-supplied HTTP client (Config.HTTP); it MUST itself use a
// configured signed *Transport, and nil selects the built-in one. The Rust
// and TS SDKs expose the same constructor (Client::from_profile /
// clientFromProfile).
func NewClientFromProfile(p Profile, signer Signer, httpc *http.Client) (*Client, error) {
	if err := validateProfile(p); err != nil {
		return nil, err
	}
	serverKey, err := p.ServerKeyBytes()
	if err != nil {
		// validateProfile already accepted this key, so this is unreachable
		// in practice; kept so a decode failure can never pass a short key on.
		return nil, fmt.Errorf("jack client: profile server_public_key: %w", err)
	}
	return NewClient(Config{
		BaseURL:   p.URL,
		Aud:       p.Aud,
		Signer:    signer,
		ServerKey: serverKey,
		HTTP:      httpc,
	})
}
