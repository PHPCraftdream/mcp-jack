package main

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

type knownServerKey struct {
	kid        string
	public     []byte
	activation int64
}

type knownServerKeys []knownServerKey

func (keys *knownServerKeys) String() string { return fmt.Sprint(len(*keys)) }

func (keys *knownServerKeys) Set(value string) error {
	fields := make(map[string]string, 3)
	for _, part := range strings.Split(value, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 || (kv[0] != "kid" && kv[0] != "public" && kv[0] != "activation") {
			return fmt.Errorf("invalid known server key field %q", part)
		}
		if _, exists := fields[kv[0]]; exists {
			return fmt.Errorf("duplicate known server key field %q", kv[0])
		}
		fields[kv[0]] = kv[1]
	}
	for _, name := range []string{"kid", "public", "activation"} {
		if fields[name] == "" {
			return fmt.Errorf("missing known server key field %q", name)
		}
	}
	public, err := base64.RawURLEncoding.DecodeString(fields["public"])
	if err != nil || len(public) != 32 {
		return fmt.Errorf("invalid known server public key")
	}
	activation, err := strconv.ParseInt(fields["activation"], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid known server key activation: %w", err)
	}
	*keys = append(*keys, knownServerKey{kid: fields["kid"], public: public, activation: activation})
	return nil
}
