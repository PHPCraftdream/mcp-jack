package main

import (
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/mcp-jack/durable"
)

// Проверяется именно staged package, а не исходный checkout.
func verifyDurableArtifact() error {
	directory, err := os.MkdirTemp("", "jack-consumer-durable-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, "nonces.db")
	opts := durable.Options{DeploymentID: "public-consumer-test", Window: 30}
	if err := durable.InitializeUnused(path, opts); err != nil {
		return err
	}
	owner, err := durable.Open(path, opts)
	if err != nil {
		return err
	}
	defer owner.Close()
	if err := owner.Close(); err != nil {
		return err
	}
	reopened, err := durable.Open(path, opts)
	if err != nil {
		return err
	}
	return reopened.Close()
}
