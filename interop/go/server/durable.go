package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/server"
)

// durableOptions holds the parsed durable-nonce-store flags. durableDir == ""
// means the volatile nonce store is used and all durable paths are skipped.
type durableOptions struct {
	dir    string
	window int64
	init   bool
}

// parseDurableFlags registers and validates the durable flags. The window must
// be an integer in 1..120, matching durable.normalizedOptions.
func parseDurableFlags() *durableOptions {
	dir := flag.String("durable-dir", "", "durable nonce store directory (enables durable admission)")
	window := flag.String("durable-window", "30", "durable nonce window in seconds (1..120)")
	init := flag.Bool("durable-init", false, "initialize the durable store and exit")
	flag.Parse()

	opts := &durableOptions{dir: *dir, init: *init}
	if *window != "" {
		w, err := strconv.ParseInt(*window, 10, 64)
		if err != nil || w < 1 || w > 120 {
			fail("--durable-window must be an integer in 1..120")
		}
		opts.window = w
	}
	return opts
}

// storePath returns the durable store file path for this deployment.
func (o *durableOptions) storePath() string {
	return filepath.Join(o.dir, "nonces")
}

// durableInit performs the explicit out-of-band initialization and prints the
// one-line init result to stdout. Never replaces an existing store.
func durableInit(o *durableOptions, aud string) {
	if err := durable.InitializeUnused(o.storePath(), durable.Options{DeploymentID: aud, Window: o.window}); err != nil {
		fail("durable-init: %v", err)
	}
	b, err := json.Marshal(struct {
		DurableInitialized bool `json:"durable_initialized"`
	}{true})
	if err != nil {
		fail("durable-init: %v", err)
	}
	fmt.Println(string(b))
	os.Exit(0)
}

// openDurableStore opens the existing store for serving. Now is left nil so
// durable defaults it to the wall clock. ErrRecoveryRequired and any other
// error are startup failures before the ready line.
func openDurableStore(o *durableOptions, aud string) *durable.Store {
	store, err := durable.Open(o.storePath(), durable.Options{DeploymentID: aud, Window: o.window})
	if err != nil {
		fail("durable store: %v", err)
	}
	return store
}

// durableVerifierConfig fills cfg for durable serving: the durable store is
// selected explicitly and NewVerifier rejects both store kinds at once.
func durableVerifierConfig(o *durableOptions, aud string, state *server.FileState) (*durable.Store, server.Config) {
	store := openDurableStore(o, aud)
	return store, server.Config{
		Aud:           aud,
		State:         state,
		DurableNonces: store,
		Native:        server.NewNativeTools(server.NativeOptions{}),
		Window:        o.window,
	}
}
