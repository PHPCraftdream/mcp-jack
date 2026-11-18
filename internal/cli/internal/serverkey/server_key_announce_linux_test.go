//go:build linux

package serverkey_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/durable"
	cli "github.com/PHPCraftdream/mcp-jack/internal/cli"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/clitest"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/serverkey"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/serverkeytest"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

func TestOfflineServerKeyAnnouncementsOverlapAndNeverExposeCustody(t *testing.T) {
	path, config := serverkeytest.SigningProfile(t)
	var diagnostics bytes.Buffer
	if cli.Run(context.Background(), serverkeytest.InitArgs(path, config), cli.IO{Err: &diagnostics}) != 0 {
		t.Fatal("init failed", diagnostics.String())
	}
	var publications []serverkey.ServerKeyPublication
	for _, entry := range config.Signers[1:3] {
		output := &clitest.NonceTestOutput{}
		if cli.Run(context.Background(), serverkeytest.AnnounceArgs(path, entry), cli.IO{Out: output, Err: &diagnostics}) != 0 {
			t.Fatal("offline announce failed", diagnostics.String())
		}
		var publication serverkey.ServerKeyPublication
		if json.Unmarshal(output.Bytes(), &publication) != nil || publication.Record == "" || output.Closed {
			t.Fatal("missing exact public publication or output ownership changed")
		}
		for _, private := range config.Signers {
			if bytes.Contains(output.Bytes(), []byte(private.SeedFile)) || bytes.Contains(output.Bytes(), []byte(private.Reference)) {
				t.Fatal("announcement exposed private custody")
			}
		}
		publications = append(publications, publication)
	}
	_, options, err := serverkey.OfflineServerKeyProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	records, err := rotation.VerifyChain([][]byte{[]byte(publications[0].Record), []byte(publications[1].Record)}, options.Binding, options.Checkpoint, nil)
	if err != nil || records[1].OldKID != config.Signers[1].KID || records[1].PublishedAt >= records[0].ActivatesAt || publications[0].StateRevision != 2 || publications[1].StateRevision != 3 {
		t.Fatal("CLI did not authorize an overlapping adjacent-tail chain", err)
	}
	for index, record := range records {
		if publications[index].Hash != record.Hash || publications[index].Ordinal != record.Ordinal || publications[index].PublishedAt != record.PublishedAt || publications[index].ActivatesAt != record.ActivatesAt {
			t.Fatal("stdout moved fixed publication metadata")
		}
	}
	output := &clitest.NonceTestOutput{}
	if cli.Run(context.Background(), serverkeytest.AnnounceArgs(path, config.Signers[2]), cli.IO{Out: output, Err: &diagnostics}) == 0 || output.Len() != 0 {
		t.Fatal("retained key was published again")
	}
	owner, err := durable.OpenServer(config.StoreFile, options)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if cli.Run(context.Background(), serverkeytest.AnnounceArgs(path, config.Signers[3]), cli.IO{Out: output, Err: &diagnostics}) == 0 || output.Len() != 0 {
		t.Fatal("offline announce bypassed serving owner")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	report, err := durable.InspectServer(config.StoreFile, options)
	if err != nil || report.HeadOrdinal != 2 || report.StateRevision != 3 || report.Dirty {
		t.Fatal("refused publication mutated ring or leaked owner", err)
	}
}

func TestOfflineStatusDoesNotLoadInventoryButAnnounceValidatesSeedsBeforeOpen(t *testing.T) {
	path, config := serverkeytest.SigningProfile(t)
	var diagnostics bytes.Buffer
	if err := os.Remove(config.Signers[3].SeedFile); err != nil {
		t.Fatal(err)
	}
	if cli.Run(context.Background(), serverkeytest.InitArgs(path, config), cli.IO{Err: &diagnostics}) != 0 {
		t.Fatal("offline init read an unavailable signer seed")
	}
	output := &clitest.NonceTestOutput{}
	if cli.Run(context.Background(), []string{"server-key-status", "--config", path}, cli.IO{Out: output, Err: &diagnostics}) != 0 {
		t.Fatal("offline status read an unavailable signer seed")
	}
	before, err := os.ReadFile(config.StoreFile)
	if err != nil {
		t.Fatal(err)
	}
	output = &clitest.NonceTestOutput{}
	if cli.Run(context.Background(), serverkeytest.AnnounceArgs(path, config.Signers[1]), cli.IO{Out: output, Err: &diagnostics}) == 0 || output.Len() != 0 {
		t.Fatal("missing configured signer admitted")
	}
	if err := os.WriteFile(config.Signers[3].SeedFile, bytes.Repeat([]byte{99}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if cli.Run(context.Background(), serverkeytest.AnnounceArgs(path, config.Signers[1]), cli.IO{Out: output, Err: &diagnostics}) == 0 || output.Len() != 0 {
		t.Fatal("seed/KID mismatch admitted")
	}
	after, err := os.ReadFile(config.StoreFile)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("invalid signer inventory opened or changed store")
	}
	keys, cleanup, err := serverkey.LoadServerKeyInventory(config.Signers[:3])
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	for _, key := range keys {
		if !bytes.Equal(key.Signer.(*serverkey.LocalServerKeySigner).Private(), make([]byte, ed25519.PrivateKeySize)) {
			t.Fatal("owned private buffer not cleared")
		}
	}
}

type serverKeyOutputFunc func([]byte) (int, error)

func (write serverKeyOutputFunc) Write(data []byte) (int, error) { return write(data) }

func TestOfflineAnnounceOutputFailureDoesNotRollbackOrRetryCommit(t *testing.T) {
	path, config := serverkeytest.SigningProfile(t)
	if err := serverkey.ServerKeyInitializeUnused(path, config.Endpoint, config.Aud); err != nil {
		t.Fatal(err)
	}
	_, options, err := serverkey.OfflineServerKeyProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	writes := 0
	output := serverKeyOutputFunc(func([]byte) (int, error) {
		writes++
		report, err := durable.InspectServer(config.StoreFile, options)
		if err != nil || report.Dirty || report.StateRevision != 2 || report.HeadOrdinal != 1 {
			t.Error("stdout preceded confirmed publication and healthy owner close", err)
		}
		return 0, errors.New("public output fixture failure")
	})
	entry := config.Signers[1]
	if err := serverkey.ServerKeyAnnounce(path, entry.Reference, entry.KID, output); err == nil || writes != 1 {
		t.Fatal("output failure hidden or retried")
	}
	report, err := durable.InspectServer(config.StoreFile, options)
	if err != nil || report.HeadOrdinal != 1 || report.StateRevision != 2 {
		t.Fatal("output failure rolled back confirmed state")
	}
}
