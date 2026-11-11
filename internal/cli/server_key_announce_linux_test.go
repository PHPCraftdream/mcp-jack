//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
)

func serverKeySigningProfile(t *testing.T) (string, serverKeyConfig) {
	t.Helper()
	path, config := serverKeyCLIProfile(t)
	for index := 0; index < 4; index++ {
		seed := bytes.Repeat([]byte{byte(44 + index)}, 32)
		private := ed25519.NewKeyFromSeed(seed)
		kid := jack.KeyID(private.Public().(ed25519.PublicKey))
		seedPath := filepath.Join(filepath.Dir(path), "server-"+string(rune('a'+index))+".seed")
		if err := os.WriteFile(seedPath, seed, 0600); err != nil {
			t.Fatal(err)
		}
		reference := "pending/" + kid
		if index == 0 {
			reference = config.AnchorReference
		}
		config.Signers = append(config.Signers, serverKeySignerConfig{Reference: reference, KID: kid, SeedFile: seedPath})
	}
	return saveJSON(t, filepath.Dir(path), "signing-profile.json", config), config
}

func announceArgs(path string, entry serverKeySignerConfig) []string {
	return []string{"server-key-announce", "--config", path, "--reference", entry.Reference, "--kid", entry.KID}
}

func TestOfflineServerKeyAnnouncementsOverlapAndNeverExposeCustody(t *testing.T) {
	path, config := serverKeySigningProfile(t)
	var diagnostics bytes.Buffer
	if Run(context.Background(), serverKeyInitArgs(path, config), IO{Err: &diagnostics}) != 0 {
		t.Fatal("init failed", diagnostics.String())
	}
	var publications []serverKeyPublication
	for _, entry := range config.Signers[1:3] {
		output := &nonceTestOutput{}
		if Run(context.Background(), announceArgs(path, entry), IO{Out: output, Err: &diagnostics}) != 0 {
			t.Fatal("offline announce failed", diagnostics.String())
		}
		var publication serverKeyPublication
		if json.Unmarshal(output.Bytes(), &publication) != nil || publication.Record == "" || output.closed {
			t.Fatal("missing exact public publication or output ownership changed")
		}
		for _, private := range config.Signers {
			if bytes.Contains(output.Bytes(), []byte(private.SeedFile)) || bytes.Contains(output.Bytes(), []byte(private.Reference)) {
				t.Fatal("announcement exposed private custody")
			}
		}
		publications = append(publications, publication)
	}
	_, options, err := offlineServerKeyProfile(path)
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
	output := &nonceTestOutput{}
	if Run(context.Background(), announceArgs(path, config.Signers[2]), IO{Out: output, Err: &diagnostics}) == 0 || output.Len() != 0 {
		t.Fatal("retained key was published again")
	}
	owner, err := durable.OpenServer(config.StoreFile, options)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if Run(context.Background(), announceArgs(path, config.Signers[3]), IO{Out: output, Err: &diagnostics}) == 0 || output.Len() != 0 {
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
	path, config := serverKeySigningProfile(t)
	var diagnostics bytes.Buffer
	if err := os.Remove(config.Signers[3].SeedFile); err != nil {
		t.Fatal(err)
	}
	if Run(context.Background(), serverKeyInitArgs(path, config), IO{Err: &diagnostics}) != 0 {
		t.Fatal("offline init read an unavailable signer seed")
	}
	output := &nonceTestOutput{}
	if Run(context.Background(), []string{"server-key-status", "--config", path}, IO{Out: output, Err: &diagnostics}) != 0 {
		t.Fatal("offline status read an unavailable signer seed")
	}
	before, err := os.ReadFile(config.StoreFile)
	if err != nil {
		t.Fatal(err)
	}
	output = &nonceTestOutput{}
	if Run(context.Background(), announceArgs(path, config.Signers[1]), IO{Out: output, Err: &diagnostics}) == 0 || output.Len() != 0 {
		t.Fatal("missing configured signer admitted")
	}
	if err := os.WriteFile(config.Signers[3].SeedFile, bytes.Repeat([]byte{99}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if Run(context.Background(), announceArgs(path, config.Signers[1]), IO{Out: output, Err: &diagnostics}) == 0 || output.Len() != 0 {
		t.Fatal("seed/KID mismatch admitted")
	}
	after, err := os.ReadFile(config.StoreFile)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("invalid signer inventory opened or changed store")
	}
	keys, cleanup, err := loadServerKeyInventory(config.Signers[:3])
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	for _, key := range keys {
		if !bytes.Equal(key.Signer.(*localServerKeySigner).private, make([]byte, ed25519.PrivateKeySize)) {
			t.Fatal("owned private buffer not cleared")
		}
	}
}

type serverKeyOutputFunc func([]byte) (int, error)

func (write serverKeyOutputFunc) Write(data []byte) (int, error) { return write(data) }

func TestOfflineAnnounceOutputFailureDoesNotRollbackOrRetryCommit(t *testing.T) {
	path, config := serverKeySigningProfile(t)
	if err := serverKeyInitializeUnused(path, config.Endpoint, config.Aud); err != nil {
		t.Fatal(err)
	}
	_, options, err := offlineServerKeyProfile(path)
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
	if err := serverKeyAnnounce(path, entry.Reference, entry.KID, output); err == nil || writes != 1 {
		t.Fatal("output failure hidden or retried")
	}
	report, err := durable.InspectServer(config.StoreFile, options)
	if err != nil || report.HeadOrdinal != 1 || report.StateRevision != 2 {
		t.Fatal("output failure rolled back confirmed state")
	}
}

func TestProcessOfflineServerKeyAnnouncement(t *testing.T) {
	path, config := serverKeySigningProfile(t)
	invoke := func(success bool, args ...string) []byte {
		t.Helper()
		process, in, out, diagnostics := childArgs(t, args...)
		if err := in.Close(); err != nil {
			t.Fatal(err)
		}
		reply, err := io.ReadAll(io.LimitReader(out, maxBody+1))
		if err != nil || len(reply) > maxBody {
			t.Fatal("child output unreadable or unbounded")
		}
		waitErr := process.Wait()
		if success && waitErr != nil || !success && waitErr == nil {
			t.Fatal("unexpected offline publication process outcome", diagnostics.String())
		}
		return reply
	}
	invoke(true, serverKeyInitArgs(path, config)...)
	for _, entry := range config.Signers[1:3] {
		var result serverKeyPublication
		if json.Unmarshal(invoke(true, announceArgs(path, entry)...), &result) != nil || result.Record == "" {
			t.Fatal("shipping announce did not expose confirmed public record")
		}
	}
	invoke(false, announceArgs(path, config.Signers[2])...)
	var report durable.ServerInspection
	if json.Unmarshal(invoke(true, "server-key-status", "--config", path), &report) != nil || report.HeadOrdinal != 2 || report.StateRevision != 3 || report.Dirty {
		t.Fatal("shipping announcement lifecycle status invalid")
	}
}
