//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/durable"
)

func serverKeyCLIProfile(t *testing.T) (string,serverKeyConfig) {
	t.Helper()
	directory := privateDir(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{44},32))
	public := key.Public().(ed25519.PublicKey)
	config := serverKeyConfig{Version:1,StoreFile:filepath.Join(directory,"ring.db"),Endpoint:"https://server-key.example.invalid/mcp",Aud:"public-server-key-cli",Window:30,AnchorKID:jack.KeyID(public),AnchorPublicKey:jack.EncodeBase64URL(public),AnchorReference:"protected-reference-not-a-seed-file"}
	return saveJSON(t,directory,"server-key.json",config),config
}

func serverKeyInitArgs(path string,config serverKeyConfig) []string {
	return []string{"server-key-init-unused","--config",path,"--confirm-unused-endpoint",config.Endpoint,"--confirm-unused-aud",config.Aud}
}

func TestOfflineServerKeyInitAndStatusConfirmBindingNeverReplace(t *testing.T) {
	path,config := serverKeyCLIProfile(t)
	var diagnostics bytes.Buffer
	for _,args := range [][]string{
		{"server-key-init-unused","--config",path},
		{"server-key-init-unused","--config",path,"--confirm-unused-endpoint",config.Endpoint},
		{"server-key-init-unused","--config",path,"--confirm-unused-endpoint","wrong","--confirm-unused-aud",config.Aud},
		{"server-key-init-unused","--config",path,"--confirm-unused-endpoint",config.Endpoint,"--confirm-unused-aud","wrong"},
		{"server-key-status","--config",path},
	} {
		if Run(context.Background(),args,IO{Out:&nonceTestOutput{},Err:&diagnostics})==0 { t.Fatal("missing confirmation/store accepted") }
		if _,err := os.Lstat(config.StoreFile); !os.IsNotExist(err) { t.Fatal("failed offline command touched missing store") }
	}
	if Run(context.Background(),serverKeyInitArgs(path,config),IO{Err:&diagnostics})!=0 { t.Fatal("explicit unused binding init failed",diagnostics.String()) }
	before,err := os.ReadFile(config.StoreFile)
	if err != nil { t.Fatal(err) }
	if Run(context.Background(),serverKeyInitArgs(path,config),IO{Err:&diagnostics})==0 { t.Fatal("existing server store replaced") }
	output := &nonceTestOutput{}
	if Run(context.Background(),[]string{"server-key-status","--config",path},IO{Out:output,Err:&diagnostics})!=0 { t.Fatal("offline server status failed",diagnostics.String()) }
	var report durable.ServerInspection
	if json.Unmarshal(output.Bytes(),&report)!=nil || report.Dirty || report.Unsafe || report.Fenced || report.HeadOrdinal!=0 || report.HeadHash!="-" || report.StateRevision!=1 || report.RetainedKeys!=1 || report.StoreID=="" { t.Fatal("incorrect public status") }
	if output.closed || bytes.Contains(output.Bytes(),[]byte(config.AnchorReference)) || bytes.Contains(output.Bytes(),[]byte(config.StoreFile)) || bytes.Contains(diagnostics.Bytes(),[]byte(config.StoreFile)) || bytes.Contains(diagnostics.Bytes(),[]byte(config.Aud)) { t.Fatal("output ownership or private diagnostic leak") }
	after,err := os.ReadFile(config.StoreFile)
	if err != nil || !bytes.Equal(before,after) { t.Fatal("repeat init/status rewrote store") }
}

func TestOfflineServerKeyStatusDoesNotClearDirtyOrOpenServing(t *testing.T) {
	path,config := serverKeyCLIProfile(t)
	var diagnostics bytes.Buffer
	if Run(context.Background(),serverKeyInitArgs(path,config),IO{Err:&diagnostics})!=0 { t.Fatal("fixture init failed") }
	_,options,err := offlineServerKeyProfile(path)
	if err != nil { t.Fatal(err) }
	owner,err := durable.OpenServer(config.StoreFile,options)
	if err != nil { t.Fatal(err) }
	if output := (&nonceTestOutput{}); Run(context.Background(),[]string{"server-key-status","--config",path},IO{Out:output,Err:&diagnostics})==0 || output.Len()!=0 { t.Fatal("status bypassed lifetime owner") }
	owner.Fence()
	if owner.Close()==nil { t.Fatal("fixture failed to preserve dirty epoch") }
	before,err := os.ReadFile(config.StoreFile)
	if err != nil { t.Fatal(err) }
	output := &nonceTestOutput{}
	if Run(context.Background(),[]string{"server-key-status","--config",path},IO{Out:output,Err:&diagnostics})!=0 { t.Fatal("dirty status unreadable") }
	var report durable.ServerInspection
	if json.Unmarshal(output.Bytes(),&report)!=nil || !report.Dirty { t.Fatal("CLI repaired/hidden dirty flag") }
	after,err := os.ReadFile(config.StoreFile)
	if err != nil || !bytes.Equal(before,after) { t.Fatal("dirty status changed evidence") }
	if reopened,err := durable.OpenServer(config.StoreFile,options); err == nil || reopened!=nil { t.Fatal("status authorized serving recovery") }
}

func TestProcessOfflineServerKeyCommands(t *testing.T) {
	path,config := serverKeyCLIProfile(t)
	invoke := func(success bool,args ...string) []byte {
		t.Helper()
		process,in,out,diagnostics := childArgs(t,args...)
		if err := in.Close(); err != nil { t.Fatal(err) }
		reply,err := io.ReadAll(io.LimitReader(out,maxBody+1))
		if err != nil || len(reply)>maxBody { t.Fatal("child output unreadable or unbounded") }
		waitErr := process.Wait()
		if success && waitErr!=nil || !success && waitErr==nil { t.Fatal("unexpected offline CLI process outcome",diagnostics.String()) }
		return reply
	}
	if reply := invoke(true,serverKeyInitArgs(path,config)...); len(reply)!=0 { t.Fatal("init child disclosed output") }
	invoke(false,serverKeyInitArgs(path,config)...)
	var report durable.ServerInspection
	if json.Unmarshal(invoke(true,"server-key-status","--config",path),&report)!=nil || report.Dirty || report.HeadHash!="-" || report.StateRevision!=1 { t.Fatal("shipping process status invalid") }
}

func TestOfflineServerKeyProfileValidationBeforeStoreCreation(t *testing.T) {
	path,config := serverKeyCLIProfile(t)
	var diagnostics bytes.Buffer
	for index,mutate := range []func(*serverKeyConfig){
		func(c *serverKeyConfig){ c.Version=2 },
		func(c *serverKeyConfig){ c.Window=0 },
		func(c *serverKeyConfig){ c.Window=121 },
		func(c *serverKeyConfig){ c.AnchorKID="wrong" },
		func(c *serverKeyConfig){ c.AnchorPublicKey+="=" },
		func(c *serverKeyConfig){ c.AnchorReference="" },
		func(c *serverKeyConfig){ c.Endpoint="relative/path" },
		func(c *serverKeyConfig){ c.Endpoint="https://user:secret@example.invalid/mcp" },
		func(c *serverKeyConfig){ c.Endpoint="https://example.invalid/mcp#fragment" },
		func(c *serverKeyConfig){ c.Aud="" },
		func(c *serverKeyConfig){ c.StoreFile="" },
	} {
		bad := config
		mutate(&bad)
		badPath := saveJSON(t,filepath.Dir(path),"bad-"+string(rune('a'+index))+".json",bad)
		if Run(context.Background(),serverKeyInitArgs(badPath,bad),IO{Err:&diagnostics})==0 { t.Fatal("invalid protected profile accepted") }
		if _,err := os.Lstat(config.StoreFile); !os.IsNotExist(err) { t.Fatal("invalid profile touched store") }
	}
	encoded,err := json.Marshal(config)
	if err != nil { t.Fatal(err) }
	for index,extra := range []string{`"version":1,"version":1`,`"version":1,"private_key":"forbidden"`} {
		changed := bytes.Replace(encoded,[]byte(`"version":1`),[]byte(extra),1)
		if bytes.Equal(changed,encoded) { t.Fatal("negative config token missing") }
		badPath := filepath.Join(filepath.Dir(path),"ambiguous-"+string(rune('a'+index))+".json")
		if err := os.WriteFile(badPath,changed,0600); err != nil { t.Fatal(err) }
		if Run(context.Background(),serverKeyInitArgs(badPath,config),IO{Err:&diagnostics})==0 { t.Fatal("duplicate/unknown private config field accepted") }
	}
	if serverKeyStatus(path,nil)==nil { t.Fatal("missing output accepted") }
	if bytes.Contains(diagnostics.Bytes(),[]byte("secret")) || bytes.Contains(diagnostics.Bytes(),[]byte(config.StoreFile)) { t.Fatal("profile refusal leaked supplied values") }
}
