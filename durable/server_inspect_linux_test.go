//go:build linux

package durable

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func inspectionOptions(t *testing.T, options ServerOptions) ServerOptions {
	t.Helper()
	options.Now = func()int64 { t.Error("offline inspection invoked clock"); return -1 }
	return options
}

func TestServerInspectionExclusivePublicOnlyAndNoMutation(t *testing.T) {
	store,path,options,_,signer := testServerOwner(t)
	offline := inspectionOptions(t,options)
	if report,err := InspectServer(path,offline); err == nil || report != (ServerInspection{}) { t.Fatal("offline inspection bypassed serving owner") }
	previous,clock,err := store.Snapshot()
	if err != nil { t.Fatal(err) }
	desired := extendServer(t,previous,clock,signer)
	if err := store.CompareAndSwap(previous,desired,clock); err != nil { t.Fatal(err) }
	if err := store.Close(); err != nil { t.Fatal(err) }
	before,err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	report,err := InspectServer(path,offline)
	if err != nil || report.Dirty || report.Unsafe || report.Fenced || report.HighWater!=1000 || report.Window!=30 || report.ClockRevision!=clock.Revision || report.StateRevision!=2 || report.HeadOrdinal!=1 || report.HeadHash!=desired.Public.Head.Hash || report.RetainedKeys!=2 || !report.PublicationPresent || report.StoreID=="" { t.Fatal("inspection did not describe committed public metadata",err) }
	encoded,err := json.Marshal(report)
	if err != nil || bytes.Contains(encoded,[]byte("protected/")) || bytes.Contains(encoded,[]byte("reference")) || bytes.Contains(encoded,[]byte("private")) || bytes.Contains(encoded,[]byte(path)) { t.Fatal("inspection disclosed protected locator/path") }
	after,err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before,after) { t.Fatal("inspection rewrote existing store") }
	repeated,err := InspectServer(path,offline)
	if err != nil || !reflect.DeepEqual(report,repeated) { t.Fatal("inspection advanced owner/clock or changed report",err) }
	reopened,err := OpenServer(path,options)
	if err != nil { t.Fatal("healthy inspected store could not reopen",err) }
	if err := reopened.Close(); err != nil { t.Fatal(err) }
}

func TestServerInspectionPreservesDirtyAndUnsafeRecoveryGates(t *testing.T) {
	for _,unsafe := range []bool{false,true} {
		t.Run(map[bool]string{false:"dirty-unknown",true:"unsafe"}[unsafe],func(t *testing.T){
			store,path,options,now,_ := testServerOwner(t)
			if unsafe {
				now.Store(999)
				if _,err := store.AdvanceAndCheck(); err == nil { t.Fatal("fixture did not latch rollback") }
			} else { store.Fence() }
			if err := store.Close(); err == nil { t.Fatal("fixture closed uncertain owner healthy") }
			now.Store(2000)
			before,err := os.ReadFile(path)
			if err != nil { t.Fatal(err) }
			report,err := InspectServer(path,inspectionOptions(t,options))
			if err != nil || !report.Dirty || report.Unsafe!=unsafe || report.HighWater!=1000 || report.StateRevision!=1 || report.PublicationPresent || report.RetainedKeys!=1 { t.Fatal("inspection repaired/rejected diagnostic recovery flags",err) }
			after,err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before,after) { t.Fatal("inspection changed recovery evidence") }
			if owner,err := OpenServer(path,options); err == nil || owner!=nil { t.Fatal("inspection authorized recovery or catch-up cleared fence") }
		})
	}
}

func TestServerInspectionRejectsLostIntentAndNeverCreatesMissingStore(t *testing.T) {
	store,path,options,_,signer := testServerOwner(t)
	previous,clock,err := store.Snapshot()
	if err != nil { t.Fatal(err) }
	if err := store.CompareAndSwap(previous,extendServer(t,previous,clock,signer),clock); err != nil { t.Fatal(err) }
	if err := store.Close(); err != nil { t.Fatal(err) }
	db,_,err := openTrustDB(path,false)
	if err != nil { t.Fatal(err) }
	if err := db.Update(func(tx *bolt.Tx)error { return tx.Bucket(serverBucket).Put(serverIntentKey,[]byte{}) }); err != nil { t.Fatal(err) }
	if err := db.Close(); err != nil { t.Fatal(err) }
	if report,err := InspectServer(path,inspectionOptions(t,options)); err == nil || report!=(ServerInspection{}) { t.Fatal("incomplete publication journal exposed diagnostic success") }
	missing := filepath.Join(privateTestDirectory(t),"missing-server.db")
	if report,err := InspectServer(missing,inspectionOptions(t,options)); err == nil || report!=(ServerInspection{}) { t.Fatal("missing store inspected successfully") }
	if _,err := os.Lstat(missing); !os.IsNotExist(err) { t.Fatal("inspection created missing store") }
}
