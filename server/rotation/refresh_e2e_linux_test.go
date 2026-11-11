//go:build linux

package rotationserver_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	rotationclient "github.com/PHPCraftdream/mcp-jack/client/rotation"
	"github.com/PHPCraftdream/mcp-jack/durable"
	"github.com/PHPCraftdream/mcp-jack/rotation"
	"github.com/PHPCraftdream/mcp-jack/server"
	rotationserver "github.com/PHPCraftdream/mcp-jack/server/rotation"
)

type requestSigner struct { testSigner }
func (key requestSigner) KID() string { return jack.KeyID(key.PublicKey()) }

type handlerSlot struct { handler http.Handler }
type capturedRequest struct { body []byte; auth []string; target string }

func integrationDirectory(t *testing.T) string {
	t.Helper()
	directory,err := filepath.EvalSymlinks(t.TempDir())
	if err != nil { t.Fatal(err) }
	if err := os.Chmod(directory,0700); err != nil { t.Fatal(err) }
	return directory
}

func TestNativeRefreshActualHTTPDurableNonceAndClientRestart(t *testing.T) {
	var active atomic.Value
	captured := make(chan capturedRequest,1)
	var requests,nativeCalls,appCalls atomic.Int32
	httpServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		requests.Add(1)
		body,err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil { t.Error(err); http.Error(w,"fixture request unavailable",500); return }
		r.Body = io.NopCloser(bytes.NewReader(body))
		select { case captured<-capturedRequest{body:append([]byte{},body...),auth:append([]string{},r.Header.Values("Jack-Auth")...),target:r.URL.RequestURI()}: default: }
		active.Load().(handlerSlot).handler.ServeHTTP(w,r)
	}))
	defer httpServer.Close()
	endpoint := "http://"+httpServer.Listener.Addr().String()+"/mcp"
	f := setupWithEndpoint(t,endpoint,nil)
	provider,err := rotationserver.New(f.store,f.inventory)
	if err != nil { t.Fatal(err) }
	first,err := provider.Announce("next",jack.KeyID(f.keys[1].PublicKey()))
	if err != nil { t.Fatal(err) }
	second,err := provider.Announce("tail",jack.KeyID(f.keys[2].PublicKey()))
	if err != nil { t.Fatal(err) }
	caller := requestSigner{makeSigner(88)}
	state := server.NewMemoryState()
	if err := state.Update(func(edit *server.StateEdit)error {
		edit.PutKey(server.RegistryEntry{Kid:caller.KID(),PublicKey:jack.EncodeBase64URL(caller.PublicKey()),Name:"durable-refresh-caller"})
		return nil
	}); err != nil { t.Fatal(err) }
	noncePath := filepath.Join(integrationDirectory(t),"nonce.db")
	nonceOptions := durable.Options{DeploymentID:"native-refresh-e2e",Window:30,Now:f.now.Load}
	if err := durable.InitializeUnused(noncePath,nonceOptions); err != nil { t.Fatal(err) }
	nonces,err := durable.Open(noncePath,nonceOptions)
	if err != nil { t.Fatal(err) }
	defer func(){ if nonces != nil { _ = nonces.Close() } }()
	wrap := func(owner *durable.Store)http.Handler {
		verifier,err := server.NewVerifier(server.Config{Aud:"provider-test",State:state,DurableNonces:owner,Now:f.now.Load,ServerKeys:nativeFunc(func(call *server.NativeCall)(server.NativeResult,*jack.Error){ nativeCalls.Add(1); return provider.Call(call) })})
		if err != nil { t.Fatal(err) }
		handler,err := server.NewHandler(server.HandlerConfig{Verifier:verifier,ResponseKeys:provider},http.HandlerFunc(func(w http.ResponseWriter,_ *http.Request){ appCalls.Add(1); _,_ = w.Write([]byte(`{"ok":true}`)) }))
		if err != nil { t.Fatal(err) }
		return handler
	}
	active.Store(handlerSlot{handler:wrap(nonces)})
	httpServer.Start()
	checkpoint := rotation.Checkpoint{Hash:"-",KID:jack.KeyID(f.keys[0].PublicKey())}
	copy(checkpoint.PublicKey[:],f.keys[0].PublicKey())
	trustOptions := durable.TrustOptions{Binding:rotation.Binding{Endpoint:endpoint,Audience:"provider-test"},Window:30,Checkpoint:checkpoint,Now:f.now.Load}
	trustPath := filepath.Join(integrationDirectory(t),"trust.db")
	if err := durable.InitializeTrustUnused(trustPath,trustOptions); err != nil { t.Fatal(err) }
	trust,err := durable.OpenTrust(trustPath,trustOptions)
	if err != nil { t.Fatal(err) }
	defer func(){ if trust != nil { _ = trust.Close() } }()
	sender,err := rotationclient.NewHTTP(trust,caller,5*time.Second)
	if err != nil { t.Fatal(err) }
	ctx,cancel := context.WithTimeout(context.Background(),30*time.Second)
	defer cancel()
	ack,err := sender.Refresh(ctx)
	if err != nil || !ack.Committed || !ack.Complete || ack.Terminal.Ordinal!=2 || ack.Terminal.Hash!=second.Record.Hash || ack.Revision!=2 { t.Fatal("actual native refresh did not ACK exact two-record page",err) }
	var replay capturedRequest
	select { case replay=<-captured: case <-ctx.Done(): t.Fatal("request capture missing") }
	if replay.target!="/mcp" { t.Fatal("wrong captured signed target") }
	duplicate,err := sender.Refresh(ctx)
	if err != nil || duplicate.Committed || duplicate.Revision!=2 || requests.Load()!=2 || nativeCalls.Load()!=2 || appCalls.Load()!=0 { t.Fatal("duplicate refresh mutated trust, retried or forwarded",err) }
	if err := nonces.Close(); err != nil { t.Fatal(err) }
	nonces,err = durable.Open(noncePath,nonceOptions)
	if err != nil { t.Fatal(err) }
	active.Store(handlerSlot{handler:wrap(nonces)})
	request,err := http.NewRequestWithContext(ctx,"POST",endpoint,bytes.NewReader(replay.body))
	if err != nil { t.Fatal(err) }
	request.GetBody = nil
	request.Header.Set("Content-Type","application/json")
	for _,value := range replay.auth { request.Header.Add("Jack-Auth",value) }
	transport := &http.Transport{Proxy:nil,DisableKeepAlives:true}
	defer transport.CloseIdleConnections()
	response,err := (&http.Client{Transport:transport,Timeout:5*time.Second}).Do(request)
	if err != nil { t.Fatal(err) }
	refusal,readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr!=nil || closeErr!=nil || response.StatusCode!=401 || response.Header.Get("Jack-Auth")!="" || !bytes.Contains(refusal,[]byte("replayed_nonce")) || nativeCalls.Load()!=2 || appCalls.Load()!=0 { t.Fatal("exact native request replay admitted after durable nonce restart") }
	if err := trust.Close(); err != nil { t.Fatal(err) }
	trust,err = durable.OpenTrust(trustPath,trustOptions)
	if err != nil { t.Fatal(err) }
	snapshot,_,err := trust.Snapshot()
	if err != nil || snapshot.Revision!=2 || snapshot.Head!=ack.Terminal || len(snapshot.Records)!=2 { t.Fatal("client restart lost confirmed trust") }
	sender,err = rotationclient.NewHTTP(trust,caller,5*time.Second)
	if err != nil { t.Fatal(err) }
	f.now.Store(first.Record.ActivatesAt)
	reply,err := sender.Call(ctx,[]byte(`{"jsonrpc":"2.0","id":9,"method":"ping"}`))
	if err != nil || reply.Status!=200 || string(reply.Body)!=`{"ok":true}` || appCalls.Load()!=1 || nativeCalls.Load()!=2 || requests.Load()!=4 { t.Fatal("restarted client failed new signer or performed hidden refresh",err) }
	final,err := sender.Refresh(ctx)
	if err != nil || final.Committed || final.Revision!=2 || final.Terminal!=ack.Terminal || nativeCalls.Load()!=3 || appCalls.Load()!=1 || requests.Load()!=5 { t.Fatal("explicit post-activation duplicate refresh changed ACK or retried",err) }
}
