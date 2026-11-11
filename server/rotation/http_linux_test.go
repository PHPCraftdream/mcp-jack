//go:build linux

package rotationserver_test

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/server"
	rotationserver "github.com/PHPCraftdream/mcp-jack/server/rotation"
)

type signingHook struct {
	testSigner
	onSign func()
}
func (key signingHook) Sign(message []byte) ([]byte,error) {
	if key.onSign != nil { key.onSign() }
	return key.testSigner.Sign(message)
}

func TestConcreteProviderThroughMiddlewareFinalBeforeWireAndConsumedReplay(t *testing.T) {
	for _, late := range []bool{false,true} {
		t.Run(map[bool]string{false:"success",true:"late-final"}[late],func(t *testing.T){
			f := setup(t)
			signs := 0
			f.inventory[0].Signer = signingHook{testSigner:f.keys[0],onSign:func(){
				signs++
				if late { f.now.Store(1031) }
			}}
			provider,err := rotationserver.New(f.store,f.inventory)
			if err != nil { t.Fatal(err) }
			caller := makeSigner(34)
			kid := jack.KeyID(caller.PublicKey())
			state := server.NewMemoryState()
			if err := state.Update(func(edit *server.StateEdit) error {
				edit.PutKey(server.RegistryEntry{Kid:kid,PublicKey:jack.EncodeBase64URL(caller.PublicKey()),Name:"caller"})
				return nil
			}); err != nil { t.Fatal(err) }
			nonces := server.NewNonceStore()
			verifier,err := server.NewVerifier(server.Config{Aud:"provider-test",State:state,Nonces:nonces,Now:func()int64{return 1000}})
			if err != nil { t.Fatal(err) }
			applications := 0
			handler,err := server.NewHandler(server.HandlerConfig{Verifier:verifier,ResponseKeys:provider},http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
				applications++
				w.Header().Set("X-Private-App","not-on-refusal")
				_,_ = w.Write([]byte("exact application body"))
			}))
			if err != nil { t.Fatal(err) }
			body := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
			auth := jack.RequestAuth{Kid:kid,TS:1000,Nonce:jack.EncodeBase64URL(bytes.Repeat([]byte{18},16))}
			message := jack.RequestSigningString("POST","/mcp","provider-test",kid,auth.TS,auth.Nonce,body)
			auth.Sig = jack.EncodeBase64URL(ed25519.Sign(caller.key,[]byte(message)))
			request := func() *http.Request {
				r := httptest.NewRequest("POST","/mcp",bytes.NewReader(body))
				r.Header.Set("Jack-Auth",jack.FormatRequestAuth(auth))
				r.Header.Set("Content-Type","application/json")
				return r
			}
			output := httptest.NewRecorder()
			handler.ServeHTTP(output,request())
			if signs != 1 || applications != 1 || nonces.Len() != 1 { t.Fatal("wrong sign/dispatch/reservation count") }
			if late {
				if output.Code != 503 || output.Header().Get("Jack-Auth") != "" || output.Header().Get("X-Private-App") != "" || bytes.Contains(output.Body.Bytes(),[]byte("exact application body")) { t.Fatal("late final leaked signed/application output") }
			} else {
				if output.Code != 200 || output.Body.String() != "exact application body" { t.Fatal("valid response lost") }
				response,err := jack.ParseResponseAuth(output.Header().Values("Jack-Auth"))
				if err != nil || response.Kid != jack.KeyID(f.keys[0].PublicKey()) || response.TS != 1000 { t.Fatal("wrong pinned wire identity/time") }
				signature,err := jack.DecodeBase64URL(response.Sig)
				if err != nil || !jack.Verify(f.keys[0].PublicKey(),[]byte(jack.ResponseSigningString(200,auth.Sig,response.Kid,response.TS,output.Body.Bytes())),signature) { t.Fatal("wire response signature invalid") }
			}
			replay := httptest.NewRecorder()
			handler.ServeHTTP(replay,request())
			if replay.Code != 401 || signs != 1 || applications != 1 { t.Fatal("consumed request redelivered or signed again") }
			if err := f.store.Close(); err != nil { t.Fatal("middleware leaked serving lease",err) }
		})
	}
}
