package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	spec "github.com/PHPCraftdream/mcp-jack/spec"
)

// adminCase finds the named case in the admin vectors.
func adminCase(t *testing.T, id string) spec.AdminCase {
	t.Helper()
	vec, err := spec.LoadAdminVectors()
	if err != nil {
		t.Fatalf("spec.LoadAdminVectors: %v", err)
	}
	for _, c := range vec.Cases {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("admin vectors have no case %q", id)
	return spec.AdminCase{}
}

// fixtureHeaderValue returns the named header value of a fixture request.
func fixtureHeaderValue(t *testing.T, req spec.FixtureRequest, name string) string {
	t.Helper()
	for _, h := range req.Headers {
		if h.Name == name {
			return h.Value
		}
	}
	t.Fatalf("fixture request has no %q header", name)
	return ""
}

// fixtureNonce extracts the base64url nonce from a fixture Jack-Auth header.
func fixtureNonce(t *testing.T, headerValue string) string {
	t.Helper()
	auth, err := jack.ParseRequestAuth([]string{headerValue})
	if err != nil {
		t.Fatalf("jack.ParseRequestAuth(%q): %v", headerValue, err)
	}
	return auth.Nonce
}

// fixtureBody decodes the exact request body bytes of a fixture step.
func fixtureBody(t *testing.T, step spec.Step) []byte {
	t.Helper()
	body, err := step.Request.Body()
	if err != nil {
		t.Fatalf("step.Request.Body(): %v", err)
	}
	return body
}

// newFixtureClient builds a Client pinned to srv with the given signer and
// one queued nonce per call (variadic: a test making N calls queues N
// nonces), clocked at fixtureNow.
func newFixtureClient(t *testing.T, srv *testServer, signer Signer, nonceB64 ...string) *Client {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	u.Path = "/mcp"
	c, err := NewClient(Config{
		BaseURL:   u.String(),
		Aud:       fixtureAud,
		Signer:    signer,
		ServerKey: srv.Pub,
		Now:       fixedClock(fixtureNow),
		Window:    30 * time.Second,
		Nonce:     queuedNonce(t, nonceB64...),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// assertFixtureRequest compares the captured request against the fixture:
// header byte-for-byte, method/target exactly, body decoded DeepEqual and
// (softly) byte-identical.
func assertFixtureRequest(t *testing.T, step spec.Step, gotHeader, gotMethod, gotTarget string, gotBody []byte) {
	t.Helper()
	wantHeader := fixtureHeaderValue(t, step.Request, "Jack-Auth")
	if gotHeader != wantHeader {
		t.Errorf("Jack-Auth header = %q, want fixture %q", gotHeader, wantHeader)
	}
	if gotMethod != step.Request.Method {
		t.Errorf("method = %q, want %q", gotMethod, step.Request.Method)
	}
	if gotTarget != step.Request.Target {
		t.Errorf("target = %q, want %q", gotTarget, step.Request.Target)
	}
	wantBody := fixtureBody(t, step)
	var gotAny, wantAny any
	if err := json.Unmarshal(gotBody, &gotAny); err != nil {
		t.Fatalf("captured body does not decode: %v", err)
	}
	if err := json.Unmarshal(wantBody, &wantAny); err != nil {
		t.Fatalf("fixture body does not decode: %v", err)
	}
	if !reflect.DeepEqual(gotAny, wantAny) {
		t.Errorf("decoded body mismatch:\n got  %s\n want %s", gotBody, wantBody)
	}
	if string(gotBody) != string(wantBody) {
		t.Errorf("body bytes differ from fixture bytes:\n got  %q\n want %q", gotBody, wantBody)
	}
}

func TestEnrollMatchesFixture(t *testing.T) {
	c := adminCase(t, "enroll-ok")
	if len(c.Steps) == 0 {
		t.Fatalf("case enroll-ok has no steps")
	}
	step := c.Steps[0]

	srv := newTestServer(t)
	wantStructured := step.Expect.Structured
	var gotHeader, gotMethod, gotTarget string
	var gotBody []byte
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) {
		gotHeader = jack.FormatRequestAuth(auth)
		gotMethod = "POST"
		gotTarget = "/mcp"
		gotBody = body
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(wantStructured))
	}

	headerValue := fixtureHeaderValue(t, step.Request, "Jack-Auth")
	client := newFixtureClient(t, srv, seedSignerByName(t, "newbie"), fixtureNonce(t, headerValue))

	res, err := client.Enroll(context.Background(),
		"NTpoPAFYwVkAdj8kps_x_Q_pgjkaWP-pvdbaV0eQau4", "newbie",
		seedSignerByName(t, "newbie"))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	assertFixtureRequest(t, step, gotHeader, gotMethod, gotTarget, gotBody)

	want := EnrollResult{
		KID:    "imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg",
		Name:   "newbie",
		Kind:   "human",
		Scopes: []string{"read"},
	}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("EnrollResult = %+v, want %+v", res, want)
	}
}

func TestRotateMatchesFixture(t *testing.T) {
	c := adminCase(t, "rotate-ok")
	if len(c.Steps) == 0 {
		t.Fatalf("case rotate-ok has no steps")
	}
	step := c.Steps[0]

	srv := newTestServer(t)
	var gotHeader, gotMethod, gotTarget string
	var gotBody []byte
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) {
		gotHeader = jack.FormatRequestAuth(auth)
		gotMethod = "POST"
		gotTarget = "/mcp"
		gotBody = body
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(step.Expect.Structured))
	}

	headerValue := fixtureHeaderValue(t, step.Request, "Jack-Auth")
	aliceSigner := seedSignerByName(t, "alice")
	newbieSigner := seedSignerByName(t, "newbie")
	client := newFixtureClient(t, srv, aliceSigner, fixtureNonce(t, headerValue))

	res, err := client.RotateKey(context.Background(), newbieSigner)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	assertFixtureRequest(t, step, gotHeader, gotMethod, gotTarget, gotBody)

	var req jsonrpcRequest
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("captured body does not decode as jsonrpc request: %v", err)
	}
	var args map[string]any
	if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
		t.Fatalf("arguments do not decode: %v", err)
	}
	if args["public_key"] != "71JMCNs18t7E5IysFMZEKsnlr9Cw0kahC_h5FkDWrdQ" {
		t.Errorf("arguments[public_key] = %v, want newbie public key", args["public_key"])
	}
	proof, ok := args["proof"].(string)
	if !ok {
		t.Fatalf("arguments[proof] = %v (%T), want a string", args["proof"], args["proof"])
	}

	// Independent re-derivation of the proof from the primitives
	// (spec 03 section 3.1): the client must have signed exactly
	// RotateProofString(aud, oldKid, newKid, fixtureNow).
	proofBytes, err := jack.DecodeBase64URLFixed(proof, 64)
	if err != nil {
		t.Fatalf("DecodeBase64URLFixed(proof): %v", err)
	}
	msg := []byte(jack.RotateProofString(fixtureAud, aliceSigner.KID(), newbieSigner.KID(), fixtureNow))
	if !jack.Verify(newbieSigner.PublicKey(), msg, proofBytes) {
		t.Errorf("rotate proof does not verify under the newbie key over %q", msg)
	}

	if res.KID != "imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg" {
		t.Errorf("KidResult.KID = %q, want imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg", res.KID)
	}
}

func TestWhoAmIDecodesResult(t *testing.T) {
	srv := newTestServer(t)
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, _ []byte) {
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(
			`{"kid":"imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg","name":"newbie","kind":"human","scopes":["read"],"not_before":null,"not_after":null}`)))
	}

	client := newFixtureClient(t, srv, seedSignerByName(t, "newbie"), "assryd677-uYrqD4v-7HYw")
	res, err := client.WhoAmI(context.Background())
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	if res.KID != "imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg" {
		t.Errorf("KID = %q, want imZX4AkHSrS_UT1wZ5oEPklelGqIooKk4TfK3ht5LYg", res.KID)
	}
	if res.Name != "newbie" {
		t.Errorf("Name = %q, want newbie", res.Name)
	}
	if res.Kind != "human" {
		t.Errorf("Kind = %q, want human", res.Kind)
	}
	if !reflect.DeepEqual(res.Scopes, []string{"read"}) {
		t.Errorf("Scopes = %v, want [read]", res.Scopes)
	}
	if res.NotBefore != nil {
		t.Errorf("NotBefore = %v, want nil", res.NotBefore)
	}
	if res.NotAfter != nil {
		t.Errorf("NotAfter = %v, want nil", res.NotAfter)
	}
}

func TestAdminListDecodesWrappers(t *testing.T) {
	srv := newTestServer(t)
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, body []byte) {
		if strings.Contains(string(body), `"jack.admin.user.list"`) {
			srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(
				`{"users":[{"kid":"k1","public_key":"p1","name":"alice","kind":"human","scopes":["read"],"not_before":null,"not_after":1750000000}]}`)))
			return
		}
		srv.writeSignedJSON(w, auth, http.StatusOK, rpcResultBody(json.RawMessage(
			`{"invites":[{"invite_id":"iv1","scopes":["read"],"kind":"human","created_by":"k1","created_at":1767225500,"expires_at":1767228600}]}`)))
	}

	client := newFixtureClient(t, srv, seedSignerByName(t, "alice"), "assryd677-uYrqD4v-7HYw", "assryd677-uYrqD4v-7HYw")

	users, err := client.AdminUserList(context.Background())
	if err != nil {
		t.Fatalf("AdminUserList: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("len(users) = %d, want 1", len(users))
	}
	if users[0].Kind != "human" {
		t.Errorf("users[0].Kind = %q, want human", users[0].Kind)
	}
	if users[0].NotAfter == nil || *users[0].NotAfter != 1750000000 {
		t.Errorf("users[0].NotAfter = %v, want 1750000000", users[0].NotAfter)
	}

	invites, err := client.AdminInviteList(context.Background())
	if err != nil {
		t.Fatalf("AdminInviteList: %v", err)
	}
	if len(invites) != 1 {
		t.Fatalf("len(invites) = %d, want 1", len(invites))
	}
	if invites[0].InviteID != "iv1" {
		t.Errorf("invites[0].InviteID = %q, want iv1", invites[0].InviteID)
	}
	if invites[0].ExpiresAt != 1767228600 {
		t.Errorf("invites[0].ExpiresAt = %d, want 1767228600", invites[0].ExpiresAt)
	}
}

func TestToolCallHTTPError(t *testing.T) {
	srv := newTestServer(t)
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, _ []byte) {
		srv.writeSignedJSON(w, auth, http.StatusForbidden, []byte(`{"error":{"code":"insufficient_scope","message":"no"}}`))
	}

	client := newFixtureClient(t, srv, seedSignerByName(t, "alice"), "assryd677-uYrqD4v-7HYw")
	_, err := client.AdminUserGet(context.Background(), "k1")
	if err == nil {
		t.Fatalf("AdminUserGet err = nil, want *HTTPError")
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("err = %T (%v), want *HTTPError", err, err)
	}
	if httpErr.Status != http.StatusForbidden {
		t.Errorf("Status = %d, want 403", httpErr.Status)
	}
	if httpErr.Code != "insufficient_scope" {
		t.Errorf("Code = %q, want insufficient_scope", httpErr.Code)
	}
}

func TestToolCallToolError(t *testing.T) {
	srv := newTestServer(t)
	srv.Handle = func(w http.ResponseWriter, auth jack.RequestAuth, _ []byte) {
		body := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"boom"}],"isError":true}}`)
		srv.writeSignedJSON(w, auth, http.StatusOK, body)
	}

	client := newFixtureClient(t, srv, seedSignerByName(t, "alice"), "assryd677-uYrqD4v-7HYw")
	_, err := client.WhoAmI(context.Background())
	if err == nil {
		t.Fatalf("WhoAmI err = nil, want *ToolError")
	}
	var toolErr *ToolError
	if !errors.As(err, &toolErr) {
		t.Fatalf("err = %T (%v), want *ToolError", err, err)
	}
	if toolErr.Message != "boom" {
		t.Errorf("Message = %q, want boom", toolErr.Message)
	}
}
