package userkey_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

// TestZeroAndNilValues defines the safe behavior of zero and nil handles:
// guards return errors, nil, empty slices, empty strings, or false. They
// never panic and never print secret material.
func TestZeroAndNilValues(t *testing.T) {
	msg := []byte("zero and nil behave safely")
	sig := make([]byte, userkey.SignatureSize)

	var zeroClient userkey.ClientKey
	if out, err := zeroClient.Sign(msg); err == nil || out != nil {
		t.Fatalf("zero ClientKey Sign did not fail cleanly")
	}
	if got := zeroClient.PublicKey(); len(got) != 0 {
		t.Fatalf("zero ClientKey PublicKey is not empty")
	}
	if got := zeroClient.KID(); got != "" {
		t.Fatalf("zero ClientKey KID is not empty")
	}
	if rep := fmt.Sprintf("%v", zeroClient); !strings.Contains(rep, "kid:") {
		t.Fatalf("zero ClientKey fmt is not the redacted form")
	}

	var nilClient *userkey.ClientKey
	if out, err := nilClient.Sign(msg); err == nil || out != nil {
		t.Fatalf("nil ClientKey Sign did not fail cleanly")
	}
	if got := nilClient.PublicKey(); got != nil {
		t.Fatalf("nil ClientKey PublicKey is not nil")
	}
	if got := nilClient.KID(); got != "" {
		t.Fatalf("nil ClientKey KID is not empty")
	}

	var zeroIssued userkey.IssuedKey
	if got := zeroIssued.Secret(); got != nil {
		t.Fatalf("zero IssuedKey Secret is not nil")
	}
	if got := zeroIssued.PublicKey(); len(got) != 0 {
		t.Fatalf("zero IssuedKey PublicKey is not empty")
	}
	if got := zeroIssued.KID(); got != "" {
		t.Fatalf("zero IssuedKey KID is not empty")
	}
	var nilIssued *userkey.IssuedKey
	if got := nilIssued.Secret(); got != nil {
		t.Fatalf("nil IssuedKey Secret is not nil")
	}
	if got := nilIssued.PublicKey(); got != nil {
		t.Fatalf("nil IssuedKey PublicKey is not nil")
	}
	if got := nilIssued.KID(); got != "" {
		t.Fatalf("nil IssuedKey KID is not empty")
	}

	var zeroServer userkey.ServerKey
	if zeroServer.Verify(msg, sig) {
		t.Fatalf("zero ServerKey Verify accepted a signature")
	}
	if got := zeroServer.PublicKey(); len(got) != 0 {
		t.Fatalf("zero ServerKey PublicKey is not empty")
	}
	if got := zeroServer.KID(); got != "" {
		t.Fatalf("zero ServerKey KID is not empty")
	}
	var nilServer *userkey.ServerKey
	if nilServer.Verify(msg, sig) {
		t.Fatalf("nil ServerKey Verify accepted a signature")
	}
	if got := nilServer.PublicKey(); got != nil {
		t.Fatalf("nil ServerKey PublicKey is not nil")
	}
	if got := nilServer.KID(); got != "" {
		t.Fatalf("nil ServerKey KID is not empty")
	}
}

// TestRepresentationsNeverLeakSecrets covers fmt and JSON representations for
// both secret-bearing types: direct verbs are fully redacted, and the seed
// never appears through outer structs, slices, maps, pointers, or
// unexported-field walks that skip formatting methods — including the
// unsupported-verb fallback path (%s/%q on nested pointers) that restarts
// rendering at depth zero. The oracle covers hex, uppercase hex, base64, the
// full former private-key decimal list (64 bytes: seed then public), an
// open-ended seed decimal run, and the named private-key sharp prefix. A
// TEST-ONLY positive control recreates the former unsafe representation
// locally and requires each detector to fire on its real output, so the
// oracle cannot be silently vacuous. Failure texts in this test print only
// the label and the leaked-form name; other tests in this package
// deliberately print public values (public keys, signatures, error text)
// and never seed material.
func TestRepresentationsNeverLeakSecrets(t *testing.T) {
	issued, _, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatalf("IssueLocalPair: %v", err)
	}
	seed := issued.Secret()
	clientKey := mustClient(t, seed)
	pub := clientKey.PublicKey()

	forbidden := map[string]string{
		"seed-hex":         hex.EncodeToString(seed),
		"seed-HEX":         strings.ToUpper(hex.EncodeToString(seed)),
		"seed-b64":         jack.EncodeBase64URL(seed),
		"priv-key-dec":     privateKeyDecimal(seed, pub),
		"seed-decimal-run": seedDecimalRun(seed),
		"priv-key-sharp":   privateKeySharpPrefix(seed),
	}
	publicForms := map[string]string{
		"pub-hex": hex.EncodeToString(pub),
		"pub-HEX": strings.ToUpper(hex.EncodeToString(pub)),
		"pub-b64": jack.EncodeBase64URL(pub),
	}

	outer := struct{ key userkey.ClientKey }{*clientKey}
	outerKey := struct{ Key userkey.ClientKey }{*clientKey}
	outerSlice := struct{ keys []userkey.ClientKey }{[]userkey.ClientKey{*clientKey}}
	outerMap := struct{ m map[string]userkey.ClientKey }{map[string]userkey.ClientKey{"k": *clientKey}}
	outerPointer := &struct{ key userkey.ClientKey }{*clientKey}
	issuerPointer := []*userkey.IssuedKey{issued}
	issuerSlice := []userkey.IssuedKey{*issued}
	issuerMap := map[string]userkey.IssuedKey{"h": *issued}
	outerIssued := struct{ handle userkey.IssuedKey }{*issued}
	outerIssuedExported := struct{ Handle userkey.IssuedKey }{*issued}
	outerIssuedPointer := &struct{ handle userkey.IssuedKey }{*issued}

	reps := map[string]string{
		"client %v":                fmt.Sprintf("%v", any(clientKey)),
		"client %+v":               fmt.Sprintf("%+v", any(clientKey)),
		"client %#v":               fmt.Sprintf("%#v", any(clientKey)),
		"client %s":                fmt.Sprintf("%s", any(clientKey)),
		"client %q":                fmt.Sprintf("%q", any(clientKey)),
		"client %x":                fmt.Sprintf("%x", any(clientKey)),
		"client %X":                fmt.Sprintf("%X", any(clientKey)),
		"client %d":                fmt.Sprintf("%d", any(clientKey)),
		"client value %v":          fmt.Sprintf("%v", any(*clientKey)),
		"client value %x":          fmt.Sprintf("%x", any(*clientKey)),
		"client slice %x":          fmt.Sprintf("%x", any([]userkey.ClientKey{*clientKey})),
		"client pointers %x":       fmt.Sprintf("%x", any([]*userkey.ClientKey{clientKey})),
		"client String":            clientKey.String(),
		"issuer %v":                fmt.Sprintf("%v", any(issued)),
		"issuer %#v":               fmt.Sprintf("%#v", any(issued)),
		"issuer %x":                fmt.Sprintf("%x", any(issued)),
		"issuer value %x":          fmt.Sprintf("%x", any(*issued)),
		"issuer String":            issued.String(),
		"issuer outer %s":          fmt.Sprintf("%s", any(outerIssued)),
		"issuer outer %q":          fmt.Sprintf("%q", any(outerIssued)),
		"issuer map field %s":      fmt.Sprintf("%s", any(struct{ m map[string]userkey.IssuedKey }{issuerMap})),
		"outer slice field %s":     fmt.Sprintf("%s", any(outerSlice)),
		"outer map field %s":       fmt.Sprintf("%s", any(outerMap)),
		"issuer pointers %x":       fmt.Sprintf("%x", any(issuerPointer)),
		"issuer slice %x":          fmt.Sprintf("%x", any(issuerSlice)),
		"issuer map field %x":      fmt.Sprintf("%x", any(struct{ m map[string]userkey.IssuedKey }{issuerMap})),
		"issuer outer pointer %x":  fmt.Sprintf("%x", any(outerIssuedPointer)),
		"issuer outer exported %x": fmt.Sprintf("%x", any(outerIssuedExported)),
		"outer unexported %v":      fmt.Sprintf("%v", any(outer)),
		"outer unexported %+v":     fmt.Sprintf("%+v", any(outer)),
		"outer unexported %#v":     fmt.Sprintf("%#v", any(outer)),
		"outer unexported %s":      fmt.Sprintf("%s", any(outer)),
		"outer unexported %q":      fmt.Sprintf("%q", any(outer)),
		"outer unexported %x":      fmt.Sprintf("%x", any(outer)),
		"outer unexported %X":      fmt.Sprintf("%X", any(outer)),
		"outer unexported %d":      fmt.Sprintf("%d", any(outer)),
		"outer pointer %x":         fmt.Sprintf("%x", any(outerPointer)),
		"outer exported %x":        fmt.Sprintf("%x", any(outerKey)),
		"outer slice field %x":     fmt.Sprintf("%x", any(outerSlice)),
		"outer map field %x":       fmt.Sprintf("%x", any(outerMap)),
		"issuer outer %v":          fmt.Sprintf("%v", any(outerIssued)),
		"issuer outer %+v":         fmt.Sprintf("%+v", any(outerIssued)),
		"issuer outer %#v":         fmt.Sprintf("%#v", any(outerIssued)),
		"issuer outer %d":          fmt.Sprintf("%d", any(outerIssued)),
		"issuer outer %x":          fmt.Sprintf("%x", any(outerIssued)),
	}

	for label, rep := range reps {
		for name, secret := range forbidden {
			if strings.Contains(rep, secret) {
				t.Fatalf("%s leaked %s", label, name)
			}
		}
	}

	// TEST-ONLY positive control: locally recreate the former unsafe
	// representation (private-key bytes reachable under an unexported field,
	// rendered through unsupported verbs) and verify the detectors above
	// actually recognize its real output, so the oracle cannot be silently
	// vacuous. Production keeps the closure representation; no sample or
	// secret appears in failure text.
	legacyPriv := ed25519.NewKeyFromSeed(seed)
	legacyPointer := struct{ key *ed25519.PrivateKey }{key: &legacyPriv}
	legacyNamed := struct{ key ed25519.PrivateKey }{legacyPriv}
	legacyPointerSample := fmt.Sprintf("%s", any(legacyPointer))
	legacyNamedSample := fmt.Sprintf("%#v", any(legacyNamed))
	if !strings.Contains(legacyPointerSample, privateKeyDecimal(seed, pub)) {
		t.Fatalf("decimal oracle failed to detect the legacy pointer representation")
	}
	if !strings.Contains(legacyPointerSample, seedDecimalRun(seed)) {
		t.Fatalf("seed-run oracle failed to detect the legacy pointer representation")
	}
	if !strings.Contains(legacyNamedSample, privateKeySharpPrefix(seed)) {
		t.Fatalf("named-slice oracle failed to detect the legacy named representation")
	}

	for _, label := range []string{
		"client %v", "client %+v", "client %#v", "client %s", "client %q",
		"client %x", "client %X", "client %d", "client value %v", "client value %x",
		"client slice %x", "client pointers %x", "client String",
		"issuer %v", "issuer %#v", "issuer %x", "issuer value %x", "issuer String",
	} {
		for name, form := range publicForms {
			if strings.Contains(reps[label], form) {
				t.Fatalf("%s showed %s in a redacted representation", label, name)
			}
		}
	}
	if !strings.Contains(reps["client %v"], clientKey.KID()) {
		t.Fatalf("client redacted representation dropped the public kid")
	}
	if !strings.Contains(reps["issuer %v"], issued.KID()) {
		t.Fatalf("issuer redacted representation dropped the public kid")
	}

	blobClient, err := json.Marshal(clientKey)
	if err != nil {
		t.Fatalf("json.Marshal(ClientKey): %v", err)
	}
	blobClientValue, err := json.Marshal(*clientKey)
	if err != nil {
		t.Fatalf("json.Marshal(ClientKey value): %v", err)
	}
	blobWrapper, err := json.Marshal(struct{ Key *userkey.ClientKey }{clientKey})
	if err != nil {
		t.Fatalf("json.Marshal(wrapper): %v", err)
	}
	blobUnexported, err := json.Marshal(struct{ handle *userkey.IssuedKey }{issued})
	if err != nil {
		t.Fatalf("json.Marshal(unexported wrapper): %v", err)
	}
	blobIssued, err := json.Marshal(issued)
	if err != nil {
		t.Fatalf("json.Marshal(IssuedKey): %v", err)
	}
	server := mustServer(t, pub)
	blobServer, err := json.Marshal(server)
	if err != nil {
		t.Fatalf("json.Marshal(ServerKey): %v", err)
	}

	if string(blobClient) != "{}" {
		t.Fatalf("json.Marshal(ClientKey) is not an empty object")
	}
	if string(blobClientValue) != "{}" {
		t.Fatalf("json.Marshal(ClientKey value) is not an empty object")
	}
	if string(blobWrapper) != `{"Key":{}}` {
		t.Fatalf("json.Marshal of a wrapper is not the empty-field form")
	}
	if string(blobUnexported) != "{}" {
		t.Fatalf("json.Marshal of an unexported-field wrapper is not an empty object")
	}
	if string(blobIssued) != "{}" {
		t.Fatalf("json.Marshal(IssuedKey) is not an empty object")
	}
	if string(blobServer) != "{}" {
		t.Fatalf("json.Marshal(ServerKey) is not an empty object")
	}
	jsonDocs := []string{
		string(blobClient), string(blobClientValue), string(blobWrapper),
		string(blobUnexported), string(blobIssued), string(blobServer),
	}
	for name, secret := range forbidden {
		for _, doc := range jsonDocs {
			if strings.Contains(doc, secret) {
				t.Fatalf("JSON leaked %s", name)
			}
		}
	}

	if _, err := userkey.ImportClientKey(pub[:31]); err == nil {
		t.Fatalf("ImportClientKey(31 bytes) accepted")
	} else if strings.Contains(err.Error(), hex.EncodeToString(pub[:31])) {
		t.Fatalf("client seed error echoes rejected input")
	}
	if _, err := userkey.ImportServerKey(pub[:31]); err == nil {
		t.Fatalf("ImportServerKey(31 bytes) accepted")
	} else if strings.Contains(err.Error(), hex.EncodeToString(pub[:31])) {
		t.Fatalf("server public-key error echoes rejected input")
	}
}
