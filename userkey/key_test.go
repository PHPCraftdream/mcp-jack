package userkey_test

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

// TestKnownKeysJSONVectors covers public imports for both roles against the
// keys.json vectors: the client role imports the private seed, the server
// role imports and validates only the public bytes, and both derive the same
// public key and KID.
func TestKnownKeysJSONVectors(t *testing.T) {
	for _, v := range keysJSONVectors {
		v := v
		t.Run(v.name, func(t *testing.T) {
			seed := mustHex(t, v.seedHex)
			wantPub, err := jack.DecodeBase64URLFixed(v.pubB64, userkey.PublicKeySize)
			if err != nil {
				t.Fatalf("DecodeBase64URLFixed(public): %v", err)
			}

			clientKey := mustClient(t, seed)
			if got := clientKey.PublicKey(); !bytes.Equal(got, wantPub) {
				t.Fatalf("client public = %x, want %x", got, wantPub)
			}
			if got := clientKey.KID(); got != v.kid {
				t.Fatalf("client kid = %q, want %q", got, v.kid)
			}

			server := mustServer(t, wantPub)
			if got := server.PublicKey(); !bytes.Equal(got, wantPub) {
				t.Fatalf("server public = %x, want %x", got, wantPub)
			}
			if got := server.KID(); got != v.kid {
				t.Fatalf("server kid = %q, want %q", got, v.kid)
			}

			if err := jack.ValidatePublicKey(wantPub); err != nil {
				t.Fatalf("ValidatePublicKey: %v", err)
			}
		})
	}
}

// TestRFC8032Vectors signs and verifies with the RFC oracle: the client role
// reproduces the reference signatures, the server role verifies them with
// jack.Verify and rejects a tampered message.
func TestRFC8032Vectors(t *testing.T) {
	for _, v := range rfc8032Vectors {
		v := v
		t.Run(v.name, func(t *testing.T) {
			seed := mustHex(t, v.seedHex)
			wantPub := mustHex(t, v.pubHex)
			msg := mustHex(t, v.msgHex)
			wantSig := mustHex(t, v.sigHex)

			clientKey := mustClient(t, seed)
			if got := clientKey.PublicKey(); !bytes.Equal(got, wantPub) {
				t.Fatalf("public = %x, want %x", got, wantPub)
			}
			sig, err := clientKey.Sign(msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !bytes.Equal(sig, wantSig) {
				t.Fatalf("signature = %x, want %x", sig, wantSig)
			}

			server := mustServer(t, wantPub)
			if !server.Verify(msg, sig) {
				t.Fatalf("server Verify rejected the RFC signature")
			}
			tampered := append([]byte(nil), msg...)
			if len(tampered) == 0 {
				tampered = []byte{'x'}
			} else {
				tampered[len(tampered)-1] ^= 0x01
			}
			if server.Verify(tampered, sig) {
				t.Fatalf("server Verify accepted a tampered message")
			}
		})
	}
}

// TestInteropRequestSignature pins the full request-signing path: rebuilding
// alice's signing string through the existing jack primitive reproduces the
// pinned bytes, the client signature matches the pinned interop signature,
// and the server role verifies it.
func TestInteropRequestSignature(t *testing.T) {
	v := keysJSONVectors[0]
	clientKey := mustClient(t, mustHex(t, v.seedHex))

	signingString := jack.RequestSigningString("POST", "/mcp", "https://svc.example.test", clientKey.KID(), 1767225600, "9t3KTc6TGArpVjaFOCLCPw", nil)
	if signingString != aliceSigningString {
		t.Fatalf("rebuilt signing string differs from the pinned interop string")
	}

	sig, err := clientKey.Sign([]byte(signingString))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	wantSig, err := jack.DecodeBase64URLFixed(aliceExpectedSigB64, userkey.SignatureSize)
	if err != nil {
		t.Fatalf("DecodeBase64URLFixed(sig): %v", err)
	}
	if !bytes.Equal(sig, wantSig) {
		t.Fatalf("signature differs from the pinned interop signature")
	}

	server := mustServer(t, clientKey.PublicKey())
	if !server.Verify([]byte(signingString), sig) {
		t.Fatalf("server Verify rejected the pinned interop signature")
	}
}

// TestIssueHandoffImportRoundTrip covers the handoff path with two
// independent imports of the same issued seed: immutable expected identity
// and signature, mutation isolation of the already-imported keys, and a
// post-mutation import that must diverge.
func TestIssueHandoffImportRoundTrip(t *testing.T) {
	issued, server, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatalf("IssueLocalPair: %v", err)
	}
	seed := issued.Secret()
	wantPub := append([]byte(nil), issued.PublicKey()...)
	wantKid := issued.KID()
	msg := []byte("two independent imports of one handoff")

	first := mustClient(t, seed)
	second := mustClient(t, seed)
	if first.KID() != wantKid || second.KID() != wantKid {
		t.Fatalf("independent imports diverge on kid")
	}
	if got := first.PublicKey(); !bytes.Equal(got, wantPub) {
		t.Fatalf("first import diverges on public key")
	}
	if got := second.PublicKey(); !bytes.Equal(got, wantPub) {
		t.Fatalf("second import diverges on public key")
	}

	sig1, err := first.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	wantSig := append([]byte(nil), sig1...) // immutable expected signature
	sig2, err := second.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(sig2, wantSig) {
		t.Fatalf("independent imports disagree on the deterministic signature")
	}
	if !server.Verify(msg, wantSig) {
		t.Fatalf("server Verify rejected the handoff signature")
	}

	// Mutation isolation: mutating the handed-off bytes cannot change the
	// already-imported keys, and a later import must diverge.
	seed[0] ^= 0xff // never restored
	if got := first.PublicKey(); !bytes.Equal(got, wantPub) {
		t.Fatalf("first import changed after handoff mutation")
	}
	if got := second.PublicKey(); !bytes.Equal(got, wantPub) {
		t.Fatalf("second import changed after handoff mutation")
	}
	again, err := first.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(again, wantSig) {
		t.Fatalf("first import signature changed after handoff mutation")
	}
	divergent := mustClient(t, seed)
	if divergent.KID() == wantKid {
		t.Fatalf("post-mutation import matched the pre-mutation identity")
	}
}

// TestRoleRepresentationsNonconvertible pins the conversion boundary between
// the two private-bearing roles: the underlying struct types must not be
// convertible in any direction, for pointers or values, so ordinary Go code
// cannot reinterpret a client key as an issuance handle or vice versa.
func TestRoleRepresentationsNonconvertible(t *testing.T) {
	clientPointer := reflect.TypeOf((*userkey.ClientKey)(nil))
	clientValue := reflect.TypeOf(userkey.ClientKey{})
	issuedPointer := reflect.TypeOf((*userkey.IssuedKey)(nil))
	issuedValue := reflect.TypeOf(userkey.IssuedKey{})

	for _, probe := range []struct {
		from, to reflect.Type
	}{
		{clientPointer, issuedPointer},
		{clientValue, issuedValue},
		{issuedPointer, clientPointer},
		{issuedValue, clientValue},
	} {
		if probe.from.ConvertibleTo(probe.to) {
			t.Fatalf("%s is convertible to %s: the role boundary must reject ordinary conversions", probe.from, probe.to)
		}
	}
}

// TestGenerateClientKeyRoleAndOracle covers generation through the public
// role boundary: distinct generated keys, admission-clean public keys,
// correct KID derivation, server-side verification, tamper rejection, and
// the signer bridge on a generated key.
func TestGenerateClientKeyRoleAndOracle(t *testing.T) {
	a, err := userkey.GenerateClientKey()
	if err != nil {
		t.Fatalf("GenerateClientKey: %v", err)
	}
	b, err := userkey.GenerateClientKey()
	if err != nil {
		t.Fatalf("GenerateClientKey: %v", err)
	}
	if a.KID() == b.KID() {
		t.Fatalf("two generated keys share a kid")
	}

	pub := a.PublicKey()
	if a.KID() != jack.KeyID(pub) {
		t.Fatalf("generated kid does not match jack.KeyID of the public key")
	}
	if err := jack.ValidatePublicKey(pub); err != nil {
		t.Fatalf("generated public key rejected by admission: %v", err)
	}
	server := mustServer(t, pub)

	msg := []byte("generated client key role oracle")
	sig, err := a.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !server.Verify(msg, sig) {
		t.Fatalf("server Verify rejected the generated key signature")
	}
	tampered := append([]byte(nil), msg...)
	tampered[len(tampered)-1] ^= 0x01
	if server.Verify(tampered, sig) {
		t.Fatalf("server Verify accepted a tampered message")
	}

	if _, ok := reflect.TypeOf((*userkey.ClientKey)(nil)).MethodByName("Secret"); ok {
		t.Fatalf("*userkey.ClientKey must not expose Secret")
	}
	var signer client.Signer = a
	if signer.KID() != a.KID() || !bytes.Equal(signer.PublicKey(), pub) {
		t.Fatalf("generated key does not satisfy the signer bridge")
	}
}

// TestIssueLocalPairRoles covers the role boundary of local issuance: both
// halves share the public identity, the client half signs and the server half
// verifies, and neither ServerKey nor IssuedKey exposes a signing or private
// surface. ClientKey itself must expose no private accessor.
func TestIssueLocalPairRoles(t *testing.T) {
	issued, server, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatalf("IssueLocalPair: %v", err)
	}
	if issued.KID() != server.KID() {
		t.Fatalf("pair kids differ: %q vs %q", issued.KID(), server.KID())
	}
	if !bytes.Equal(issued.PublicKey(), server.PublicKey()) {
		t.Fatalf("pair public keys differ")
	}

	msg := []byte("issued locally, delivered out of band")
	clientKey := mustClient(t, issued.Secret())
	sig, err := clientKey.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !server.Verify(msg, sig) {
		t.Fatalf("server Verify rejected the handoff signature")
	}
	if server.Verify([]byte("another message"), sig) {
		t.Fatalf("server Verify accepted another message")
	}

	issued2, server2, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatalf("IssueLocalPair: %v", err)
	}
	if issued.KID() == issued2.KID() || server.KID() == server2.KID() {
		t.Fatalf("two issued pairs share a kid")
	}

	for _, probe := range []struct {
		typ  reflect.Type
		name string
	}{
		{reflect.TypeOf((*userkey.ClientKey)(nil)), "Secret"},
		{reflect.TypeOf((*userkey.IssuedKey)(nil)), "Sign"},
		{reflect.TypeOf((*userkey.ServerKey)(nil)), "Sign"},
		{reflect.TypeOf((*userkey.ServerKey)(nil)), "Secret"},
	} {
		if _, ok := probe.typ.MethodByName(probe.name); ok {
			t.Fatalf("%s must not expose %q", probe.typ, probe.name)
		}
	}
	if _, ok := any(server).(userkey.Signer); ok {
		t.Fatalf("ServerKey must not satisfy userkey.Signer")
	}
	if _, ok := any(server).(client.Signer); ok {
		t.Fatalf("ServerKey must not satisfy client.Signer")
	}
	if _, ok := any(issued).(userkey.Signer); ok {
		t.Fatalf("IssuedKey must not satisfy userkey.Signer")
	}
	if _, ok := any(issued).(client.Signer); ok {
		t.Fatalf("IssuedKey must not satisfy client.Signer")
	}
}

// TestSignerBridgeBothRoles uses one issued key through both roles: the
// issuer hands off private bytes, a real ordinary client imports them and
// signs via the existing client.Signer interface, and the server role
// verifies from imported public bytes only.
func TestSignerBridgeBothRoles(t *testing.T) {
	issued, _, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatalf("IssueLocalPair: %v", err)
	}
	clientKey := mustClient(t, issued.Secret())

	var signer client.Signer = clientKey
	msg := []byte("bridged signing")
	viaBridge, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("client.Signer Sign: %v", err)
	}
	direct, err := clientKey.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(viaBridge, direct) {
		t.Fatalf("bridge signature differs from direct signature")
	}
	if !bytes.Equal(signer.PublicKey(), clientKey.PublicKey()) {
		t.Fatalf("bridge public key differs")
	}
	if signer.KID() != clientKey.KID() {
		t.Fatalf("bridge kid differs")
	}

	server := mustServer(t, signer.PublicKey())
	if !server.Verify(msg, viaBridge) {
		t.Fatalf("server Verify rejected the bridged signature")
	}
}

// TestImportRejectsWrongLengths covers wrong seed and public-key lengths:
// both importers reject them, return no key, state the required size, and
// never echo the input bytes in the error text.
func TestImportRejectsWrongLengths(t *testing.T) {
	for _, n := range []int{0, 1, 31, 33, 64} {
		input := make([]byte, n)
		for i := range input {
			input[i] = byte(i + 1)
		}

		clientKey, err := userkey.ImportClientKey(input)
		if err == nil {
			t.Fatalf("ImportClientKey(%d bytes): accepted", n)
		}
		if clientKey != nil {
			t.Fatalf("ImportClientKey(%d bytes): returned a key", n)
		}
		if n > 0 && strings.Contains(err.Error(), hex.EncodeToString(input)) {
			t.Fatalf("ImportClientKey(%d bytes): error echoes rejected input", n)
		}
		if !strings.Contains(err.Error(), "32") {
			t.Fatalf("ImportClientKey(%d bytes): error does not state 32", n)
		}

		server, err := userkey.ImportServerKey(input)
		if err == nil {
			t.Fatalf("ImportServerKey(%d bytes): accepted", n)
		}
		if server != nil {
			t.Fatalf("ImportServerKey(%d bytes): returned a key", n)
		}
		if n > 0 && strings.Contains(err.Error(), hex.EncodeToString(input)) {
			t.Fatalf("ImportServerKey(%d bytes): error echoes rejected input", n)
		}
		if !strings.Contains(err.Error(), "32") {
			t.Fatalf("ImportServerKey(%d bytes): error does not state 32", n)
		}
	}

	if c, err := userkey.ImportClientKey(nil); err == nil || c != nil {
		t.Fatalf("ImportClientKey(nil) did not fail cleanly")
	}
	if s, err := userkey.ImportServerKey(nil); err == nil || s != nil {
		t.Fatalf("ImportServerKey(nil) did not fail cleanly")
	}
}

// TestImportServerKeyRejectsInvalidKeys covers server-role admission: the
// importer itself rejects the independent key-vectors.json negative controls
// (identity, small-order, mixed-order, non-canonical, off-curve, wrong
// length) without echoing key material.
func TestImportServerKeyRejectsInvalidKeys(t *testing.T) {
	for _, v := range invalidKeyVectors {
		pub := mustHex(t, v.pubHex)
		server, err := userkey.ImportServerKey(pub)
		if err == nil {
			t.Fatalf("ImportServerKey(%s): accepted an invalid public key", v.name)
		}
		if server != nil {
			t.Fatalf("ImportServerKey(%s): returned a key", v.name)
		}
		if strings.Contains(err.Error(), v.pubHex) || strings.Contains(err.Error(), strings.ToUpper(v.pubHex)) {
			t.Fatalf("ImportServerKey(%s): error echoes rejected key material", v.name)
		}
	}
}

// TestImportCopiesCallerInput covers caller mutation of input: both
// importers copy, so mutating the caller's slices cannot change the stored
// keys.
func TestImportCopiesCallerInput(t *testing.T) {
	v := keysJSONVectors[1] // root

	seed := mustHex(t, v.seedHex)
	clientKey := mustClient(t, seed)
	wantPub := append([]byte(nil), clientKey.PublicKey()...)
	wantKid := clientKey.KID()
	msg := []byte("input mutation must not matter")
	wantSig, err := clientKey.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	seed[0] ^= 0xff
	seed[31] ^= 0xff
	if got := clientKey.PublicKey(); !bytes.Equal(got, wantPub) {
		t.Fatalf("client public changed after input mutation")
	}
	if clientKey.KID() != wantKid {
		t.Fatalf("client kid changed after input mutation")
	}
	if got, _ := clientKey.Sign(msg); !bytes.Equal(got, wantSig) {
		t.Fatalf("client signature changed after input mutation")
	}

	pub, err := jack.DecodeBase64URLFixed(v.pubB64, userkey.PublicKeySize)
	if err != nil {
		t.Fatalf("DecodeBase64URLFixed: %v", err)
	}
	pristine := append([]byte(nil), pub...)
	server := mustServer(t, pub)
	wantServerKid := server.KID()

	pub[0] ^= 0xff
	pub[31] ^= 0xff
	if got := server.PublicKey(); !bytes.Equal(got, pristine) {
		t.Fatalf("server public changed after input mutation")
	}
	if server.KID() != wantServerKid {
		t.Fatalf("server kid changed after input mutation")
	}
}

// TestExportedPublicBytesAreIndependent covers caller mutation of exported
// public bytes for the client and server roles: PublicKey hands out fresh
// copies, so mutating them cannot change the stored keys.
func TestExportedPublicBytesAreIndependent(t *testing.T) {
	clientKey := mustClient(t, mustHex(t, keysJSONVectors[0].seedHex))

	p1 := clientKey.PublicKey()
	p2 := clientKey.PublicKey()
	if !bytes.Equal(p1, p2) {
		t.Fatalf("two PublicKey calls differ")
	}
	p1[0] ^= 0xff
	if got := clientKey.PublicKey(); !bytes.Equal(got, p2) {
		t.Fatalf("mutating a returned public copy changed the stored key")
	}
	if clientKey.KID() != jack.KeyID(p2) {
		t.Fatalf("kid changed after mutating a returned public copy")
	}

	server := mustServer(t, p2)
	sp := server.PublicKey()
	sp[0] ^= 0xff
	if got := server.PublicKey(); !bytes.Equal(got, p2) {
		t.Fatalf("mutating a server public copy changed the stored key")
	}
	if server.KID() != jack.KeyID(p2) {
		t.Fatalf("server kid changed after mutating a returned public copy")
	}
}

// TestIssuedExportedBytesAreIndependent covers mutation of exported issuer
// public bytes: PublicKey must hand out fresh copies, and public-copy
// mutation must not touch the private seed export.
func TestIssuedExportedBytesAreIndependent(t *testing.T) {
	issued, _, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatalf("IssueLocalPair: %v", err)
	}
	seedSnapshot := append([]byte(nil), issued.Secret()...) // immutable oracle

	p1 := issued.PublicKey()
	p2 := issued.PublicKey()
	if !bytes.Equal(p1, p2) {
		t.Fatalf("two issued PublicKey calls differ")
	}
	p1[0] ^= 0xff // never restored
	if got := issued.PublicKey(); !bytes.Equal(got, p2) {
		t.Fatalf("mutating an exported issuer public copy changed the stored key")
	}
	if issued.KID() != jack.KeyID(p2) {
		t.Fatalf("issued kid changed after mutating an exported public copy")
	}
	if got := issued.Secret(); !bytes.Equal(got, seedSnapshot) {
		t.Fatalf("public-copy mutation affected the issued seed export")
	}
}

// TestHandoffSecretIsIndependent covers the issuance handle's private export:
// every Secret call returns a fresh copy, compared after mutation against an
// immutable pre-mutation snapshot that is never restored to mask corruption.
// The stored identity and the signing outcome must be unaffected.
func TestHandoffSecretIsIndependent(t *testing.T) {
	issued, server, err := userkey.IssueLocalPair()
	if err != nil {
		t.Fatalf("IssueLocalPair: %v", err)
	}
	first := issued.Secret()
	if len(first) != userkey.SeedSize {
		t.Fatalf("Secret length = %d, want %d", len(first), userkey.SeedSize)
	}
	// Immutable oracle snapshot, taken before any mutation and never mutated.
	expect := append([]byte(nil), first...)
	wantPub := append([]byte(nil), issued.PublicKey()...)
	wantKid := issued.KID()
	msg := []byte("handoff secret copies are independent")

	s1 := issued.Secret()
	if !bytes.Equal(s1, expect) {
		t.Fatalf("a second Secret export differed before any mutation")
	}
	s1[0] ^= 0xff // mutate; never restored

	s2 := issued.Secret()
	if !bytes.Equal(s2, expect) {
		t.Fatalf("stored seed changed after mutating an exported copy")
	}
	if issued.KID() != wantKid || server.KID() != wantKid {
		t.Fatalf("kids changed after mutating an exported copy")
	}
	if got := issued.PublicKey(); !bytes.Equal(got, wantPub) {
		t.Fatalf("issued public changed after mutating an exported copy")
	}

	clientKey := mustClient(t, s2)
	if !bytes.Equal(clientKey.PublicKey(), wantPub) {
		t.Fatalf("client key from the second export diverged from the issued identity")
	}
	sig, err := clientKey.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !server.Verify(msg, sig) {
		t.Fatalf("server Verify rejected the client signature after export-copy mutation")
	}
}
