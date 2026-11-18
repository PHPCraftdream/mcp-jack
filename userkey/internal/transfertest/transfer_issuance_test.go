package userkey_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

// TestIssuanceDeterminism covers row 3: fixed config plus an injected fixed
// 32-byte random source (RFC 8032 TEST 1 seed) yields credential bytes equal
// to our independently composed canonical credential, twice-identical
// issuance, a correct PublicIdentity, and a surface that exposes no signing
// or private accessor.
func TestIssuanceDeterminism(t *testing.T) {
	expected := ukSVCTuple(ukSVCURL)
	seed := ukHex(t, ukRFC1SeedHex)

	inner := ukComposePrivate(ukRFC1DB64, jack.KeyID(ukHex(t, ukRFC1PubHex)), ukRFC1XB64)
	wantCred := ukComposeCredSvc(ukSVCURL, string(inner), ukSVCURL)

	issued, err := userkey.IssueUserKey(expected, bytes.NewReader(seed))
	ukExpectOK(t, err, "IssueUserKey")
	cred := issued.CredentialBytes()
	if !bytes.Equal(cred, wantCred) {
		t.Fatalf("issued credential differs from the composed canonical credential")
	}

	issued2, err := userkey.IssueUserKey(expected, bytes.NewReader(seed))
	ukExpectOK(t, err, "second IssueUserKey")
	if !bytes.Equal(issued2.CredentialBytes(), cred) {
		t.Fatalf("two issuances with the same random differ")
	}

	wantPub := ukHex(t, ukRFC1PubHex)
	if got := issued.PublicIdentity.PublicKey(); !bytes.Equal(got, wantPub) {
		t.Fatalf("PublicIdentity public differs from the derived key")
	}
	if got := issued.PublicIdentity.KID(); got != jack.KeyID(wantPub) {
		t.Fatalf("PublicIdentity kid mismatch")
	}

	// Surface probes: the issuance handle is not a signer and exposes no
	// secret accessor; ordinary records expose no credential accessor.
	issuanceType := reflect.TypeOf((*userkey.UserKeyIssuance)(nil))
	for _, name := range []string{"Sign", "Secret"} {
		if _, ok := issuanceType.MethodByName(name); ok {
			t.Fatalf("*userkey.UserKeyIssuance must not expose %q", name)
		}
	}
	for _, typ := range []reflect.Type{
		reflect.TypeOf((*userkey.ClientKey)(nil)),
		reflect.TypeOf((*userkey.ServerKey)(nil)),
		reflect.TypeOf((*userkey.IssuedKey)(nil)),
	} {
		if _, ok := typ.MethodByName("CredentialBytes"); ok {
			t.Fatalf("%s must not expose CredentialBytes", typ)
		}
	}
	if _, ok := any(issued).(userkey.Signer); ok {
		t.Fatalf("*userkey.UserKeyIssuance must not satisfy userkey.Signer")
	}
	if _, ok := any(issued).(client.Signer); ok {
		t.Fatalf("*userkey.UserKeyIssuance must not satisfy client.Signer")
	}

	encoded, err := json.Marshal(issued)
	ukExpectOK(t, err, "json.Marshal(issuance)")
	if string(encoded) != "{}" {
		t.Fatalf("issuance JSON is not the empty redacted object")
	}
}

// TestIssuanceRedaction covers rows 3/7/9: every fmt verb on the value, the
// pointer, and nested containers, plus json.Marshal, contains no credential
// or inner-seed material in hex, base64url, base64, or decimal form. The
// positive controls prove the detectors are non-vacuous by requiring them to
// fire on legacy byte-bearing output.
func TestIssuanceRedaction(t *testing.T) {
	expected := ukSVCTuple(ukSVCURL)
	seed := ukHex(t, ukRFC1SeedHex)
	issued, err := userkey.IssueUserKey(expected, bytes.NewReader(seed))
	ukExpectOK(t, err, "IssueUserKey")
	cred := issued.CredentialBytes()

	credHex := hex.EncodeToString(cred)
	credHexUpper := strings.ToUpper(credHex)
	credB64U := jack.EncodeBase64URL(cred)
	credB64STD := base64.StdEncoding.EncodeToString(cred)
	credDec := ukDecimalRun(cred)
	seedHex := hex.EncodeToString(seed)
	seedHexUpper := strings.ToUpper(seedHex)
	seedB64U := jack.EncodeBase64URL(seed)
	seedB64STD := base64.StdEncoding.EncodeToString(seed)
	seedDec := ukDecimalRun(seed)

	detectors := []string{credHex, credHexUpper, credB64U, credB64STD, credDec, seedHex, seedHexUpper, seedB64U, seedB64STD, seedDec}

	value := *issued
	unexportedValue := struct{ h userkey.UserKeyIssuance }{*issued}
	unexportedPointer := struct{ h *userkey.UserKeyIssuance }{issued}
	unexportedContainer := struct {
		handles map[string]userkey.UserKeyIssuance
	}{map[string]userkey.UserKeyIssuance{"h": *issued}}
	unexportedSlice := struct{ list []userkey.UserKeyIssuance }{[]userkey.UserKeyIssuance{*issued}}
	targets := []any{
		issued, value,
		map[string]any{"handle": issued},
		[]any{issued, issued},
		struct{ H *userkey.UserKeyIssuance }{issued},
		unexportedValue,
		unexportedPointer,
		unexportedContainer,
		unexportedSlice,
	}
	for _, target := range targets {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
			out := fmt.Sprintf(verb, target)
			for _, d := range detectors {
				if strings.Contains(out, d) {
					t.Fatalf("redacted output leaked material (verb %s)", verb)
				}
			}
		}
	}
	encoded, err := json.Marshal(issued)
	ukExpectOK(t, err, "json.Marshal")
	for _, d := range detectors {
		if strings.Contains(string(encoded), d) {
			t.Fatalf("issuance JSON leaked material")
		}
	}

	// Positive controls on legacy byte-bearing values: the same detectors
	// must fire, proving they are full-length and non-vacuous.
	type legacyCred struct {
		C []byte
	}
	type legacySeed struct {
		S []byte
	}
	lc := legacyCred{cred}
	ls := legacySeed{seed}
	// Named byte-array variant (row 7 positive control class).
	var credFixed [4096]byte
	copy(credFixed[:], cred)

	controls := []struct {
		name string
		out  string
		det  string
	}{
		{"legacy cred %x hex", fmt.Sprintf("%x", lc), credHex},
		{"legacy cred %X hex", fmt.Sprintf("%X", lc), credHexUpper},
		{"legacy cred %v decimal", fmt.Sprintf("%v", lc), credDec},
		{"legacy cred %+v decimal", fmt.Sprintf("%+v", lc), credDec},
		{"legacy cred %d decimal", fmt.Sprintf("%d", lc), credDec},
		{"legacy cred array %x hex", fmt.Sprintf("%x", &credFixed), credHex},
		{"legacy cred array %v decimal", fmt.Sprintf("%v", &credFixed), credDec},
		{"legacy seed %x hex", fmt.Sprintf("%x", ls), seedHex},
		{"legacy seed %X hex", fmt.Sprintf("%X", ls), seedHexUpper},
		{"legacy seed %v decimal", fmt.Sprintf("%v", ls), seedDec},
	}
	credJSON, err := json.Marshal(lc)
	ukExpectOK(t, err, "json.Marshal(legacy cred)")
	controls = append(controls, struct {
		name, out, det string
	}{"legacy cred json base64", string(credJSON), credB64STD})
	seedJSON, err := json.Marshal(ls)
	ukExpectOK(t, err, "json.Marshal(legacy seed)")
	controls = append(controls, struct {
		name, out, det string
	}{"legacy seed json base64", string(seedJSON), seedB64STD})

	hiddenCred := struct{ c []byte }{cred}
	hiddenSeed := struct{ s []byte }{seed}
	controls = append(controls,
		struct{ name, out, det string }{"hidden cred %v decimal", fmt.Sprintf("%v", any(hiddenCred)), credDec},
		struct{ name, out, det string }{"hidden cred %d decimal", fmt.Sprintf("%d", any(hiddenCred)), credDec},
		struct{ name, out, det string }{"hidden cred %x hex", fmt.Sprintf("%x", any(hiddenCred)), credHex},
		struct{ name, out, det string }{"hidden cred %X hex", fmt.Sprintf("%X", any(hiddenCred)), credHexUpper},
		struct{ name, out, det string }{"hidden cred %s raw", fmt.Sprintf("%s", any(hiddenCred)), seedB64U},
		struct{ name, out, det string }{"hidden cred %q raw", fmt.Sprintf("%q", any(hiddenCred)), seedB64U},
		struct{ name, out, det string }{"hidden seed %x hex", fmt.Sprintf("%x", any(hiddenSeed)), seedHex},
		struct{ name, out, det string }{"hidden seed %X hex", fmt.Sprintf("%X", any(hiddenSeed)), seedHexUpper},
		struct{ name, out, det string }{"hidden seed %v decimal", fmt.Sprintf("%v", any(hiddenSeed)), seedDec},
		struct{ name, out, det string }{"hidden seed %d decimal", fmt.Sprintf("%d", any(hiddenSeed)), seedDec},
	)

	for _, c := range controls {
		if !strings.Contains(c.out, c.det) {
			t.Fatalf("positive control did not fire: %s", c.name)
		}
	}
}

// TestCredentialBytesFreshness covers rows 3/14: the credential accessor
// returns equal independent copies with no consumption state; the credential
// imports on its own sink with the trusted tuple BEFORE any export mutation,
// and the retained signer plus public identity are unaffected afterwards.
func TestCredentialBytesFreshness(t *testing.T) {
	expected := ukSVCTuple(ukSVCURL)
	seed := ukHex(t, ukRFC1SeedHex)
	issued, err := userkey.IssueUserKey(expected, bytes.NewReader(seed))
	ukExpectOK(t, err, "IssueUserKey")

	// Immutable oracle snapshot of the credential bytes; never mutated.
	snapshot := append([]byte(nil), issued.CredentialBytes()...)
	wantPub := append([]byte(nil), issued.PublicIdentity.PublicKey()...)
	msg := []byte("freshness probe")

	// The FULL credential imports through the credential sink with the
	// independently trusted tuple; the signer is retained before any export
	// copy is mutated.
	original, err := userkey.ImportCredential(append([]byte(nil), snapshot...), expected)
	ukExpectOK(t, err, "ImportCredential(original credential)")
	if original.Signer.KID() != jack.KeyID(wantPub) {
		t.Fatalf("imported credential client kid differs from the issuance identity")
	}
	originalSig, err := original.Signer.Sign(msg)
	ukExpectOK(t, err, "Sign(retained signer)")

	// Fresh equal copies with no consumption state.
	first := issued.CredentialBytes()
	wantCred := issued.CredentialBytes()
	if !bytes.Equal(first, wantCred) {
		t.Fatalf("two accessor calls disagree")
	}
	if !bytes.Equal(first, snapshot) {
		t.Fatalf("accessor copy diverged from the snapshot")
	}

	// Mutate the ACTUAL returned copy completely; never restored.
	for i := range first {
		first[i] ^= 0xFF
	}
	if !bytes.Equal(wantCred, snapshot) {
		t.Fatal("mutating one credential export changed a previously returned copy")
	}
	second := issued.CredentialBytes()
	if !bytes.Equal(second, snapshot) {
		t.Fatalf("second copy changed after mutating the first")
	}
	third := issued.CredentialBytes()
	if !bytes.Equal(third, snapshot) {
		t.Fatalf("third copy differs from the original")
	}

	// The retained signer and public identity are unaffected (row 3, section 9).
	if got := issued.PublicIdentity.PublicKey(); !bytes.Equal(got, wantPub) {
		t.Fatalf("PublicIdentity changed after copy mutation")
	}
	if original.Signer.KID() != jack.KeyID(wantPub) {
		t.Fatalf("retained signer identity changed after export mutation")
	}
	againSig, err := original.Signer.Sign(msg)
	ukExpectOK(t, err, "Sign(retained signer after mutation)")
	if !bytes.Equal(againSig, originalSig) {
		t.Fatalf("retained signer lost determinism after export mutation")
	}
}

// TestIssuanceHandoff covers row 4: the issued credential imports on the
// client role with the matching tuple and yields a working signer whose
// signatures verify under the ServerKey built from the issuance identity.
func TestIssuanceHandoff(t *testing.T) {
	expected := ukSVCTuple(ukSVCURL)
	seed := ukHex(t, ukCarolSeedHex)
	issued, err := userkey.IssueUserKey(expected, bytes.NewReader(seed))
	ukExpectOK(t, err, "IssueUserKey")

	imp, err := userkey.ImportCredential(issued.CredentialBytes(), expected)
	ukExpectOK(t, err, "ImportCredential")
	msg := []byte("handoff signature")
	sig, err := imp.Signer.Sign(msg)
	ukExpectOK(t, err, "Sign")
	server, err := userkey.ImportServerKey(issued.PublicIdentity.PublicKey())
	ukExpectOK(t, err, "ImportServerKey")
	if !server.Verify(msg, sig) {
		t.Fatalf("server Verify rejected the handoff signature")
	}
	if imp.Signer.KID() != server.KID() {
		t.Fatalf("handoff kids differ")
	}
}

// TestPublicSinkNotPrivate covers row 5: a public-only identity refuses the
// secret operation with not_private and verifies honestly.
func TestPublicSinkNotPrivate(t *testing.T) {
	ident, err := userkey.ImportClientPublicEnvelope([]byte(ukPubAlice))
	ukExpectOK(t, err, "ImportClientPublicEnvelope")

	msg := []byte("verify-only probe")
	_, err = ident.Sign(msg)
	ukExpectClass(t, err, userkey.ClassNotPrivate)

	ck, err := userkey.ImportClientKey(ukHex(t, ukAliceSeedHex))
	ukExpectOK(t, err, "ImportClientKey")
	sig, err := ck.Sign(msg)
	ukExpectOK(t, err, "Sign")
	if !ident.Verify(msg, sig) {
		t.Fatalf("public identity rejected a valid signature")
	}
	if ident.Verify([]byte("another message"), sig) {
		t.Fatalf("public identity accepted a signature of another message")
	}
}

// TestWrongSinks covers row 11: cross-kind imports are refused with the
// security class winning on the server public sink.
func TestWrongSinks(t *testing.T) {
	credAlice := []byte(ukCredAlice)

	// Client public sink with private material.
	_, err := userkey.ImportClientPublicEnvelope([]byte(ukPrivAlice))
	ukExpectClass(t, err, userkey.ClassWrongEnvelopeType)

	// Credential document into both envelope sinks.
	_, err = userkey.ImportClientPublicEnvelope(credAlice)
	ukExpectClass(t, err, userkey.ClassWrongEnvelopeType)
	_, err = userkey.ImportClientPrivateEnvelope(credAlice)
	ukExpectClass(t, err, userkey.ClassWrongEnvelopeType)

	// Server public sink with private or credential material: the security
	// class private_material_rejected wins at step 5.
	_, err = userkey.ImportServerPublicEnvelope([]byte(ukPrivAlice))
	ukExpectClass(t, err, userkey.ClassPrivateMaterialRejected)
	_, err = userkey.ImportServerPublicEnvelope(credAlice)
	ukExpectClass(t, err, userkey.ClassPrivateMaterialRejected)

	// Credential sink with a public inner envelope.
	_, err = userkey.ImportCredential([]byte(ukNegCredClientKeyPublic), ukSVCTuple(ukSVCURL))
	ukExpectClass(t, err, userkey.ClassWrongEnvelopeType)
}

// TestTrustPolicy covers row 12: exact-tuple acceptance for every aud
// positive (decoded rune equality), decoded url/aud mismatches, differing
// expected identities, and missing/zero/incomplete/invalid tuples failing
// server_identity_mismatch AFTER structural acceptance.
func TestTrustPolicy(t *testing.T) {
	audPositives := []struct {
		id  string
		aud string
	}{
		{"cred-alice", ukSVCURL},
		{"cred-bob", ukSVCURL},
		{"cred-aud-html-sensitive", ukAudHTML},
		{"cred-aud-codepoints", ukAudCodepoints},
		{"cred-aud-control", ukAudControl},
		{"cred-aud-separators", ukAudSeparators},
		{"cred-aud-replacement-char", ukAudReplacement},
	}
	for _, ap := range audPositives {
		ap := ap
		t.Run("valid-tuple/"+ap.id, func(t *testing.T) {
			data := ukComposeCredSvc(ap.aud, ukPrivAlice, ukSVCURL)
			ukExpectOK(t, userkey.ValidateCredential(data, ukSVCTuple(ap.aud)), "ValidateCredential")
			imp, err := userkey.ImportCredential(data, ukSVCTuple(ap.aud))
			ukExpectOK(t, err, "ImportCredential")
			if imp.Signer == nil {
				t.Fatalf("successful import returned no signer")
			}
		})
	}

	credAlice := []byte(ukCredAlice)

	t.Run("decoded-url-mismatch", func(t *testing.T) {
		tuple := ukSVCTuple(ukSVCURL)
		tuple.URL = "https://other.example.test"
		_, err := userkey.ImportCredential(credAlice, tuple)
		ukExpectClass(t, err, userkey.ClassServerIdentityMismatch)
	})
	t.Run("decoded-aud-mismatch", func(t *testing.T) {
		tuple := ukSVCTuple("other-audience")
		_, err := userkey.ImportCredential(credAlice, tuple)
		ukExpectClass(t, err, userkey.ClassServerIdentityMismatch)
	})
	t.Run("differing-expected-identity", func(t *testing.T) {
		tuple := userkey.ExpectedIdentity{
			URL:             ukSVCURL,
			Aud:             ukSVCURL,
			ServerPublicKey: ukB64(t, ukBobPubB64),
			ServerKID:       ukBobKid,
		}
		_, err := userkey.ImportCredential(credAlice, tuple)
		ukExpectClass(t, err, userkey.ClassServerIdentityMismatch)
	})
	for _, name := range []string{"zero", "missing-server-kid", "missing-server-key", "invalid-kid", "invalid-key-length"} {
		name := name
		t.Run("incomplete-or-invalid/"+name, func(t *testing.T) {
			tuple := ukSVCTuple(ukSVCURL)
			switch name {
			case "zero":
				tuple = userkey.ExpectedIdentity{}
			case "missing-server-kid":
				tuple.ServerKID = ""
			case "missing-server-key":
				tuple.ServerPublicKey = nil
			case "invalid-kid":
				tuple.ServerKID = ukBobKid
			case "invalid-key-length":
				tuple.ServerPublicKey = ukB64(t, ukSVCPubB64)[:31]
			}
			_, err := userkey.ImportCredential(credAlice, tuple)
			ukExpectClass(t, err, userkey.ClassServerIdentityMismatch)
		})
	}

	// Ordering proof: an invalid document with an invalid expected tuple
	// still yields its pipeline class, never server_identity_mismatch.
	t.Run("ordering/bad-url-before-trust", func(t *testing.T) {
		_, err := userkey.ImportCredential([]byte(ukNegCredBadURL), userkey.ExpectedIdentity{})
		ukExpectClass(t, err, userkey.ClassBadURL)
	})
	t.Run("ordering/kid-mismatch-before-trust", func(t *testing.T) {
		_, err := userkey.ImportCredential([]byte(ukNegCredServerKidMismatch), userkey.ExpectedIdentity{})
		ukExpectClass(t, err, userkey.ClassKIDMismatch)
	})
	t.Run("ordering/empty-aud-before-trust", func(t *testing.T) {
		_, err := userkey.ImportCredential([]byte(ukNegCredEmptyAud), userkey.ExpectedIdentity{})
		ukExpectClass(t, err, userkey.ClassWrongFieldType)
	})

	// Refusals return nothing usable.
	t.Run("refusal-returns-nothing", func(t *testing.T) {
		imp, err := userkey.ImportCredential(credAlice, userkey.ExpectedIdentity{})
		if err == nil || imp != nil {
			t.Fatalf("refused import must return no result")
		}
	})
}

// TestRepresentationBoundaries covers row 13: the size boundaries, invalid
// UTF-8, escaped spellings, non-zero padding bits, and exact public
// import->export byte round trips.
func TestRepresentationBoundaries(t *testing.T) {
	t.Run("size-4096-non-canonical", func(t *testing.T) {
		data := append([]byte(ukPrivAlice), bytes.Repeat([]byte{0x20}, 4096-len(ukPrivAlice))...)
		if len(data) != 4096 {
			t.Fatalf("composed length = %d, want 4096", len(data))
		}
		_, err := userkey.ImportClientPrivateEnvelope(data)
		ukExpectClass(t, err, userkey.ClassNonCanonicalBytes)
	})
	t.Run("size-4097-oversized", func(t *testing.T) {
		data := append([]byte(ukPrivAlice), bytes.Repeat([]byte{0x20}, 4097-len(ukPrivAlice))...)
		_, err := userkey.ImportClientPrivateEnvelope(data)
		ukExpectClass(t, err, userkey.ClassOversizedEnvelope)
	})
	t.Run("very-large-oversized", func(t *testing.T) {
		data := make([]byte, 1<<16) // far past the 4096-byte cap
		_, err := userkey.ImportClientPublicEnvelope(data)
		ukExpectClass(t, err, userkey.ClassOversizedEnvelope)
		_, err = userkey.ImportClientPrivateEnvelope(data)
		ukExpectClass(t, err, userkey.ClassOversizedEnvelope)
		_, err = userkey.ImportServerPublicEnvelope(data)
		ukExpectClass(t, err, userkey.ClassOversizedEnvelope)
		_, err = userkey.ImportCredential(data, ukSVCTuple(ukSVCURL))
		ukExpectClass(t, err, userkey.ClassOversizedEnvelope)
		ukExpectClass(t, userkey.ValidateCredential(data, ukSVCTuple(ukSVCURL)), userkey.ClassOversizedEnvelope)
	})
	t.Run("invalid-utf8", func(t *testing.T) {
		data := []byte(ukPrivAlice)
		data[len(data)-1] = 0xFF
		_, err := userkey.ImportClientPrivateEnvelope(data)
		ukExpectClass(t, err, userkey.ClassMalformedJSON)
	})
	t.Run("escaped-member-name", func(t *testing.T) {
		_, err := userkey.ImportClientPublicEnvelope([]byte(ukNegEscapedMemberName))
		ukExpectClass(t, err, userkey.ClassNonCanonicalBytes)
	})
	t.Run("escaped-url-slash", func(t *testing.T) {
		_, err := userkey.ImportCredential([]byte(ukNegEscapedURLSlash), ukSVCTuple(ukSVCURL))
		ukExpectClass(t, err, userkey.ClassNonCanonicalBytes)
	})
	t.Run("trailing-bits", func(t *testing.T) {
		_, err := userkey.ImportClientPublicEnvelope([]byte(ukNegB64TrailingBits))
		ukExpectClass(t, err, userkey.ClassBadEncoding)
	})
	for _, f := range []struct{ id, envelope string }{
		{"pub-alice", ukPubAlice},
		{"pub-bob", ukPubBob},
		{"pub-carol", ukPubCarol},
	} {
		f := f
		t.Run("round-trip/"+f.id, func(t *testing.T) {
			ident, err := userkey.ImportClientPublicEnvelope([]byte(f.envelope))
			ukExpectOK(t, err, "ImportClientPublicEnvelope")
			re, err := ident.ExportPublicEnvelope()
			ukExpectOK(t, err, "ExportPublicEnvelope")
			if !bytes.Equal(re, []byte(f.envelope)) {
				t.Fatalf("round trip is not byte-identical")
			}
		})
	}
}

// TestAudJCSEscapes covers row 14: lone surrogate escapes are malformed_json
// before any decoding, a valid escaped pair reaches the canonical gate, and
// the composed aud positives decode to exact scalar sequences.
func TestAudJCSEscapes(t *testing.T) {
	svc := ukSVCTuple(ukSVCURL)
	t.Run("lone-high-surrogate", func(t *testing.T) {
		data := ukComposeCred(`"\ud800"`, ukPrivAlice, ukSVCKid, ukSVCPubB64, ukJCSQuote(ukSVCURL))
		// Prerequisite: the document is syntactically valid JSON whose aud
		// carries the raw lone-surrogate escape inside a quoted string, so a
		// malformed_json verdict isolates the scalar rule.
		if !json.Valid(data) {
			t.Fatalf("lone-surrogate composition is not syntactically valid JSON")
		}
		if !bytes.Contains(data, []byte(`"aud":"\ud800"`)) {
			t.Fatalf("raw aud escape spelling missing from the composition")
		}
		_, err := userkey.ImportCredential(data, svc)
		ukExpectClass(t, err, userkey.ClassMalformedJSON)
	})
	t.Run("lone-low-surrogate", func(t *testing.T) {
		data := ukComposeCred(`"\udc00"`, ukPrivAlice, ukSVCKid, ukSVCPubB64, ukJCSQuote(ukSVCURL))
		// Prerequisite: the document is syntactically valid JSON whose aud
		// carries the raw lone-surrogate escape inside a quoted string, so a
		// malformed_json verdict isolates the scalar rule.
		if !json.Valid(data) {
			t.Fatalf("lone-surrogate composition is not syntactically valid JSON")
		}
		if !bytes.Contains(data, []byte(`"aud":"\udc00"`)) {
			t.Fatalf("raw aud escape spelling missing from the composition")
		}
		_, err := userkey.ImportCredential(data, svc)
		ukExpectClass(t, err, userkey.ClassMalformedJSON)
	})
	t.Run("valid-escaped-pair-non-canonical", func(t *testing.T) {
		data := ukComposeCred(`"\ud83d\ude00"`, ukPrivAlice, ukSVCKid, ukSVCPubB64, ukJCSQuote(ukSVCURL))
		// Prerequisite: the document is syntactically valid JSON whose aud
		// carries the raw surrogate-pair escape inside a quoted string, so a
		// non_canonical_bytes verdict isolates the canonical spelling rule.
		if !json.Valid(data) {
			t.Fatalf("surrogate-pair composition is not syntactically valid JSON")
		}
		if !bytes.Contains(data, []byte(`"aud":"\ud83d\ude00"`)) {
			t.Fatalf("raw aud escape spelling missing from the composition")
		}
		_, err := userkey.ImportCredential(data, svc)
		ukExpectClass(t, err, userkey.ClassNonCanonicalBytes)
	})
	t.Run("decoded-codepoint-equality", func(t *testing.T) {
		// Compare rune sequences; the aud values are never printed.
		cases := []struct {
			id  string
			aud string
		}{
			{"U+0001", ukAudControl},
			{"U+2028-U+2029", ukAudSeparators},
			{"U+FFFD", ukAudReplacement},
			{"e-acute-plus-U+1F600", ukAudCodepoints},
		}
		for _, c := range cases {
			c := c
			t.Run(c.id, func(t *testing.T) {
				data := ukComposeCredSvc(c.aud, ukPrivAlice, ukSVCURL)
				imp, err := userkey.ImportCredential(data, ukSVCTuple(c.aud))
				ukExpectOK(t, err, "ImportCredential")
				if !ukRunesEqual(imp.Connection.Aud, c.aud) {
					t.Fatalf("decoded aud scalar sequence mismatch")
				}
				if !utf8.ValidString(imp.Connection.Aud) {
					t.Fatalf("decoded aud is not valid UTF-8")
				}
			})
		}
	})
}

// TestSecretAbsence covers row 7: the public export never contains the d
// member or any seed encoding, and the smuggled server_private_key member is
// a byte-present bad_member_set rejection.
func TestSecretAbsence(t *testing.T) {
	seed := ukHex(t, ukAliceSeedHex)
	ck, err := userkey.ImportClientKey(seed)
	ukExpectOK(t, err, "ImportClientKey")
	env, err := userkey.ExportPublicEnvelope(ck)
	ukExpectOK(t, err, "ExportPublicEnvelope")
	out := string(env)
	for _, det := range []string{
		`"d"`,
		hex.EncodeToString(seed),
		jack.EncodeBase64URL(seed),
		ukDecimalRun(seed),
	} {
		if strings.Contains(out, det) {
			t.Fatalf("public export contains forbidden material")
		}
	}

	extra := []byte(ukNegCredExtraServerPrivateKey)
	if !bytes.Contains(extra, []byte(`"server_private_key"`)) {
		t.Fatalf("composed smuggle document lost its extra member")
	}
	_, err = userkey.ImportCredential(extra, ukSVCTuple(ukSVCURL))
	ukExpectClass(t, err, userkey.ClassBadMemberSet)
}

// TestMutabilityIsolation covers rows 8/9 (section 9): returned bytes are
// caller-owned, input snapshots are owned by the importer, and mutation of
// any returned or input slice cannot change identity or later operations.
func TestMutabilityIsolation(t *testing.T) {
	t.Run("export-owned-copy", func(t *testing.T) {
		ck, err := userkey.ImportClientKey(ukHex(t, ukAliceSeedHex))
		ukExpectOK(t, err, "ImportClientKey")
		first, err := userkey.ExportPublicEnvelope(ck)
		ukExpectOK(t, err, "ExportPublicEnvelope")
		// Immutable oracle snapshot of the canonical export.
		snapshot := append([]byte(nil), first...)
		second, err := userkey.ExportPublicEnvelope(ck)
		ukExpectOK(t, err, "second export")
		if !bytes.Equal(second, snapshot) {
			t.Fatalf("exports diverged before mutation")
		}
		kidBefore := ck.KID()
		msg := []byte("export ownership probe")
		wantSig, err := ck.Sign(msg)
		ukExpectOK(t, err, "Sign")
		// Mutate the ACTUAL returned slice in place; never restored.
		for i := range first {
			first[i] ^= 0xFF
		}
		if !bytes.Equal(second, snapshot) {
			t.Fatal("mutating the first export changed the previously returned second copy")
		}
		third, err := userkey.ExportPublicEnvelope(ck)
		ukExpectOK(t, err, "re-export after mutation")
		if !bytes.Equal(third, snapshot) {
			t.Fatalf("re-export changed after mutating the returned export")
		}
		if ck.KID() != kidBefore {
			t.Fatalf("key identity changed after mutating a returned export")
		}
		againSig, err := ck.Sign(msg)
		ukExpectOK(t, err, "Sign after export mutation")
		if !bytes.Equal(againSig, wantSig) {
			t.Fatalf("signer changed after mutating a returned export")
		}
	})
	t.Run("public-key-fresh-copies", func(t *testing.T) {
		ident, err := userkey.ImportClientPublicEnvelope([]byte(ukPubAlice))
		ukExpectOK(t, err, "ImportClientPublicEnvelope")
		want := ident.PublicKey()
		got := ident.PublicKey()
		for i := range got {
			got[i] ^= 0xFF
		}
		again := ident.PublicKey()
		if !bytes.Equal(again, want) {
			t.Fatalf("stored identity changed after mutating a returned copy")
		}
	})
	t.Run("connection-server-key-owned", func(t *testing.T) {
		imp, err := userkey.ImportCredential([]byte(ukCredAlice), ukSVCTuple(ukSVCURL))
		ukExpectOK(t, err, "ImportCredential")
		want := append([]byte(nil), imp.Connection.ServerKey...)
		for i := range imp.Connection.ServerKey {
			imp.Connection.ServerKey[i] ^= 0xFF
		}
		re, err := userkey.ImportCredential([]byte(ukCredAlice), ukSVCTuple(ukSVCURL))
		ukExpectOK(t, err, "re-import")
		if !bytes.Equal(re.Connection.ServerKey, want) {
			t.Fatalf("re-imported server pin differs from the pinned key")
		}
	})
	t.Run("import-input-snapshot", func(t *testing.T) {
		data := []byte(ukPrivAlice)
		ck, err := userkey.ImportClientPrivateEnvelope(data)
		ukExpectOK(t, err, "ImportClientPrivateEnvelope")
		wantKid := ck.KID()
		msg := []byte("snapshot probe")
		wantSig, err := ck.Sign(msg)
		ukExpectOK(t, err, "Sign")
		for i := range data {
			data[i] ^= 0xFF // mutate the caller's input after import
		}
		if ck.KID() != wantKid {
			t.Fatalf("imported identity changed after input mutation")
		}
		sig, err := ck.Sign(msg)
		ukExpectOK(t, err, "Sign")
		if !bytes.Equal(sig, wantSig) {
			t.Fatalf("signer changed after input mutation")
		}
	})
	t.Run("redaction-of-imported-signer", func(t *testing.T) {
		seed := ukHex(t, ukAliceSeedHex)
		ck, err := userkey.ImportClientPrivateEnvelope([]byte(ukPrivAlice))
		ukExpectOK(t, err, "ImportClientPrivateEnvelope")
		detectors := []string{
			hex.EncodeToString(seed), strings.ToUpper(hex.EncodeToString(seed)),
			jack.EncodeBase64URL(seed), base64.StdEncoding.EncodeToString(seed),
			ukDecimalRun(seed),
		}
		value := *ck
		for _, target := range []any{ck, value, map[string]any{"k": ck}} {
			for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
				out := fmt.Sprintf(verb, target)
				for _, d := range detectors {
					if strings.Contains(out, d) {
						t.Fatalf("signer representation leaked material (verb %s)", verb)
					}
				}
			}
		}
	})
}

// TestNilAndZero covers section E ownership and nil/zero behavior.
func TestNilAndZero(t *testing.T) {
	t.Run("export-nil", func(t *testing.T) {
		_, err := userkey.ExportPublicEnvelope(nil)
		ukExpectClass(t, err, userkey.ClassBadEncoding)
	})
	t.Run("export-typed-nil", func(t *testing.T) {
		var ck *userkey.ClientKey
		_, err := userkey.ExportPublicEnvelope(ck)
		ukExpectClass(t, err, userkey.ClassBadEncoding)
		var sk *userkey.ServerKey
		_, err = userkey.ExportPublicEnvelope(sk)
		ukExpectClass(t, err, userkey.ClassBadEncoding)
		var pi *userkey.PublicIdentity
		_, err = userkey.ExportPublicEnvelope(pi)
		ukExpectClass(t, err, userkey.ClassBadEncoding)
	})
	t.Run("nil-public-identity-methods", func(t *testing.T) {
		var pi *userkey.PublicIdentity
		if got := pi.PublicKey(); len(got) != 0 {
			t.Fatalf("nil PublicKey = %x, want empty", got)
		}
		if got := pi.KID(); got != "" {
			t.Fatalf("nil KID = %q, want empty", got)
		}
		if pi.Verify([]byte("m"), make([]byte, 64)) {
			t.Fatalf("nil Verify returned true")
		}
		_, err := pi.Sign([]byte("m"))
		ukExpectClass(t, err, userkey.ClassNotPrivate)
	})
	t.Run("zero-public-identity-methods", func(t *testing.T) {
		var pi userkey.PublicIdentity
		if got := pi.PublicKey(); len(got) != 0 {
			t.Fatalf("zero PublicKey = %x, want empty", got)
		}
		if got := pi.KID(); got != "" {
			t.Fatalf("zero KID = %q, want empty", got)
		}
		if pi.Verify([]byte("m"), make([]byte, 64)) {
			t.Fatalf("zero Verify returned true")
		}
		_, err := pi.Sign([]byte("m"))
		ukExpectClass(t, err, userkey.ClassNotPrivate)
		if got, _ := json.Marshal(pi); string(got) != "{}" {
			t.Fatalf("zero identity JSON = %s, want {}", got)
		}
	})
	t.Run("nil-issuance-credential-bytes", func(t *testing.T) {
		var issued *userkey.UserKeyIssuance
		if got := issued.CredentialBytes(); got != nil {
			t.Fatalf("nil issuance CredentialBytes is not nil")
		}
	})
}

// TestErrorDiagnostics covers section E diagnostics: errors carry class,
// member and length only, with no decoded material and HTTPStatus 0 on every
// class.
func TestErrorDiagnostics(t *testing.T) {
	dString := "FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8"
	xString := "27O5sjd6_PRkCVbNLwEbIwxpfh0DZCURwFI9lWF-UHE"

	t.Run("seed-pub-mismatch-text", func(t *testing.T) {
		_, err := userkey.ImportClientPrivateEnvelope([]byte(ukNegSeedPubMismatch))
		var je *jack.Error
		ukExpectClass(t, err, userkey.ClassSeedPubMismatch)
		if !errors.As(err, &je) {
			t.Fatalf("unreachable")
		}
		text := je.Error()
		if strings.Contains(text, dString) || strings.Contains(text, xString) {
			t.Fatalf("error text contains decoded material")
		}
		if je.HTTPStatus != 0 {
			t.Fatalf("HTTPStatus = %d, want 0", je.HTTPStatus)
		}
	})
	t.Run("kid-mismatch-text", func(t *testing.T) {
		_, err := userkey.ImportClientPrivateEnvelope([]byte(ukNegKidMismatch))
		var je *jack.Error
		ukExpectClass(t, err, userkey.ClassKIDMismatch)
		if !errors.As(err, &je) {
			t.Fatalf("unreachable")
		}
		if je.HTTPStatus != 0 {
			t.Fatalf("HTTPStatus = %d, want 0", je.HTTPStatus)
		}
	})
	t.Run("trust-mismatch-text", func(t *testing.T) {
		err := userkey.ValidateCredential([]byte(ukCredAlice), ukSVCTuple("other-audience"))
		var je *jack.Error
		ukExpectClass(t, err, userkey.ClassServerIdentityMismatch)
		if !errors.As(err, &je) {
			t.Fatalf("unreachable")
		}
		if je.HTTPStatus != 0 {
			t.Fatalf("HTTPStatus = %d, want 0", je.HTTPStatus)
		}
	})
}

// staticSigner is a test-only non-extractable signer: it implements only the
// general client.Signer interface with its own embedded pinned key (keys.json
// erin) and never reveals a seed. Row 10 requires public export to work on it.
type staticSigner struct {
	priv ed25519.PrivateKey
	pub  []byte
	kid  string
}

var _ client.Signer = (*staticSigner)(nil)

func newStaticSigner(t *testing.T) *staticSigner {
	t.Helper()
	seed := ukHex(t, ukErinSeedHex)
	pub := ukB64(t, ukErinPubB64)
	return &staticSigner{
		priv: ed25519.NewKeyFromSeed(seed),
		pub:  pub,
		kid:  jack.KeyID(pub),
	}
}

func (s *staticSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}
func (s *staticSigner) PublicKey() []byte {
	out := make([]byte, len(s.pub))
	copy(out, s.pub)
	return out
}
func (s *staticSigner) KID() string { return s.kid }

// TestNonExtractableCompatibility covers row 10: a signer implementing only
// client.Signer exports a canonical public envelope, and *ClientKey keeps
// satisfying both signer interfaces.
func TestNonExtractableCompatibility(t *testing.T) {
	s := newStaticSigner(t)
	env, err := userkey.ExportPublicEnvelope(s)
	ukExpectOK(t, err, "ExportPublicEnvelope(staticSigner)")
	want := ukComposePublic(ukErinPubB64, jack.KeyID(ukB64(t, ukErinPubB64)))
	if !bytes.Equal(env, want) {
		t.Fatalf("exported envelope differs from the canonical template")
	}
	if s.KID() != ukErinKid {
		t.Fatalf("pinned erin kid mismatch")
	}

	msg := []byte("non-extractable probe")
	sig, err := s.Sign(msg)
	ukExpectOK(t, err, "Sign")
	server, err := userkey.ImportServerPublicEnvelope(env)
	ukExpectOK(t, err, "ImportServerPublicEnvelope")
	if !server.Verify(msg, sig) {
		t.Fatalf("server Verify rejected the static signer signature")
	}

	// The imported client key keeps satisfying both bridges (compile-time
	// assertions at the top of the file, plus a runtime double check).
	ck, err := userkey.ImportClientPrivateEnvelope([]byte(ukPrivAlice))
	ukExpectOK(t, err, "ImportClientPrivateEnvelope")
	var asClient client.Signer = ck
	var asUserkey userkey.Signer = ck
	if asClient.KID() != ck.KID() || asUserkey.KID() != ck.KID() {
		t.Fatalf("signer bridges disagree on kid")
	}
}
