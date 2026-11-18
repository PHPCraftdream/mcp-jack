package userkey_test

import (
	"bytes"
	"reflect"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

// TestClassConstants pins the exact shared class strings and the Error shape.
func TestClassConstants(t *testing.T) {
	for _, tc := range []struct {
		c    string
		want string
	}{
		{userkey.ClassMalformedJSON, "malformed_json"},
		{userkey.ClassWrongRootType, "wrong_root_type"},
		{userkey.ClassOversizedEnvelope, "oversized_envelope"},
		{userkey.ClassUnknownVersion, "unknown_version"},
		{userkey.ClassUnknownType, "unknown_type"},
		{userkey.ClassBadMemberSet, "bad_member_set"},
		{userkey.ClassWrongFieldType, "wrong_field_type"},
		{userkey.ClassBadEncoding, "bad_encoding"},
		{userkey.ClassBadURL, "bad_url"},
		{userkey.ClassInvalidPublicKey, "invalid_public_key"},
		{userkey.ClassSeedPubMismatch, "seed_pub_mismatch"},
		{userkey.ClassKIDMismatch, "kid_mismatch"},
		{userkey.ClassNonCanonicalBytes, "non_canonical_bytes"},
		{userkey.ClassWrongEnvelopeType, "wrong_envelope_type"},
		{userkey.ClassPrivateMaterialRejected, "private_material_rejected"},
		{userkey.ClassNotPrivate, "not_private"},
		{userkey.ClassServerIdentityMismatch, "server_identity_mismatch"},
	} {
		if tc.c != tc.want {
			t.Fatalf("class constant = %q, want %q", tc.c, tc.want)
		}
	}
}

// TestPositivePublicEnvelopes covers rows 1, 5 and 13: fixture pub-* imports
// on both public sinks match the pinned x/kid, the kid is jack.KeyID of the
// strict-valid public key, generated keys export the canonical template, and
// import->export round trips are byte-identical.
func TestPositivePublicEnvelopes(t *testing.T) {
	fixtures := []struct {
		id       string
		envelope string
		wantX    string
		wantKid  string
	}{
		{"pub-alice", ukPubAlice, ukAlicePubB64, ukAliceKid},
		{"pub-bob", ukPubBob, ukBobPubB64, ukBobKid},
		{"pub-carol", ukPubCarol, ukCarolPubB64, ukCarolKid},
	}
	for _, f := range fixtures {
		f := f
		t.Run(f.id, func(t *testing.T) {
			wantPub := ukB64(t, f.wantX)

			ident, err := userkey.ImportClientPublicEnvelope([]byte(f.envelope))
			ukExpectOK(t, err, "ImportClientPublicEnvelope")
			if got := ident.PublicKey(); !bytes.Equal(got, wantPub) {
				t.Fatalf("client public = %x, want %x", got, wantPub)
			}
			if got := ident.KID(); got != f.wantKid {
				t.Fatalf("client kid = %q, want %q", got, f.wantKid)
			}

			server, err := userkey.ImportServerPublicEnvelope([]byte(f.envelope))
			ukExpectOK(t, err, "ImportServerPublicEnvelope")
			if got := server.PublicKey(); !bytes.Equal(got, wantPub) {
				t.Fatalf("server public = %x, want %x", got, wantPub)
			}
			if got := server.KID(); got != f.wantKid {
				t.Fatalf("server kid = %q, want %q", got, f.wantKid)
			}

			if err := jack.ValidatePublicKey(wantPub); err != nil {
				t.Fatalf("pinned public key rejected by admission: %v", err)
			}
			if f.wantKid != jack.KeyID(wantPub) {
				t.Fatalf("pinned kid is not jack.KeyID of the pinned public key")
			}

			// Exact import->export round trip (row 13), both sink types.
			re, err := ident.ExportPublicEnvelope()
			ukExpectOK(t, err, "PublicIdentity.ExportPublicEnvelope")
			if !bytes.Equal(re, []byte(f.envelope)) {
				t.Fatalf("client round trip bytes differ from the fixture envelope")
			}
			re2, err := userkey.ExportPublicEnvelope(server)
			ukExpectOK(t, err, "ExportPublicEnvelope(ServerKey)")
			if !bytes.Equal(re2, []byte(f.envelope)) {
				t.Fatalf("server round trip bytes differ from the fixture envelope")
			}
		})
	}

	// Row 1: generated identity exports exactly the canonical public template
	// and its kid equals jack.KeyID of the public key.
	ck, err := userkey.ImportClientKey(ukHex(t, ukAliceSeedHex))
	ukExpectOK(t, err, "ImportClientKey")
	env, err := userkey.ExportPublicEnvelope(ck)
	ukExpectOK(t, err, "ExportPublicEnvelope")
	want := ukComposePublic(jack.EncodeBase64URL(ck.PublicKey()), jack.KeyID(ck.PublicKey()))
	if !bytes.Equal(env, want) {
		t.Fatalf("exported envelope differs from the canonical template")
	}
	if ck.KID() != jack.KeyID(ck.PublicKey()) {
		t.Fatalf("generated kid does not equal jack.KeyID of the public key")
	}
}

// TestPositivePrivateEnvelopes covers row 2 with oracle independence (section
// 11): decoded d bytes equal the keys.json seed_hex raw bytes, x/kid are
// pinned from keys.json strings, signatures equal client.NewInMemorySigner
// (RFC 8032 determinism) and verify via ServerKey.Verify; the composed
// priv-rfc8032-test1 envelope reproduces the RFC 8037 A.1 encodings and the
// RFC signatures for TEST 1 and TEST 3.
func TestPositivePrivateEnvelopes(t *testing.T) {
	msg := []byte("user-key transfer determinism message")
	fixtures := []struct {
		id       string
		envelope string
		seedHex  string
		pubB64   string
		kid      string
	}{
		{"priv-alice", ukPrivAlice, ukAliceSeedHex, ukAlicePubB64, ukAliceKid},
		{"priv-bob", ukPrivBob, ukBobSeedHex, ukBobPubB64, ukBobKid},
		{"priv-carol", ukPrivCarol, ukCarolSeedHex, ukCarolPubB64, ukCarolKid},
	}
	for _, f := range fixtures {
		f := f
		t.Run(f.id, func(t *testing.T) {
			seed := ukHex(t, f.seedHex)
			if !bytes.Equal(ukEnvelopeD(t, []byte(f.envelope)), seed) {
				t.Fatalf("envelope d bytes differ from keys.json seed_hex raw bytes")
			}
			wantPub := ukB64(t, f.pubB64)

			ck, err := userkey.ImportClientPrivateEnvelope([]byte(f.envelope))
			ukExpectOK(t, err, "ImportClientPrivateEnvelope")
			if got := ck.PublicKey(); !bytes.Equal(got, wantPub) {
				t.Fatalf("public = %x, want %x", got, wantPub)
			}
			if got := ck.KID(); got != f.kid {
				t.Fatalf("kid = %q, want %q", got, f.kid)
			}
			if err := jack.ValidatePublicKey(wantPub); err != nil {
				t.Fatalf("pinned public key rejected: %v", err)
			}

			// RFC determinism against the existing software signer oracle.
			ref, err := client.NewInMemorySigner(seed)
			ukExpectOK(t, err, "NewInMemorySigner")
			sig, err := ck.Sign(msg)
			ukExpectOK(t, err, "Sign")
			wantSig, err := ref.Sign(msg)
			ukExpectOK(t, err, "oracle Sign")
			if !bytes.Equal(sig, wantSig) {
				t.Fatalf("signature differs from the oracle signer signature")
			}

			server, err := userkey.ImportServerKey(wantPub)
			ukExpectOK(t, err, "ImportServerKey")
			if !server.Verify(msg, sig) {
				t.Fatalf("ServerKey.Verify rejected the deterministic signature")
			}
		})
	}

	t.Run("priv-rfc8032-test1", func(t *testing.T) {
		envelope := ukComposeRFC1Private(t)
		ck, err := userkey.ImportClientPrivateEnvelope(envelope)
		ukExpectOK(t, err, "ImportClientPrivateEnvelope")
		if !bytes.Equal(ukEnvelopeD(t, envelope), ukHex(t, ukRFC1SeedHex)) {
			t.Fatalf("RFC envelope d bytes differ from the RFC seed raw bytes")
		}
		wantPub := ukHex(t, ukRFC1PubHex)
		if got := ck.PublicKey(); !bytes.Equal(got, wantPub) {
			t.Fatalf("public = %x, want RFC public", got)
		}
		if got := ck.KID(); got != jack.KeyID(wantPub) {
			t.Fatalf("kid does not equal jack.KeyID of the RFC public key")
		}
		sig, err := ck.Sign(nil)
		ukExpectOK(t, err, "Sign(empty message)")
		if !bytes.Equal(sig, ukHex(t, ukRFC1SigHex)) {
			t.Fatalf("signature differs from RFC 8032 TEST 1")
		}
		server, err := userkey.ImportServerKey(wantPub)
		ukExpectOK(t, err, "ImportServerKey")
		if !server.Verify(nil, sig) {
			t.Fatalf("ServerKey.Verify rejected the RFC 8032 TEST 1 signature")
		}
	})

	t.Run("rfc8032-test3-signature-equality", func(t *testing.T) {
		seed := ukHex(t, ukRFC3SeedHex)
		envelope := ukComposePrivate(jack.EncodeBase64URL(seed), jack.KeyID(ukHex(t, ukRFC3PubHex)), jack.EncodeBase64URL(ukHex(t, ukRFC3PubHex)))
		ck, err := userkey.ImportClientPrivateEnvelope(envelope)
		ukExpectOK(t, err, "ImportClientPrivateEnvelope")
		sig, err := ck.Sign(ukHex(t, ukRFC3MsgHex))
		ukExpectOK(t, err, "Sign")
		if !bytes.Equal(sig, ukHex(t, ukRFC3SigHex)) {
			t.Fatalf("signature differs from RFC 8032 TEST 3")
		}
	})
}

// TestPositiveCredentials covers the credential positives on their intended
// sink (ImportCredential with the exact independently trusted tuple), rows
// 12 and 14: cred-alice, cred-bob, the literal aud control, and the four
// composed aud controls; decoded auds are compared by rune sequence.
func TestPositiveCredentials(t *testing.T) {
	t.Run("cred-alice", func(t *testing.T) {
		// Cross-check the literal against our own independent composer.
		composed := ukComposeCredSvc(ukSVCURL, ukPrivAlice, ukSVCURL)
		if !bytes.Equal(composed, []byte(ukCredAlice)) {
			t.Fatalf("composed cred-alice bytes differ from the fixture literal")
		}
		imp, err := userkey.ImportCredential([]byte(ukCredAlice), ukSVCTuple(ukSVCURL))
		ukExpectOK(t, err, "ImportCredential")
		if imp.Connection.BaseURL != ukSVCURL {
			t.Fatalf("connection url mismatch")
		}
		if !ukRunesEqual(imp.Connection.Aud, ukSVCURL) {
			t.Fatalf("connection aud mismatch")
		}
		if !bytes.Equal(imp.Connection.ServerKey, ukSVCPub(t)) || imp.Connection.ServerKID != ukSVCKid {
			t.Fatalf("connection server pin mismatch")
		}
		if imp.Signer.KID() != ukAliceKid {
			t.Fatalf("client kid mismatch")
		}
		if len(imp.Connection.ServerKey) != 32 || reflect.TypeOf(imp.Connection).NumField() != 4 {
			t.Fatalf("connection config shape changed")
		}
	})

	t.Run("cred-bob", func(t *testing.T) {
		imp, err := userkey.ImportCredential([]byte(ukCredBob), ukSVCTuple(ukSVCURL))
		ukExpectOK(t, err, "ImportCredential")
		if imp.Signer.KID() != ukBobKid {
			t.Fatalf("client kid mismatch")
		}
	})

	audCases := []struct {
		id  string
		aud string
	}{
		{"cred-aud-html-sensitive", ukAudHTML},
		{"cred-aud-codepoints", ukAudCodepoints},
		{"cred-aud-control", ukAudControl},
		{"cred-aud-separators", ukAudSeparators},
		{"cred-aud-replacement-char", ukAudReplacement},
	}
	for _, ac := range audCases {
		ac := ac
		t.Run(ac.id, func(t *testing.T) {
			data := ukComposeCredSvc(ac.aud, ukPrivAlice, ukSVCURL)
			imp, err := userkey.ImportCredential(data, ukSVCTuple(ac.aud))
			ukExpectOK(t, err, "ImportCredential")
			if !ukRunesEqual(imp.Connection.Aud, ac.aud) {
				t.Fatalf("decoded aud scalar sequence mismatch")
			}
			if err := userkey.ValidateCredential(data, ukSVCTuple(ac.aud)); err != nil {
				t.Fatalf("ValidateCredential: %v", err)
			}
			if imp.Signer.KID() != ukAliceKid {
				t.Fatalf("client kid mismatch")
			}
		})
	}

	// The literal HTML-sensitive fixture must equal our composer output: the
	// canonical emitter never HTML-escapes <>&.
	t.Run("cred-aud-html-sensitive-literal", func(t *testing.T) {
		composed := ukComposeCredSvc(ukAudHTML, ukPrivAlice, ukSVCURL)
		if !bytes.Equal(composed, []byte(ukCredAudHTML)) {
			t.Fatalf("composed bytes differ from the fixture literal")
		}
		if _, err := userkey.ImportCredential([]byte(ukCredAudHTML), ukSVCTuple(ukAudHTML)); err != nil {
			t.Fatalf("ImportCredential: %v", err)
		}
	})
}

// TestNegativeFixtures covers row 6: every neg-* case fails with exactly its
// expect_class as the first failure on the sink named by contract section 5.
func TestNegativeFixtures(t *testing.T) {
	rejectY := ukHex(t, ukRejectYAbovePHex)
	rejectIdentity := ukHex(t, ukRejectIdentityHex)
	rejectOrder2 := ukHex(t, ukRejectOrder2Hex)
	rejectOffCurve := ukHex(t, ukRejectOffCurveHex)

	padTo := func(base string, total int) []byte {
		out := []byte(base)
		if total < len(out) {
			panic("pad target smaller than base")
		}
		return append(out, bytes.Repeat([]byte{0x20}, total-len(out))...)
	}
	invalidUTF8 := func() []byte {
		out := []byte(ukPrivAlice)
		out[len(out)-1] = 0xFF // replace the closing 0x7D
		return out
	}
	composedInvalidPub := func(pub []byte) []byte {
		return ukComposePublic(jack.EncodeBase64URL(pub), jack.KeyID(pub))
	}
	loneHighAudCred := ukComposeCred(`"\ud800"`, ukPrivAlice, ukSVCKid, ukSVCPubB64, ukJCSQuote(ukSVCURL))
	loneLowAudCred := ukComposeCred(`"\udc00"`, ukPrivAlice, ukSVCKid, ukSVCPubB64, ukJCSQuote(ukSVCURL))
	escapedPairAudCred := ukComposeCred(`"\ud83d\ude00"`, ukPrivAlice, ukSVCKid, ukSVCPubB64, ukJCSQuote(ukSVCURL))
	dupInnerCred := ukComposeCred(ukJCSQuote(ukSVCURL), ukNegDupMember, ukSVCKid, ukSVCPubB64, ukJCSQuote(ukSVCURL))
	invalidServerPubCred := ukComposeCred(ukJCSQuote(ukSVCURL), ukPrivAlice, jack.KeyID(rejectY), jack.EncodeBase64URL(rejectY), ukJCSQuote(ukSVCURL))

	type sinkKind int
	const (
		sinkPublic sinkKind = iota
		sinkPrivate
		sinkCredential
	)

	cases := []struct {
		id    string
		class string
		sink  sinkKind
		data  []byte
	}{
		{"neg-unknown-version", userkey.ClassUnknownVersion, sinkPrivate, []byte(ukNegUnknownVersion)},
		{"neg-unknown-type", userkey.ClassUnknownType, sinkPrivate, []byte(ukNegUnknownType)},
		{"neg-bad-kty", userkey.ClassUnknownType, sinkPrivate, []byte(ukNegBadKTY)},
		{"neg-bad-crv", userkey.ClassUnknownType, sinkPrivate, []byte(ukNegBadCRV)},
		{"neg-unknown-field", userkey.ClassBadMemberSet, sinkPublic, []byte(ukNegUnknownField)},
		{"neg-missing-kid", userkey.ClassBadMemberSet, sinkPublic, []byte(ukNegMissingKid)},
		{"neg-wrong-field-type", userkey.ClassWrongFieldType, sinkPublic, []byte(ukNegWrongFieldType)},
		{"neg-null-field", userkey.ClassWrongFieldType, sinkPublic, []byte(ukNegNullField)},
		{"neg-empty-d", userkey.ClassBadEncoding, sinkPrivate, []byte(ukNegEmptyD)},
		{"neg-b64-padding", userkey.ClassBadEncoding, sinkPublic, []byte(ukNegB64Padding)},
		{"neg-b64-char", userkey.ClassBadEncoding, sinkPublic, []byte(`{"crv":"Ed25519","kid":"TXF9TkhWm+UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/public","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"}`)},
		{"neg-escaped-member-name", userkey.ClassNonCanonicalBytes, sinkPublic, []byte(ukNegEscapedMemberName)},
		{"neg-len-short", userkey.ClassBadEncoding, sinkPublic, []byte(ukNegLenShort)},
		{"neg-len-long", userkey.ClassBadEncoding, sinkPublic, []byte(ukNegLenLong)},
		{"neg-b64-trailing-bits", userkey.ClassBadEncoding, sinkPublic, []byte(ukNegB64TrailingBits)},
		{"neg-seed-pub-mismatch", userkey.ClassSeedPubMismatch, sinkPrivate, []byte(ukNegSeedPubMismatch)},
		{"neg-kid-mismatch", userkey.ClassKIDMismatch, sinkPrivate, []byte(ukNegKidMismatch)},
		{"neg-dup-member", userkey.ClassNonCanonicalBytes, sinkPrivate, []byte(ukNegDupMember)},
		{"neg-dup-member-last-mismatched", userkey.ClassKIDMismatch, sinkPrivate, []byte(ukNegDupMemberLastMismatched)},
		{"neg-dup-member-escaped", userkey.ClassNonCanonicalBytes, sinkPrivate, []byte(ukNegDupMemberEscaped)},
		{"neg-noncanonical-ws", userkey.ClassNonCanonicalBytes, sinkPrivate, []byte(ukNegNoncanonicalWS)},
		{"neg-key-reorder", userkey.ClassNonCanonicalBytes, sinkPrivate, []byte(ukNegKeyReorder)},
		{"neg-truncated", userkey.ClassMalformedJSON, sinkPrivate, []byte(ukNegTruncated)},
		{"neg-size-boundary-4096", userkey.ClassNonCanonicalBytes, sinkPrivate, padTo(ukPrivAlice, 4096)},
		{"neg-size-boundary-4097", userkey.ClassOversizedEnvelope, sinkPrivate, padTo(ukPrivAlice, 4097)},
		{"neg-invalid-utf8", userkey.ClassMalformedJSON, sinkPrivate, invalidUTF8()},
		{"neg-oversized-envelope", userkey.ClassOversizedEnvelope, sinkPrivate, padTo(ukPrivAlice, 4200)},
		{"neg-root-array", userkey.ClassWrongRootType, sinkPublic, []byte(ukNegRootArray)},
		{"neg-root-string", userkey.ClassWrongRootType, sinkPublic, []byte(ukNegRootString)},
		{"neg-empty-input", userkey.ClassMalformedJSON, sinkPublic, nil},
		{"neg-null-input", userkey.ClassWrongRootType, sinkPublic, []byte(ukNegNullInput)},
		{"neg-v-float", userkey.ClassNonCanonicalBytes, sinkPrivate, []byte(ukNegVFloat)},
		{"neg-invalid-pub-noncanonical-y", userkey.ClassInvalidPublicKey, sinkPublic, composedInvalidPub(rejectY)},
		{"neg-invalid-pub-identity", userkey.ClassInvalidPublicKey, sinkPublic, composedInvalidPub(rejectIdentity)},
		{"neg-invalid-pub-small-order", userkey.ClassInvalidPublicKey, sinkPublic, composedInvalidPub(rejectOrder2)},
		{"neg-invalid-pub-off-curve", userkey.ClassInvalidPublicKey, sinkPublic, composedInvalidPub(rejectOffCurve)},
		{"neg-cred-unknown-version", userkey.ClassUnknownVersion, sinkCredential, []byte(ukNegCredUnknownVersion)},
		{"neg-cred-unknown-type", userkey.ClassUnknownType, sinkCredential, []byte(ukNegCredUnknownType)},
		{"neg-cred-missing-server-kid", userkey.ClassBadMemberSet, sinkCredential, []byte(ukNegCredMissingServerKid)},
		{"neg-cred-extra-server-private-key", userkey.ClassBadMemberSet, sinkCredential, []byte(ukNegCredExtraServerPrivateKey)},
		{"neg-cred-server-kid-mismatch", userkey.ClassKIDMismatch, sinkCredential, []byte(ukNegCredServerKidMismatch)},
		{"neg-cred-bad-url", userkey.ClassBadURL, sinkCredential, []byte(ukNegCredBadURL)},
		{"neg-cred-empty-aud", userkey.ClassWrongFieldType, sinkCredential, []byte(ukNegCredEmptyAud)},
		{"neg-cred-aud-lone-surrogate-escape", userkey.ClassMalformedJSON, sinkCredential, loneHighAudCred},
		{"neg-cred-aud-lone-low-surrogate-escape", userkey.ClassMalformedJSON, sinkCredential, loneLowAudCred},
		{"neg-cred-aud-escaped-surrogate-pair", userkey.ClassNonCanonicalBytes, sinkCredential, escapedPairAudCred},
		{"neg-cred-dup-inner-member", userkey.ClassNonCanonicalBytes, sinkCredential, dupInnerCred},
		{"neg-cred-invalid-server-pub", userkey.ClassInvalidPublicKey, sinkCredential, invalidServerPubCred},
		{"neg-escaped-url-slash", userkey.ClassNonCanonicalBytes, sinkCredential, []byte(ukNegEscapedURLSlash)},
		{"neg-cred-client-key-noncanonical", userkey.ClassNonCanonicalBytes, sinkCredential, []byte(ukNegCredClientKeyNoncanonical)},
		{"neg-cred-client-key-public", userkey.ClassWrongEnvelopeType, sinkCredential, []byte(ukNegCredClientKeyPublic)},
	}

	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			var err error
			switch c.sink {
			case sinkPublic:
				_, err = userkey.ImportClientPublicEnvelope(c.data)
			case sinkPrivate:
				_, err = userkey.ImportClientPrivateEnvelope(c.data)
			case sinkCredential:
				_, err = userkey.ImportCredential(c.data, ukSVCTuple(ukSVCURL))
			}
			ukExpectClass(t, err, c.class)
		})
	}
}

// TestContextWrongServer covers the cred-wrong-server context case: the
// document embeds the ALICE server identity stand-in (exact shared fixture
// composition), imports cleanly against that embedded identity, and refuses
// with server_identity_mismatch against the independently trusted svc tuple.
func TestContextWrongServer(t *testing.T) {
	data := ukComposeCred(ukJCSQuote(ukSVCURL), ukPrivAlice, ukAliceKid, ukAlicePubB64, ukJCSQuote(ukSVCURL))
	// Composition prerequisites: the raw document carries alice's server
	// identity, not the svc identity.
	if !bytes.Contains(data, []byte(ukAlicePubB64)) || !bytes.Contains(data, []byte(ukAliceKid)) {
		t.Fatalf("composed wrong-server document does not embed the alice server identity")
	}
	if bytes.Contains(data, []byte(ukSVCPubB64)) {
		t.Fatalf("composed wrong-server document wrongly embeds the svc identity")
	}
	embedded := userkey.ExpectedIdentity{
		URL:             ukSVCURL,
		Aud:             ukSVCURL,
		ServerPublicKey: ukB64(t, ukAlicePubB64),
		ServerKID:       ukAliceKid,
	}
	imp, err := userkey.ImportCredential(data, embedded)
	ukExpectOK(t, err, "pipeline acceptance with the embedded identity")
	if imp.Signer.KID() != ukAliceKid {
		t.Fatalf("structurally accepted credential has the wrong client kid")
	}

	_, err = userkey.ImportCredential(data, ukSVCTuple(ukSVCURL))
	ukExpectClass(t, err, userkey.ClassServerIdentityMismatch)
	ukExpectClass(t, userkey.ValidateCredential(data, ukSVCTuple(ukSVCURL)), userkey.ClassServerIdentityMismatch)
}
