package userkey_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

// ukKnownClass is the set of stable Code values every strict transfer
// rejection must carry (mirrors TestClassConstants).
var ukKnownClass = map[string]bool{
	userkey.ClassMalformedJSON:           true,
	userkey.ClassWrongRootType:           true,
	userkey.ClassOversizedEnvelope:       true,
	userkey.ClassUnknownVersion:          true,
	userkey.ClassUnknownType:             true,
	userkey.ClassBadMemberSet:            true,
	userkey.ClassWrongFieldType:          true,
	userkey.ClassBadEncoding:             true,
	userkey.ClassBadURL:                  true,
	userkey.ClassInvalidPublicKey:        true,
	userkey.ClassSeedPubMismatch:         true,
	userkey.ClassKIDMismatch:             true,
	userkey.ClassNonCanonicalBytes:       true,
	userkey.ClassWrongEnvelopeType:       true,
	userkey.ClassPrivateMaterialRejected: true,
	userkey.ClassNotPrivate:              true,
	userkey.ClassServerIdentityMismatch:  true,
}

// ukRedacted reports whether every fmt rendering of the value keeps the raw
// transfer bytes out of the output (mirrors TestIssuanceRedaction).
func ukRedacted(value any, data []byte) bool {
	for _, rendered := range []string{
		fmt.Sprintf("%v", value),
		fmt.Sprintf("%+v", value),
		fmt.Sprintf("%#v", value),
	} {
		if strings.Contains(rendered, string(data)) {
			return false
		}
	}
	return true
}

// ukAliceSeedB64 is the base64url d member of the pinned ukPrivAlice
// fixture (transfer_test.go:81); it exists here only so the canonical
// private-envelope composer ukComposePrivate can rebuild that document
// from its seed.
const ukAliceSeedB64 = "FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8"

// ukCanonicalPrivateParts recomposes the canonical private envelope from the
// members the accepted document itself carries, using the test-only composer
// (docs/design/user-keys.md section 4). It fails closed on any missing or
// mis-typed member, and returns the decoded public key and kid the document
// describes so the caller can pin the imported key to the document identity.
func ukCanonicalPrivateParts(data []byte) ([]byte, []byte, string, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, "", err
	}
	if len(doc) != 7 {
		return nil, nil, "", errors.New("private envelope member set")
	}
	for name, want := range map[string]string{
		"crv":  `"Ed25519"`,
		"kty":  `"OKP"`,
		"type": `"user-key/private"`,
		"v":    `1`,
	} {
		if raw, ok := doc[name]; !ok || string(raw) != want {
			return nil, nil, "", errors.New("private envelope fixed member " + name)
		}
	}
	var d, kid, x string
	for name, dst := range map[string]*string{"d": &d, "kid": &kid, "x": &x} {
		raw, ok := doc[name]
		if !ok {
			return nil, nil, "", errors.New("private envelope missing member " + name)
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			return nil, nil, "", errors.New("private envelope member " + name + " is not a string")
		}
	}
	pub, err := jack.DecodeBase64URLFixed(x, 32)
	if err != nil {
		return nil, nil, "", errors.New("private envelope x does not decode to 32 bytes")
	}
	return ukComposePrivate(d, kid, x), pub, kid, nil
}

// ukCanonicalCredentialParts recomposes the canonical credential from the
// members the accepted document itself carries (docs/design/user-keys.md
// section 4), requiring the embedded client_key to be the canonical private
// envelope, and returns the decoded client and server public keys so the
// caller can pin the imported signer and connection to the document identity.
func ukCanonicalCredentialParts(data []byte) ([]byte, []byte, []byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, nil, err
	}
	if len(doc) != 7 {
		return nil, nil, nil, errors.New("credential member set")
	}
	for name, want := range map[string]string{
		"type": `"user-key/credential/client"`,
		"v":    `1`,
	} {
		if raw, ok := doc[name]; !ok || string(raw) != want {
			return nil, nil, nil, errors.New("credential fixed member " + name)
		}
	}
	var aud, clientKey, serverKid, serverPubB64, url string
	for name, dst := range map[string]*string{
		"aud":               &aud,
		"client_key":        &clientKey,
		"server_kid":        &serverKid,
		"server_public_key": &serverPubB64,
		"url":               &url,
	} {
		raw, ok := doc[name]
		if !ok {
			return nil, nil, nil, errors.New("credential missing member " + name)
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			return nil, nil, nil, errors.New("credential member " + name + " is not a string")
		}
	}
	innerCanonical, clientPub, _, errInner := ukCanonicalPrivateParts([]byte(clientKey))
	if errInner != nil || !bytes.Equal([]byte(clientKey), innerCanonical) {
		return nil, nil, nil, errors.New("credential client_key is not the canonical private envelope")
	}
	serverPub, errPub := jack.DecodeBase64URLFixed(serverPubB64, 32)
	if errPub != nil {
		return nil, nil, nil, errors.New("credential server_public_key does not decode to 32 bytes")
	}
	return ukComposeCred(ukJCSQuote(aud), clientKey, serverKid, serverPubB64, ukJCSQuote(url)), clientPub, serverPub, nil
}

// FuzzImportEnvelopes drives all three strict importers over the same input:
// a public-sink acceptance is verify-only (Sign must fail with not_private),
// a private-sink acceptance signs and verifies, a server-sink acceptance can
// never double as a private envelope, every acceptance carries a strictly
// valid 32-byte key with kid == jack.KeyID, every rejection is a bounded
// *jack.Error from the Class* set with no wire status, and every fmt
// rendering of an accepted identity keeps the raw bytes redacted.
func FuzzImportEnvelopes(f *testing.F) {
	for _, seed := range []string{
		ukPubAlice, ukPrivAlice, ukPubBob, ukPrivBob, ukCredAlice,
		ukNegUnknownVersion, ukNegBadKTY, ukNegKidMismatch, ukNegNoncanonicalWS,
		ukNegRootArray, ukNegTruncated, "",
		ukNegDupMember, ukNegKeyReorder, ukNegEscapedMemberName, ukNegB64TrailingBits,
	} {
		f.Add([]byte(seed))
	}
	// The pinned private envelope must be refused by the server sink with
	// private_material_rejected (asserted once, deterministically).
	if _, err := userkey.ImportServerPublicEnvelope([]byte(ukPrivAlice)); err != nil {
		var je *jack.Error
		if !errors.As(err, &je) || je.Code != userkey.ClassPrivateMaterialRejected {
			panic("server sink did not reject the pinned private envelope with private_material_rejected: " + fmt.Sprint(err))
		}
	} else {
		panic("server sink accepted the pinned private envelope")
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		checkClass := func(err error) string {
			var je *jack.Error
			if !errors.As(err, &je) {
				t.Fatalf("error %v is not a *jack.Error", err)
			}
			if !ukKnownClass[je.Code] {
				t.Fatalf("rejection code %q is not an exported Class* constant", je.Code)
			}
			if je.HTTPStatus != 0 {
				t.Fatalf("rejection carries wire status %d: %q", je.HTTPStatus, je.Code)
			}
			if len(je.Message) > 200 {
				t.Fatalf("rejection message is %d bytes, want <= 200", len(je.Message))
			}
			return je.Code
		}

		// a) client public sink: verify-only identity.
		pub, errPub := userkey.ImportClientPublicEnvelope(data)
		if errPub != nil {
			checkClass(errPub)
		} else {
			key := pub.PublicKey()
			if len(key) != 32 || jack.ValidatePublicKey(key) != nil {
				t.Fatalf("accepted public identity holds a key that fails admission")
			}
			if pub.KID() != jack.KeyID(key) {
				t.Fatalf("accepted public identity kid is not jack.KeyID")
			}
			exported, err := pub.ExportPublicEnvelope()
			if err != nil {
				t.Fatalf("ExportPublicEnvelope: %v", err)
			}
			re, err := userkey.ImportClientPublicEnvelope(exported)
			if err != nil || re.KID() != pub.KID() {
				t.Fatalf("export did not re-import with the same kid: %v", err)
			}
			if _, err := pub.Sign([]byte("probe")); err == nil {
				t.Fatalf("public identity signed")
			} else {
				var je *jack.Error
				if !errors.As(err, &je) || je.Code != userkey.ClassNotPrivate {
					t.Fatalf("Sign error %v is not not_private", err)
				}
			}
			if !ukRedacted(pub, data) {
				t.Fatalf("public identity fmt output echoes the raw input")
			}
		}

		// b) client private sink: signer round trip.
		priv, errPriv := userkey.ImportClientPrivateEnvelope(data)
		if errPriv != nil {
			checkClass(errPriv)
		} else {
			sig, err := priv.Sign([]byte("probe"))
			if err != nil || !jack.Verify(priv.PublicKey(), []byte("probe"), sig) {
				t.Fatalf("accepted private envelope failed its sign/verify round trip: %v", err)
			}
			if priv.KID() != jack.KeyID(priv.PublicKey()) {
				t.Fatalf("accepted private identity kid is not jack.KeyID")
			}
			if !ukRedacted(priv, data) {
				t.Fatalf("client key fmt output echoes the raw input")
			}
			canonical, docPub, docKid, errDoc := ukCanonicalPrivateParts(data)
			if errDoc != nil || !bytes.Equal(data, canonical) {
				t.Fatalf("canonicality witness: accepted private envelope is not byte-equal to its independently composed canonical form")
			}
			if !bytes.Equal(priv.PublicKey(), docPub) || priv.KID() != docKid {
				t.Fatalf("identity witness: imported private key does not match the accepted document identity")
			}
		}

		// c) server public sink: same admission invariants, and the same
		// bytes can never also be a private envelope.
		server, errServer := userkey.ImportServerPublicEnvelope(data)
		if errServer != nil {
			checkClass(errServer)
		} else {
			key := server.PublicKey()
			if len(key) != 32 || jack.ValidatePublicKey(key) != nil {
				t.Fatalf("accepted server identity holds a key that fails admission")
			}
			if server.KID() != jack.KeyID(key) {
				t.Fatalf("accepted server identity kid is not jack.KeyID")
			}
			if _, err := userkey.ImportClientPrivateEnvelope(data); err == nil {
				t.Fatalf("server-sink bytes were also accepted as a private envelope")
			} else {
				checkClass(err)
			}
		}

		// Acceptance witnesses: the campaign must exercise the acceptance
		// path, and an accepted public envelope must round-trip byte-for-byte
		// through ExportPublicEnvelope (canonical input byte equality).
		if bytes.Equal(data, []byte(ukPubAlice)) && errPub != nil {
			t.Fatalf("acceptance witness: canonical public envelope rejected: %v", errPub)
		}
		if bytes.Equal(data, []byte(ukPrivAlice)) {
			if errPriv != nil {
				t.Fatalf("acceptance witness: canonical private envelope rejected: %v", errPriv)
			}
			// Canonical input-vs-expected bytes: ukComposePrivate is the
			// test-only composer written from the contract; its inputs (pinned
			// seed, the imported key's own kid and public key) are independent
			// of the accepted input bytes.
			expectedCanonical := ukComposePrivate(
				ukAliceSeedB64, priv.KID(), jack.EncodeBase64URL(priv.PublicKey()),
			)
			if !bytes.Equal(data, expectedCanonical) {
				t.Fatalf("canonicality witness: accepted private envelope is not byte-equal to the independently composed canonical envelope")
			}
		}
		if bytes.Equal(data, []byte(ukPubAlice)) && errServer != nil {
			t.Fatalf("acceptance witness: canonical public envelope rejected by the server sink: %v", errServer)
		}
		if pub != nil {
			exported, err := pub.ExportPublicEnvelope()
			if err != nil {
				t.Fatalf("acceptance witness: export: %v", err)
			}
			if !bytes.Equal(exported, data) {
				t.Fatalf("acceptance witness: accepted public envelope is not byte-equal to its canonical export")
			}
		}

		// Canonical-gate witnesses: the known noncanonical spellings must be
		// refused with the canonical class on their proper sink, so removing
		// the canonical-bytes gate fails the campaign. For the public sink the
		// accepted input must additionally be byte-equal to the canonical
		// export; for the private sink the pinned fixture ukPrivAlice IS the
		// known canonical document, so accepting it and refusing these
		// spellings pins input-vs-canonical equality on that role too.
		for _, noncanonical := range []struct {
			document []byte
			code     string
		}{
			{[]byte(ukNegNoncanonicalWS), userkey.ClassNonCanonicalBytes},
			{[]byte(ukNegDupMember), userkey.ClassNonCanonicalBytes},
			{[]byte(ukNegKeyReorder), userkey.ClassNonCanonicalBytes},
		} {
			if bytes.Equal(data, noncanonical.document) {
				_, errPrivNC := userkey.ImportClientPrivateEnvelope(data)
				var jeNC *jack.Error
				if errPrivNC == nil || !errors.As(errPrivNC, &jeNC) || jeNC.Code != noncanonical.code {
					t.Fatalf("canonicality witness: noncanonical private spelling accepted or misclassified: %v", errPrivNC)
				}
			}
		}
		for _, noncanonical := range []struct {
			document []byte
			code     string
		}{
			{[]byte(ukNegEscapedMemberName), userkey.ClassNonCanonicalBytes},
			{[]byte(ukNegB64TrailingBits), userkey.ClassBadEncoding},
		} {
			if bytes.Equal(data, noncanonical.document) {
				_, errPubNC := userkey.ImportClientPublicEnvelope(data)
				var jePC *jack.Error
				if errPubNC == nil || !errors.As(errPubNC, &jePC) || jePC.Code != noncanonical.code {
					t.Fatalf("canonicality witness: noncanonical public spelling accepted or misclassified: %v", errPubNC)
				}
				_, errSrvNC := userkey.ImportServerPublicEnvelope(data)
				var jeSC *jack.Error
				if errSrvNC == nil || !errors.As(errSrvNC, &jeSC) || jeSC.Code != noncanonical.code {
					t.Fatalf("canonicality witness: server sink misclassified noncanonical public spelling: %v", errSrvNC)
				}
			}
		}
	})
}

// FuzzValidateCredential pins the credential pipeline to one independently
// trusted server identity: ValidateCredential and ImportCredential agree on
// every input, the 4096-byte cap precedes any parsing, an accepted credential
// matches the trusted tuple exactly and signs and verifies, and no credential
// pinned to one identity ever validates against a different URL, audience or
// server key.
func FuzzValidateCredential(f *testing.F) {
	svc := ukSVCTuple("https://svc.example.test")
	altURL := svc
	altURL.URL = "https://other.example.test"
	altAud := svc
	altAud.Aud = "https://other.example.test"
	altKey := svc
	ident, err := userkey.ImportClientPublicEnvelope([]byte(ukPubAlice))
	if err != nil {
		panic(err)
	}
	altKey.ServerPublicKey = ident.PublicKey()
	altKey.ServerKID = jack.KeyID(ident.PublicKey())

	fresh := ukComposeCredSvc("https://svc.example.test", ukPrivAlice, ukSVCURL)
	corrupted := append([]byte(nil), fresh...)
	corrupted[0] ^= 0x01
	filler := bytes.Repeat([]byte{0x20}, 4097)

	for _, seed := range [][]byte{
		[]byte(ukCredAlice), []byte(ukCredBob), []byte(ukCredAudHTML),
		[]byte(ukNegCredUnknownVersion), []byte(ukNegCredUnknownType),
		[]byte(ukNegCredMissingServerKid), []byte(ukNegCredExtraServerPrivateKey),
		[]byte(ukNegCredServerKidMismatch), []byte(ukNegCredBadURL),
		[]byte(ukNegCredEmptyAud), []byte(ukNegCredClientKeyNoncanonical),
		[]byte(ukNegCredClientKeyPublic), []byte(ukNegEscapedURLSlash),
		fresh, corrupted, filler,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		errV := userkey.ValidateCredential(data, svc)
		cred, errI := userkey.ImportCredential(data, svc)

		// a) the validator and the importer agree.
		if (errV == nil) != (errI == nil) {
			t.Fatalf("ValidateCredential and ImportCredential disagree: %v vs %v", errV, errI)
		}
		if errV != nil && errI != nil {
			var jeV, jeI *jack.Error
			if !errors.As(errV, &jeV) || !errors.As(errI, &jeI) || jeV.Code != jeI.Code {
				t.Fatalf("rejection codes disagree: %v vs %v", errV, errI)
			}
		}

		// b) the size cap precedes any parsing.
		if len(data) > 4096 {
			if errV == nil {
				t.Fatalf("accepted a %d-byte credential", len(data))
			}
			var je *jack.Error
			if !errors.As(errV, &je) || je.Code != userkey.ClassOversizedEnvelope {
				t.Fatalf("oversized input rejected with %v, want oversized_envelope", errV)
			}
			return
		}

		// Acceptance witness: the fixture credential and the independently
		// composed fresh credential must be accepted. Canonical byte equality
		// and identity binding are asserted for EVERY accepted credential
		// from the document itself in section c, so a serializer or importer
		// regression cannot hide behind the known seeds.
		isCanonicalSeed := bytes.Equal(data, fresh) || bytes.Equal(data, []byte(ukCredAlice))
		if isCanonicalSeed && errV != nil {
			t.Fatalf("acceptance witness: canonical credential seed rejected: %v", errV)
		}

		// Rejection witnesses (unconditional, so an unwanted-acceptance
		// regression cannot bypass them by reaching the accepted path): the
		// known noncanonical credential spellings must fail with the canonical
		// class even though every decoded field would stay valid.
		isNoncanonical := bytes.Equal(data, []byte(ukNegCredClientKeyNoncanonical)) ||
			bytes.Equal(data, []byte(ukNegEscapedURLSlash))
		if isNoncanonical {
			if errV == nil {
				t.Fatalf("rejection witness: noncanonical credential accepted")
			}
			var jeNC *jack.Error
			if !errors.As(errV, &jeNC) || jeNC.Code != userkey.ClassNonCanonicalBytes {
				t.Fatalf("rejection witness: noncanonical credential rejected as %v, want non_canonical_bytes", errV)
			}
		}

		// e) every rejection is a bounded, status-free Class* error.
		if errV != nil {
			var je *jack.Error
			if !errors.As(errV, &je) {
				t.Fatalf("error %v is not a *jack.Error", errV)
			}
			if !ukKnownClass[je.Code] {
				t.Fatalf("rejection code %q is not an exported Class* constant", je.Code)
			}
			if je.HTTPStatus != 0 {
				t.Fatalf("local rejection carries wire status %d", je.HTTPStatus)
			}
			if len(je.Message) > 200 {
				t.Fatalf("rejection message is %d bytes, want <= 200", len(je.Message))
			}
			return
		}

		// c) an accepted credential matches the trusted tuple exactly.
		// Canonical input equality and document-identity binding for EVERY
		// accepted credential: the raw input must be byte-identical to the
		// test-only composer's output over the members the document itself
		// carries, and the imported signer/connection must be the keys the
		// document describes, not merely self-consistent ones.
		canonicalCred, credClientPub, credServerPub, errDoc := ukCanonicalCredentialParts(data)
		if errDoc != nil || !bytes.Equal(data, canonicalCred) {
			t.Fatalf("canonicality witness: accepted credential is not byte-equal to its independently composed canonical form")
		}
		if !bytes.Equal(cred.Signer.PublicKey(), credClientPub) {
			t.Fatalf("identity witness: imported credential signer does not match the accepted client key")
		}
		if !bytes.Equal(cred.Connection.ServerKey, credServerPub) {
			t.Fatalf("identity witness: imported credential connection does not match the accepted server key")
		}
		conn := cred.Connection
		if conn.BaseURL != svc.URL || conn.Aud != svc.Aud ||
			!bytes.Equal(conn.ServerKey, svc.ServerPublicKey) || conn.ServerKID != svc.ServerKID {
			t.Fatalf("accepted credential mismatched the trusted tuple")
		}
		sig, err := cred.Signer.Sign([]byte("probe"))
		if err != nil || !jack.Verify(cred.Signer.PublicKey(), []byte("probe"), sig) {
			t.Fatalf("accepted signer failed its sign/verify round trip: %v", err)
		}
		if cred.Signer.KID() != jack.KeyID(cred.Signer.PublicKey()) {
			t.Fatalf("accepted credential signer kid is not jack.KeyID")
		}

		// d) no credential pinned to one identity validates against another.
		for name, expected := range map[string]userkey.ExpectedIdentity{
			"altURL": altURL, "altAud": altAud, "altKey": altKey,
		} {
			err := userkey.ValidateCredential(data, expected)
			var je *jack.Error
			if err == nil || !errors.As(err, &je) || je.Code != userkey.ClassServerIdentityMismatch {
				t.Fatalf("credential accepted against %s: %v", name, err)
			}
		}
	})
}
