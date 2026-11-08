package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

const (
	maxIPCBytes     = 2 << 20
	maxMessages     = 16
	maxMessageBytes = 4096
	maxOperations   = 1024
)

type record map[string]json.RawMessage
type operationResult map[string]any

func fail() {
	_, _ = io.WriteString(os.Stderr, "interop-transfer: invalid request or SDK failure\n")
	os.Exit(1)
}

func onlyFields(r record, allowed ...string) error {
	for key := range r {
		found := false
		for _, name := range allowed {
			if key == name {
				found = true
				break
			}
		}
		if !found {
			return errors.New("invalid")
		}
	}
	return nil
}

func readRequest() (record, error) {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxIPCBytes+1))
	if err != nil || len(data) > maxIPCBytes {
		return nil, errors.New("invalid")
	}
	var request record
	if json.Unmarshal(data, &request) != nil || request == nil {
		return nil, errors.New("invalid")
	}
	if err := onlyFields(request, "operations"); err != nil {
		return nil, err
	}
	return request, nil
}

func rawString(object record, field string) (string, error) {
	raw, ok := object[field]
	if !ok {
		return "", errors.New("invalid")
	}
	var decoded any
	if json.Unmarshal(raw, &decoded) != nil {
		return "", errors.New("invalid")
	}
	value, ok := decoded.(string)
	if !ok {
		return "", errors.New("invalid")
	}
	return value, nil
}

func optionalString(object record, field string) string {
	var value any
	if json.Unmarshal(object[field], &value) != nil {
		return ""
	}
	text, _ := value.(string)
	return text
}

func expected(raw json.RawMessage) userkey.ExpectedIdentity {
	var members record
	if len(raw) != 0 {
		_ = json.Unmarshal(raw, &members)
	}
	publicKey, err := jack.DecodeBase64URLFixed(optionalString(members, "server_public_key"), userkey.PublicKeySize)
	if err != nil {
		publicKey = nil
	}
	return userkey.ExpectedIdentity{
		URL: optionalString(members, "url"), Aud: optionalString(members, "aud"),
		ServerPublicKey: publicKey, ServerKID: optionalString(members, "server_kid"),
	}
}

func decode(value string) ([]byte, error) { return jack.DecodeBase64URL(value) }

func messages(object record) ([][]byte, error) {
	raw, ok := object["messages_b64u"]
	if !ok {
		return nil, errors.New("invalid")
	}
	var encoded []string
	if json.Unmarshal(raw, &encoded) != nil || encoded == nil || len(encoded) > maxMessages {
		return nil, errors.New("invalid")
	}
	decoded := make([][]byte, 0, len(encoded))
	for _, item := range encoded {
		message, err := decode(item)
		if err != nil || len(message) > maxMessageBytes {
			return nil, errors.New("invalid")
		}
		decoded = append(decoded, message)
	}
	return decoded, nil
}

func transferClass(err error) (string, bool) {
	var sdkErr *jack.Error
	if errors.As(err, &sdkErr) && sdkErr != nil && sdkErr.Code != "" && isTransferClass(sdkErr.Code) {
		return sdkErr.Code, true
	}
	return "", false
}

func roleSurfaceHasPrivateTransfer(value any) bool {
	typ := reflect.TypeOf(value)
	if typ == nil {
		return true
	}
	for _, name := range []string{"Secret", "ExportSeed", "ExportPrivateEnvelope", "CredentialBytes"} {
		if _, ok := typ.MethodByName(name); ok {
			return true
		}
	}
	return false
}

func hasSignMethod(value any) bool {
	typ := reflect.TypeOf(value)
	if typ == nil {
		return true
	}
	_, found := typ.MethodByName("Sign")
	return found
}

func isTransferClass(class string) bool {
	switch class {
	case userkey.ClassMalformedJSON, userkey.ClassWrongRootType, userkey.ClassOversizedEnvelope,
		userkey.ClassUnknownVersion, userkey.ClassUnknownType, userkey.ClassBadMemberSet,
		userkey.ClassWrongFieldType, userkey.ClassBadEncoding, userkey.ClassBadURL,
		userkey.ClassInvalidPublicKey, userkey.ClassSeedPubMismatch, userkey.ClassKIDMismatch,
		userkey.ClassNonCanonicalBytes, userkey.ClassWrongEnvelopeType,
		userkey.ClassPrivateMaterialRejected, userkey.ClassNotPrivate,
		userkey.ClassServerIdentityMismatch:
		return true
	default:
		return false
	}
}
func failure(id json.RawMessage, err error) (operationResult, error) {
	if class, ok := transferClass(err); ok {
		return operationResult{"id": id, "ok": false, "class": class}, nil
	}
	return nil, errors.New("invalid")
}

func signerResult(id json.RawMessage, signer client.Signer, input [][]byte, connection *userkey.ConnectionConfig) (operationResult, error) {
	if roleSurfaceHasPrivateTransfer(signer) {
		return nil, errors.New("invalid")
	}
	publicKey := signer.PublicKey()
	envelope, err := userkey.ExportPublicEnvelope(signer)
	if err != nil {
		return failure(id, err)
	}
	signatures := make([]string, 0, len(input))
	for _, message := range input {
		signature, err := signer.Sign(message)
		if err != nil {
			return failure(id, err)
		}
		signatures = append(signatures, jack.EncodeBase64URL(signature))
	}
	result := operationResult{
		"id": id, "ok": true, "public_key": jack.EncodeBase64URL(publicKey),
		"kid": signer.KID(), "public_envelope_b64u": jack.EncodeBase64URL(envelope), "signatures_b64u": signatures,
	}
	if connection != nil {
		result["connection"] = map[string]string{
			"url": connection.BaseURL, "aud": connection.Aud,
			"server_public_key": jack.EncodeBase64URL(connection.ServerKey), "server_kid": connection.ServerKID,
		}
	}
	return result, nil
}

func runOperation(raw json.RawMessage) (operationResult, error) {
	var op record
	if json.Unmarshal(raw, &op) != nil || op == nil {
		return nil, errors.New("invalid")
	}
	id, ok := op["id"]
	if !ok || !json.Valid(id) {
		return nil, errors.New("invalid")
	}
	name, err := rawString(op, "op")
	if err != nil {
		return nil, err
	}
	allowed := []string{"id", "op"}
	switch name {
	case "issue":
		allowed = append(allowed, "seed_b64u", "expected")
	case "generate", "from-seed":
		allowed = append(allowed, "seed_b64u", "messages_b64u")
	case "import-private":
		allowed = append(allowed, "document_b64u", "messages_b64u")
	case "import-credential":
		allowed = append(allowed, "document_b64u", "expected", "messages_b64u")
	case "import-public":
		allowed = append(allowed, "document_b64u", "role", "verifications")
	case "validate-credential":
		allowed = append(allowed, "document_b64u", "expected")
	default:
		return nil, errors.New("invalid")
	}
	if err := onlyFields(op, allowed...); err != nil {
		return nil, err
	}

	switch name {
	case "issue":
		seedText, err := rawString(op, "seed_b64u")
		if err != nil {
			return nil, err
		}
		seed, err := jack.DecodeBase64URLFixed(seedText, userkey.SeedSize)
		if err != nil {
			return nil, errors.New("invalid")
		}
		trusted := expected(op["expected"])
		issued, err := userkey.IssueUserKey(trusted, bytes.NewReader(seed))
		if err != nil {
			return failure(id, err)
		}
		if roleSurfaceHasPrivateTransfer(issued.PublicIdentity) || hasSignMethod(issued.PublicIdentity) {
			return nil, errors.New("invalid")
		}
		original := issued.CredentialBytes()
		first, second := issued.CredentialBytes(), issued.CredentialBytes()
		publicBefore, kidBefore := issued.PublicIdentity.PublicKey(), issued.PublicIdentity.KID()
		imported, err := userkey.ImportCredential(original, trusted)
		if err != nil {
			return failure(id, err)
		}
		publicIdentity := imported.Signer.PublicKey()
		clientKID := imported.Signer.KID()
		signatureBefore, err := imported.Signer.Sign(nil)
		if err != nil {
			return nil, errors.New("invalid")
		}
		for i := range first {
			first[i] = 0
		}
		third := issued.CredentialBytes()
		signatureAfter, err := imported.Signer.Sign(nil)
		fresh := err == nil && len(first) > 0 && &first[0] != &second[0] && &second[0] != &third[0] &&
			bytes.Equal(original, second) && bytes.Equal(original, third) && bytes.Equal(signatureBefore, signatureAfter) &&
			bytes.Equal(publicIdentity, imported.Signer.PublicKey()) && clientKID == imported.Signer.KID() &&
			bytes.Equal(publicBefore, issued.PublicIdentity.PublicKey()) && kidBefore == issued.PublicIdentity.KID() &&
			bytes.Equal(publicBefore, publicIdentity) && kidBefore == clientKID
		if !fresh {
			return nil, errors.New("invalid")
		}
		return operationResult{"id": id, "ok": true, "credential_b64u": jack.EncodeBase64URL(third),
			"public_key": jack.EncodeBase64URL(publicBefore), "kid": kidBefore, "export_fresh": fresh}, nil

	case "generate", "from-seed", "import-private", "import-credential":
		input, err := messages(op)
		if err != nil {
			return nil, err
		}
		var signer client.Signer
		var connection *userkey.ConnectionConfig
		switch name {
		case "generate":
			signer, err = userkey.GenerateClientKey()
		case "from-seed":
			seedText, parseErr := rawString(op, "seed_b64u")
			if parseErr != nil {
				return nil, parseErr
			}
			seed, decodeErr := jack.DecodeBase64URLFixed(seedText, userkey.SeedSize)
			if decodeErr != nil {
				return nil, errors.New("invalid")
			}
			signer, err = client.NewInMemorySigner(seed)
		case "import-private":
			documentText, parseErr := rawString(op, "document_b64u")
			if parseErr != nil {
				return nil, parseErr
			}
			document, decodeErr := decode(documentText)
			if decodeErr != nil {
				return nil, errors.New("invalid")
			}
			signer, err = userkey.ImportClientPrivateEnvelope(document)
		case "import-credential":
			documentText, parseErr := rawString(op, "document_b64u")
			if parseErr != nil {
				return nil, parseErr
			}
			document, decodeErr := decode(documentText)
			if decodeErr != nil {
				return nil, errors.New("invalid")
			}
			before := append([]byte(nil), document...)
			trusted := expected(op["expected"])
			trustedBefore := trusted
			trustedBefore.ServerPublicKey = append([]byte(nil), trusted.ServerPublicKey...)
			imported, importErr := userkey.ImportCredential(document, trusted)
			if !bytes.Equal(document, before) || trusted.URL != trustedBefore.URL || trusted.Aud != trustedBefore.Aud || trusted.ServerKID != trustedBefore.ServerKID || !bytes.Equal(trusted.ServerPublicKey, trustedBefore.ServerPublicKey) {
				return nil, errors.New("invalid")
			}
			if importErr != nil {
				return failure(id, importErr)
			}
			signer = imported.Signer
			connectionCopy := imported.Connection
			connection = &connectionCopy
		}
		if err != nil {
			return failure(id, err)
		}
		if signer == nil {
			return nil, errors.New("invalid")
		}
		return signerResult(id, signer, input, connection)

	case "import-public":
		documentText, err := rawString(op, "document_b64u")
		if err != nil {
			return nil, err
		}
		document, err := decode(documentText)
		if err != nil {
			return nil, errors.New("invalid")
		}
		role, err := rawString(op, "role")
		if err != nil || (role != "client" && role != "server") {
			return nil, errors.New("invalid")
		}
		var input []map[string]json.RawMessage
		if raw, exists := op["verifications"]; exists {
			if json.Unmarshal(raw, &input) != nil || len(input) > maxMessages {
				return nil, errors.New("invalid")
			}
		} else {
			input = make([]map[string]json.RawMessage, 0)
		}
		checks := make([]struct{ message, signature []byte }, 0, len(input))
		for _, pair := range input {
			if err := onlyFields(pair, "message_b64u", "signature_b64u"); err != nil {
				return nil, err
			}
			messageText, err := rawString(pair, "message_b64u")
			if err != nil {
				return nil, err
			}
			signatureText, err := rawString(pair, "signature_b64u")
			if err != nil {
				return nil, err
			}
			message, err := decode(messageText)
			if err != nil || len(message) > maxMessageBytes {
				return nil, errors.New("invalid")
			}
			signature, err := decode(signatureText)
			if err != nil || len(signature) > maxMessageBytes {
				return nil, errors.New("invalid")
			}
			checks = append(checks, struct{ message, signature []byte }{message, signature})
		}
		verified := make([]bool, 0, len(checks))
		var publicKey []byte
		var kid string
		if role == "client" {
			identity, err := userkey.ImportClientPublicEnvelope(document)
			if err != nil {
				return failure(id, err)
			}
			publicKey, kid = identity.PublicKey(), identity.KID()
			for _, forbidden := range []string{"Secret", "ExportSeed", "ExportPrivateEnvelope", "CredentialBytes"} {
				if _, exists := reflect.TypeOf(identity).MethodByName(forbidden); exists {
					return nil, errors.New("invalid")
				}
			}
			_, signErr := identity.Sign(nil)
			class, ok := transferClass(signErr)
			if signErr == nil || !ok || class != userkey.ClassNotPrivate {
				return nil, errors.New("invalid")
			}
			for _, check := range checks {
				verified = append(verified, identity.Verify(check.message, check.signature))
			}
		} else {
			identity, err := userkey.ImportServerPublicEnvelope(document)
			if err != nil {
				return failure(id, err)
			}
			if roleSurfaceHasPrivateTransfer(identity) {
				return nil, errors.New("invalid")
			}
			publicKey, kid = identity.PublicKey(), identity.KID()
			for _, check := range checks {
				verified = append(verified, identity.Verify(check.message, check.signature))
			}
		}
		return operationResult{"id": id, "ok": true, "public_key": jack.EncodeBase64URL(publicKey), "kid": kid, "public_only": true, "verification_results": verified}, nil

	case "validate-credential":
		documentText, err := rawString(op, "document_b64u")
		if err != nil {
			return nil, err
		}
		document, err := decode(documentText)
		if err != nil {
			return nil, errors.New("invalid")
		}
		if err := userkey.ValidateCredential(document, expected(op["expected"])); err != nil {
			return failure(id, err)
		}
		return operationResult{"id": id, "ok": true}, nil
	}
	return nil, errors.New("invalid")
}

func main() {
	request, err := readRequest()
	if err != nil {
		fail()
	}
	operationsRaw, exists := request["operations"]
	if !exists {
		fail()
	}
	var operations []json.RawMessage
	if json.Unmarshal(operationsRaw, &operations) != nil || operations == nil || len(operations) > maxOperations {
		fail()
	}
	results := make([]operationResult, 0, len(operations))
	for _, operation := range operations {
		result, err := runOperation(operation)
		if err != nil {
			fail()
		}
		results = append(results, result)
	}
	output, err := json.Marshal(map[string]any{"results": results})
	if err != nil || len(output)+1 > maxIPCBytes {
		fail()
	}
	if _, err := os.Stdout.Write(append(output, '\n')); err != nil {
		fail()
	}
}
