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
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
	"github.com/PHPCraftdream/mcp-jack/userkey"
)

// Compile-time signer bridge assertions (docs/design/user-keys.md row 10).
var (
	_ client.Signer  = (*userkey.ClientKey)(nil)
	_ userkey.Signer = (*userkey.ClientKey)(nil)
)

// Pinned oracle values from spec/fixtures/keys.json (independent test-only
// vectors; seeds are sha256("mcp-jack test key: <name>")).
const (
	ukAliceSeedHex = "15949421ee8241acde219c4cff93cc346a0488e049deff61da312798b758d28f"
	ukAlicePubB64  = "kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"
	ukAliceKid     = "TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs"

	ukBobSeedHex = "7eb4f89033dfe79db5a8fdaa667361b768722d619b62f531fba0cae9714a351b"
	ukBobPubB64  = "27O5sjd6_PRkCVbNLwEbIwxpfh0DZCURwFI9lWF-UHE"
	ukBobKid     = "g1T9GIZg0cumv7-IsIzIcKz9DRzv_zxZQLOnHSI4Rns"

	ukCarolSeedHex = "50d2c03eab0770775c84772e131000ba021d8a1716629b068a85b273cca17fbb"
	ukCarolPubB64  = "r1DLsXDIaAY-rmPFCzV9dgAxes6dpdXkOrJNHiFkQl4"
	ukCarolKid     = "bu9N_ld9z81i0mvxfKO0bgHdiYjZx7jBF8sd8DTo9gc"

	ukErinSeedHex = "8e1f127a749e6caa8bec33e8fe1d685b1327e35a38307f31b8960f5a5db85aa6"
	ukErinPubB64  = "axZb1B_q1F6s3zc6V0glCNJMJJSHy-nrRRRJwPFU3rY"
	ukErinKid     = "EO02KVTMv4Y2l4PhmwUsLHNMcdRTCoMClOs-tP6TO68"

	// The server identity stand-in shared by every credential fixture.
	ukSVCPubB64 = "wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw"
	ukSVCKid    = "wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88"
	ukSVCURL    = "https://svc.example.test"
)

// RFC 8032 section 7.1 vectors and the RFC 8037 appendix A.1 JWK encodings
// of the TEST 1 key: standards oracles independent of every fixture.
const (
	ukRFC1SeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	ukRFC1PubHex  = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	ukRFC1DB64    = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	ukRFC1XB64    = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	ukRFC1SigHex  = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

	ukRFC3SeedHex = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
	ukRFC3PubHex  = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
	ukRFC3MsgHex  = "af82"
	ukRFC3SigHex  = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
)

// Invalid public-key encodings from spec/fixtures/key-vectors.json (the
// generated normative rejection oracle).
const (
	ukRejectYAbovePHex  = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	ukRejectIdentityHex = "0100000000000000000000000000000000000000000000000000000000000000"
	ukRejectOrder2Hex   = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
	ukRejectOffCurveHex = "0200000000000000000000000000000000000000000000000000000000000000"
)

// Canonical positive envelopes, embedded as literals from
// spec/fixtures/user-key-transfer.json (hand-maintained shared test table).
const (
	ukPubAlice  = `{"crv":"Ed25519","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/public","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"}`
	ukPrivAlice = `{"crv":"Ed25519","d":"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/private","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"}`
	ukPubBob    = `{"crv":"Ed25519","kid":"g1T9GIZg0cumv7-IsIzIcKz9DRzv_zxZQLOnHSI4Rns","kty":"OKP","type":"user-key/public","v":1,"x":"27O5sjd6_PRkCVbNLwEbIwxpfh0DZCURwFI9lWF-UHE"}`
	ukPrivBob   = `{"crv":"Ed25519","d":"frT4kDPf5521qP2qZnNht2hyLWGbYvUx-6DK6XFKNRs","kid":"g1T9GIZg0cumv7-IsIzIcKz9DRzv_zxZQLOnHSI4Rns","kty":"OKP","type":"user-key/private","v":1,"x":"27O5sjd6_PRkCVbNLwEbIwxpfh0DZCURwFI9lWF-UHE"}`
	ukPubCarol  = `{"crv":"Ed25519","kid":"bu9N_ld9z81i0mvxfKO0bgHdiYjZx7jBF8sd8DTo9gc","kty":"OKP","type":"user-key/public","v":1,"x":"r1DLsXDIaAY-rmPFCzV9dgAxes6dpdXkOrJNHiFkQl4"}`
	ukPrivCarol = `{"crv":"Ed25519","d":"UNLAPqsHcHdchHcuExAAugIdihcWYpsGioWyc8yhf7s","kid":"bu9N_ld9z81i0mvxfKO0bgHdiYjZx7jBF8sd8DTo9gc","kty":"OKP","type":"user-key/private","v":1,"x":"r1DLsXDIaAY-rmPFCzV9dgAxes6dpdXkOrJNHiFkQl4"}`

	ukCredAlice = `{"aud":"https://svc.example.test","client_key":"{\"crv\":\"Ed25519\",\"d\":\"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8\",\"kid\":\"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs\",\"kty\":\"OKP\",\"type\":\"user-key/private\",\"v\":1,\"x\":\"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE\"}","server_kid":"wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88","server_public_key":"wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw","type":"user-key/credential/client","url":"https://svc.example.test","v":1}`
	ukCredBob   = `{"aud":"https://svc.example.test","client_key":"{\"crv\":\"Ed25519\",\"d\":\"frT4kDPf5521qP2qZnNht2hyLWGbYvUx-6DK6XFKNRs\",\"kid\":\"g1T9GIZg0cumv7-IsIzIcKz9DRzv_zxZQLOnHSI4Rns\",\"kty\":\"OKP\",\"type\":\"user-key/private\",\"v\":1,\"x\":\"27O5sjd6_PRkCVbNLwEbIwxpfh0DZCURwFI9lWF-UHE\"}","server_kid":"wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88","server_public_key":"wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw","type":"user-key/credential/client","url":"https://svc.example.test","v":1}`

	ukCredAudHTML = `{"aud":"a<b>&c","client_key":"{\"crv\":\"Ed25519\",\"d\":\"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8\",\"kid\":\"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs\",\"kty\":\"OKP\",\"type\":\"user-key/private\",\"v\":1,\"x\":\"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE\"}","server_kid":"wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88","server_public_key":"wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw","type":"user-key/credential/client","url":"https://svc.example.test","v":1}`
)

// Literal negative envelopes from spec/fixtures/user-key-transfer.json.
const (
	ukNegUnknownVersion          = `{"crv":"Ed25519","d":"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/private","v":2,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"}`
	ukNegUnknownType             = `{"crv":"Ed25519","d":"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/secret","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"}`
	ukNegBadKTY                  = `{"crv":"Ed25519","d":"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"EC","type":"user-key/private","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"}`
	ukNegBadCRV                  = `{"crv":"Ed448","d":"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/private","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"}`
	ukNegUnknownField            = `{"crv":"Ed25519","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/public","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE","comment":"hi"}`
	ukNegMissingKid              = `{"crv":"Ed25519","kty":"OKP","type":"user-key/public","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"}`
	ukNegWrongFieldType          = `{"crv":"Ed25519","kid":123,"kty":"OKP","type":"user-key/public","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"}`
	ukNegNullField               = `{"crv":"Ed25519","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/public","v":1,"x":null}`
	ukNegEmptyD                  = `{"crv":"Ed25519","d":"","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/private","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"}`
	ukNegB64Padding              = `{"crv":"Ed25519","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/public","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE="}`
	ukNegB64Char                 = `{"crv":"Ed25519","kid":"TXF9TkhWm+UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/public","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"}`
	ukNegEscapedMemberName       = `{"\u0063rv":"Ed25519","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/public","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"}`
	ukNegLenShort                = `{"crv":"Ed25519","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/public","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJ"}`
	ukNegLenLong                 = `{"crv":"Ed25519","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNsA","kty":"OKP","type":"user-key/public","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"}`
	ukNegB64TrailingBits         = `{"crv":"Ed25519","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/public","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJF"}`
	ukNegSeedPubMismatch         = `{"crv":"Ed25519","d":"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8","kid":"g1T9GIZg0cumv7-IsIzIcKz9DRzv_zxZQLOnHSI4Rns","kty":"OKP","type":"user-key/private","v":1,"x":"27O5sjd6_PRkCVbNLwEbIwxpfh0DZCURwFI9lWF-UHE"}`
	ukNegKidMismatch             = `{"crv":"Ed25519","d":"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8","kid":"g1T9GIZg0cumv7-IsIzIcKz9DRzv_zxZQLOnHSI4Rns","kty":"OKP","type":"user-key/private","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"}`
	ukNegDupMember               = `{"crv":"Ed25519","d":"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/private","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs"}`
	ukNegDupMemberLastMismatched = `{"crv":"Ed25519","d":"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/private","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE","kid":"g1T9GIZg0cumv7-IsIzIcKz9DRzv_zxZQLOnHSI4Rns"}`
	ukNegDupMemberEscaped        = `{"crv":"Ed25519","d":"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/private","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE","\u006b\u0069\u0064":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs"}`
	ukNegNoncanonicalWS          = `{ "crv":"Ed25519","d":"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/private","v":1,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"}`
	ukNegKeyReorder              = `{"type":"user-key/private","v":1,"crv":"Ed25519","d":"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"}`
	ukNegTruncated               = `{"crv":"Ed25519","d":"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o`
	ukNegRootArray               = `[]`
	ukNegRootString              = `"user-key/private"`
	ukNegNullInput               = `null`
	ukNegVFloat                  = `{"crv":"Ed25519","d":"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8","kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","kty":"OKP","type":"user-key/private","v":1.0,"x":"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE"}`

	ukNegCredUnknownVersion        = `{"aud":"https://svc.example.test","client_key":"{\"crv\":\"Ed25519\",\"d\":\"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8\",\"kid\":\"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs\",\"kty\":\"OKP\",\"type\":\"user-key/private\",\"v\":1,\"x\":\"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE\"}","server_kid":"wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88","server_public_key":"wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw","type":"user-key/credential/client","url":"https://svc.example.test","v":2}`
	ukNegCredUnknownType           = `{"aud":"https://svc.example.test","client_key":"{\"crv\":\"Ed25519\",\"d\":\"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8\",\"kid\":\"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs\",\"kty\":\"OKP\",\"type\":\"user-key/private\",\"v\":1,\"x\":\"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE\"}","server_kid":"wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88","server_public_key":"wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw","type":"user-key/credential/server","url":"https://svc.example.test","v":1}`
	ukNegCredMissingServerKid      = `{"aud":"https://svc.example.test","client_key":"{\"crv\":\"Ed25519\",\"d\":\"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8\",\"kid\":\"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs\",\"kty\":\"OKP\",\"type\":\"user-key/private\",\"v\":1,\"x\":\"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE\"}","server_public_key":"wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw","type":"user-key/credential/client","url":"https://svc.example.test","v":1}`
	ukNegCredExtraServerPrivateKey = `{"aud":"https://svc.example.test","client_key":"{\"crv\":\"Ed25519\",\"d\":\"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8\",\"kid\":\"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs\",\"kty\":\"OKP\",\"type\":\"user-key/private\",\"v\":1,\"x\":\"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE\"}","server_kid":"wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88","server_public_key":"wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw","type":"user-key/credential/client","url":"https://svc.example.test","v":1,"server_private_key":"27O5sjd6_PRkCVbNLwEbIwxpfh0DZCURwFI9lWF-UHE"}`
	ukNegCredServerKidMismatch     = `{"aud":"https://svc.example.test","client_key":"{\"crv\":\"Ed25519\",\"d\":\"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8\",\"kid\":\"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs\",\"kty\":\"OKP\",\"type\":\"user-key/private\",\"v\":1,\"x\":\"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE\"}","server_kid":"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs","server_public_key":"wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw","type":"user-key/credential/client","url":"https://svc.example.test","v":1}`
	ukNegCredBadURL                = `{"aud":"https://svc.example.test","client_key":"{\"crv\":\"Ed25519\",\"d\":\"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8\",\"kid\":\"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs\",\"kty\":\"OKP\",\"type\":\"user-key/private\",\"v\":1,\"x\":\"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE\"}","server_kid":"wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88","server_public_key":"wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw","type":"user-key/credential/client","url":"http://svc.example.test","v":1}`
	ukNegCredEmptyAud              = `{"aud":"","client_key":"{\"crv\":\"Ed25519\",\"d\":\"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8\",\"kid\":\"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs\",\"kty\":\"OKP\",\"type\":\"user-key/private\",\"v\":1,\"x\":\"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE\"}","server_kid":"wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88","server_public_key":"wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw","type":"user-key/credential/client","url":"https://svc.example.test","v":1}`
	ukNegEscapedURLSlash           = `{"aud":"https://svc.example.test","client_key":"{\"crv\":\"Ed25519\",\"d\":\"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8\",\"kid\":\"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs\",\"kty\":\"OKP\",\"type\":\"user-key/private\",\"v\":1,\"x\":\"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE\"}","server_kid":"wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88","server_public_key":"wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw","type":"user-key/credential/client","url":"https:\/\/svc.example.test","v":1}`
	ukNegCredClientKeyNoncanonical = `{"aud":"https://svc.example.test","client_key":"{ \"crv\":\"Ed25519\",\"d\":\"FZSUIe6CQazeIZxM_5PMNGoEiOBJ3v9h2jEnmLdY0o8\",\"kid\":\"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs\",\"kty\":\"OKP\",\"type\":\"user-key/private\",\"v\":1,\"x\":\"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE\"}","server_kid":"wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88","server_public_key":"wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw","type":"user-key/credential/client","url":"https://svc.example.test","v":1}`
	ukNegCredClientKeyPublic       = `{"aud":"https://svc.example.test","client_key":"{\"crv\":\"Ed25519\",\"kid\":\"TXF9TkhWm8UNPD-pk0NiJtux3ecJ69fMW8J9_YBDGNs\",\"kty\":\"OKP\",\"type\":\"user-key/public\",\"v\":1,\"x\":\"kelVoYoxb3XSb-kFkOMEZNQ_x6GUFJNgdI2RjrsdgJE\"}","server_kid":"wltl591LbtvQV2vee3U5IpVRhqVxpnEeuh1NZh_mL88","server_public_key":"wjtM7aRy1vnp-ZPuyY_99ncsbRVv28vGJTIZzFXvOMw","type":"user-key/credential/client","url":"https://svc.example.test","v":1}`
)

// ukJCSQuote is the test-only independent canonical JSON string emitter
// (docs/design/user-keys.md section 4 rules), written from the contract text
// rather than calling any production serializer.
func ukJCSQuote(value string) string {
	var out bytes.Buffer
	out.WriteByte('"')
	for _, r := range value {
		switch {
		case r == '"' || r == '\\':
			out.WriteByte('\\')
			out.WriteRune(r)
		case r == '\b':
			out.WriteString(`\b`)
		case r == '\t':
			out.WriteString(`\t`)
		case r == '\n':
			out.WriteString(`\n`)
		case r == '\f':
			out.WriteString(`\f`)
		case r == '\r':
			out.WriteString(`\r`)
		case r >= 0x00 && r <= 0x1f:
			out.WriteString(fmt.Sprintf(`\u%04x`, r))
		default:
			out.WriteRune(r)
		}
	}
	out.WriteByte('"')
	return out.String()
}

func ukComposePublic(xB64, kid string) []byte {
	return []byte(`{"crv":"Ed25519","kid":"` + kid + `","kty":"OKP","type":"user-key/public","v":1,"x":"` + xB64 + `"}`)
}

func ukComposePrivate(dB64, kid, xB64 string) []byte {
	return []byte(`{"crv":"Ed25519","d":"` + dB64 + `","kid":"` + kid + `","kty":"OKP","type":"user-key/private","v":1,"x":"` + xB64 + `"}`)
}

// ukComposeCred builds a canonical credential with the svc identity stand-in.
// audJSON and urlJSON are raw pre-quoted JSON string tokens so the surrogate
// compositions can inject escape spellings.
func ukComposeCred(audJSON, clientKey, serverKid, serverPubB64, urlJSON string) []byte {
	return []byte(`{"aud":` + audJSON +
		`,"client_key":` + ukJCSQuote(clientKey) +
		`,"server_kid":"` + serverKid +
		`","server_public_key":"` + serverPubB64 +
		`","type":"user-key/credential/client","url":` + urlJSON +
		`,"v":1}`)
}

func ukComposeCredSvc(aud, clientKey, url string) []byte {
	return ukComposeCred(ukJCSQuote(aud), clientKey, ukSVCKid, ukSVCPubB64, ukJCSQuote(url))
}

// ukEnvelopeD extracts the d member of the envelope actually under test and
// decodes it to exactly 32 raw bytes, so the comparison pins the oracle seed
// against the tested artifact itself (docs/design/user-keys.md section 11).
func ukEnvelopeD(t *testing.T, envelope []byte) []byte {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(envelope, &doc); err != nil {
		t.Fatalf("envelope parse for d extraction: %v", err)
	}
	raw, ok := doc["d"]
	if !ok {
		t.Fatalf("envelope has no d member")
	}
	var dString string
	if err := json.Unmarshal(raw, &dString); err != nil {
		t.Fatalf("d member is not a string")
	}
	decoded, err := jack.DecodeBase64URLFixed(dString, userkey.PublicKeySize)
	if err != nil {
		t.Fatalf("d decode: %v", err)
	}
	return decoded
}

func ukHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

func ukB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := jack.DecodeBase64URLFixed(s, 32)
	if err != nil {
		t.Fatalf("base64url decode: %v", err)
	}
	return b
}

func ukSVCPub(t *testing.T) []byte {
	t.Helper()
	return ukB64(t, ukSVCPubB64)
}

func ukSVCTuple(aud string) userkey.ExpectedIdentity {
	return userkey.ExpectedIdentity{
		URL:             ukSVCURL,
		Aud:             aud,
		ServerPublicKey: ukSVCPubB64Bytes,
		ServerKID:       ukSVCKid,
	}
}

// ukSVCPubB64Bytes is the decoded pinned svc public key (computed once,
// deterministically, from the pinned literal).
var ukSVCPubB64Bytes = func() []byte {
	b, err := jack.DecodeBase64URLFixed(ukSVCPubB64, 32)
	if err != nil {
		panic(err)
	}
	return b
}()

func ukExpectClass(t *testing.T, err error, class string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	var je *jack.Error
	if !errors.As(err, &je) {
		t.Fatalf("error is not *jack.Error: %v", err)
	}
	if je.Code != class {
		t.Fatalf("error class = %q, want %q", je.Code, class)
	}
	if je.HTTPStatus != 0 {
		t.Fatalf("error HTTPStatus = %d, want 0", je.HTTPStatus)
	}
}

func ukExpectOK(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

// ukRunesEqual compares decoded audience values by Unicode scalar sequence
// (never by raw escape spelling, and never printed in failure text).
func ukRunesEqual(a, b string) bool {
	ra := []rune(a)
	rb := []rune(b)
	if len(ra) != len(rb) {
		return false
	}
	for i := range ra {
		if ra[i] != rb[i] {
			return false
		}
	}
	return true
}

func ukDecimalRun(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, " ")
}

// Audiences for the composed aud-positive credential cases; integers in the
// fixture's aud_codepoints are Unicode scalars, single-character strings are
// that character, concatenated in order.
var (
	ukAudCodepoints  = "\u00e9\U0001F600" // 233, 128512
	ukAudControl     = "a\x01z"           // "a", 1, "z"
	ukAudSeparators  = "a\u2028b\u2029"   // "a", 8232, "b", 8233
	ukAudReplacement = "a\uFFFDb"         // "a", 65533, "b"
	ukAudHTML        = "a<b>&c"
)

func ukComposeRFC1Private(t *testing.T) []byte {
	t.Helper()
	seed := ukHex(t, ukRFC1SeedHex)
	pub := ukHex(t, ukRFC1PubHex)
	// The runner's own base64url encodings MUST equal the RFC 8037 A.1 strings.
	if got := jack.EncodeBase64URL(seed); got != ukRFC1DB64 {
		t.Fatalf("seed base64url does not equal the RFC 8037 A.1 d constant")
	}
	if got := jack.EncodeBase64URL(pub); got != ukRFC1XB64 {
		t.Fatalf("public base64url = %q, want RFC 8037 A.1 x", got)
	}
	return ukComposePrivate(ukRFC1DB64, jack.KeyID(pub), ukRFC1XB64)
}

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
