package userkey_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

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
