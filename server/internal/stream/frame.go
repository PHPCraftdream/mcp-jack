package stream

import (
	"crypto/rand"
	"strconv"
	"strings"

	jack "github.com/PHPCraftdream/mcp-jack"
)

const (
	// OpenDomain is the first line of the 2.5 open signing string.
	OpenDomain = "mcp-jack/stream1/open"
	// FrameDomain is the first line of the 2.15 frame signing string.
	FrameDomain = "mcp-jack/stream1/frame"
	// SignalMethod is the JSON-RPC method of the 2.18 transport signal frame.
	SignalMethod = "notifications/jack/stream_error"
	// SignalFrameTooLarge is the one signalled code of 2.18 (4.6).
	SignalFrameTooLarge = "stream_frame_too_large"
	// MessageEvent is the event name of a message frame (2.6).
	MessageEvent = "message"
	// EndEvent is the event name of the end frame (2.16).
	EndEvent = "jack-end"
)

// Key is the signing capability of one stream (3.1): the open header and every
// frame use this key and no other.
type Key struct {
	Kid       string
	PublicKey []byte
	// Sign returns the raw 64-byte Ed25519 signature of message; this package
	// encodes it as canonical unpadded base64url wherever the wire needs a
	// string (2.5, 2.15).
	Sign func(message []byte) ([]byte, error)
	// Cutoff is the successor activation A known for this key (5.1); no frame
	// may carry a ts at or after it. Nil means no successor is known.
	Cutoff *int64
}

// OpenSigningString is the 2.5 open signing string: six lines joined with a
// single LF and no trailing LF.
func OpenSigningString(status int, requestSig, kid string, ts int64, sid string) string {
	return strings.Join([]string{
		OpenDomain,
		strconv.Itoa(status),
		requestSig,
		kid,
		strconv.FormatInt(ts, 10),
		sid,
	}, "\n")
}

// FrameSigningString is the 2.15 frame signing string: six lines joined with a
// single LF and no trailing LF.
func FrameSigningString(sid string, seq uint64, ts int64, prev, hash string) string {
	return strings.Join([]string{
		FrameDomain,
		sid,
		strconv.FormatUint(seq, 10),
		strconv.FormatInt(ts, 10),
		prev,
		hash,
	}, "\n")
}

// DataHash is base64url(SHA-256(data value)) of 2.15, over the UTF-8 bytes of
// the data value.
func DataHash(data []byte) string { return jack.BodyHash(data) }

// FormatOpenValue builds the 2.1 Jack-Auth value with the parameter order of
// 2.2.
func FormatOpenValue(kid string, ts int64, sid, sig string) string {
	return "s1 kid=" + kid + ",ts=" + strconv.FormatInt(ts, 10) + ",sid=" + sid + ",sig=" + sig
}

// SignalValue builds the exact 2.18 transport signal object for code and limit.
func SignalValue(code string, limit int64) string {
	return `{"jsonrpc":"2.0","method":"` + SignalMethod + `","params":{"code":"` + code +
		`","limit":` + strconv.FormatInt(limit, 10) + `}}`
}

// EncodeFrame returns the event bytes of 2.6 and 2.16: LF only, one data line
// per LF-separated piece and a trailing blank line.
func EncodeFrame(kind, data string, seq uint64, ts int64, sig string) []byte {
	var b strings.Builder
	b.WriteString("event: ")
	b.WriteString(kind)
	b.WriteByte('\n')
	for _, piece := range strings.Split(data, "\n") {
		if piece == "" {
			b.WriteString("data:\n")
		} else {
			b.WriteString("data: ")
			b.WriteString(piece)
			b.WriteByte('\n')
		}
	}
	b.WriteString("jack: seq=")
	b.WriteString(strconv.FormatUint(seq, 10))
	b.WriteString(",ts=")
	b.WriteString(strconv.FormatInt(ts, 10))
	b.WriteString(",sig=")
	b.WriteString(sig)
	b.WriteString("\n\n")
	return []byte(b.String())
}

// NewSID returns a fresh sid of 2.4: 16 bytes from crypto/rand, base64url.
func NewSID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return jack.EncodeBase64URL(raw[:]), nil
}
