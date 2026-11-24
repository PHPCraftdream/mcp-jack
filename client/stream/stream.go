// Package stream provides the client side of the signed streams (s1) profile
// of MCP 2026-07-28 (spec 05-signed-streams.md, section 4).
//
// It verifies the open header and every frame before handing a data value on,
// keeps the thirteen client codes of section 4.6 as a closed set, and never
// parses the MCP layer: a verified data value is returned as exact bytes and
// its meaning is the caller's business. Nothing here changes the mcp-jack/v1
// wire bytes.
//
// The package is a thin public facade over the implementation in
// github.com/PHPCraftdream/mcp-jack/client/internal/stream: every type is an
// alias and every function is a one-line wrapper, so the two packages share
// exactly the same values.
package stream

import impl "github.com/PHPCraftdream/mcp-jack/client/internal/stream"

// Code is one closed section 4.6 stream verification code.
type Code = impl.Code

// The closed set of the thirteen client codes of section 4.6.
const (
	// MissingAuth reports an answer without a Jack-Auth open header.
	MissingAuth = impl.MissingAuth
	// MalformedAuth reports an open header or frame that does not parse.
	MalformedAuth = impl.MalformedAuth
	// UnsupportedVersion reports an s1 version this client does not know.
	UnsupportedVersion = impl.UnsupportedVersion
	// UnknownServerKey reports an open header signed by an unpinned key.
	UnknownServerKey = impl.UnknownServerKey
	// OutOfWindow reports a timestamp outside the acceptance window.
	OutOfWindow = impl.OutOfWindow
	// BadSignature reports a signature that does not verify.
	BadSignature = impl.BadSignature
	// BadFrame reports a frame that fails the frame grammar or its checks.
	BadFrame = impl.BadFrame
	// OutOfOrder reports a sequence number out of order.
	OutOfOrder = impl.OutOfOrder
	// StaleFrame reports a frame older than the freshness bound.
	StaleFrame = impl.StaleFrame
	// Truncated reports a stream that ended before its final frame.
	Truncated = impl.Truncated
	// Idle reports a stream that exceeded the idle timeout.
	Idle = impl.Idle
	// FrameTooLarge reports a data value above the frame cap.
	FrameTooLarge = impl.FrameTooLarge
	// AfterCutoff reports a frame signed after a known key cutoff.
	AfterCutoff = impl.AfterCutoff
)

// Codes returns the closed set of the thirteen client codes in section 4.6
// order.
func Codes() []Code { return impl.Codes() }

// Error is a stream verification failure carrying a Code.
type Error = impl.Error

// Header is one HTTP header of an answer.
type Header = impl.Header

// Key is a rotation-known server key with its activation metadata.
type Key = impl.Key

// Consumer names the layer that consumes a verified data value.
type Consumer = impl.Consumer

// The closed consumer vocabulary.
const (
	// ConsumerMCP consumes a verified data value as an MCP message.
	ConsumerMCP = impl.ConsumerMCP
	// ConsumerStdio consumes a verified data value as a stdio message.
	ConsumerStdio = impl.ConsumerStdio
)

// Expectation is what the caller knows about the answer before verifying it.
type Expectation = impl.Expectation

// Result is the outcome of verifying a whole stream.
type Result = impl.Result

// Verifier verifies an open header and then the frames of one stream.
type Verifier = impl.Verifier

// NewVerifier returns a Verifier for exp.
func NewVerifier(exp Expectation) (*Verifier, error) { return impl.NewVerifier(exp) }

// Verify verifies a whole stream from its status, headers and chunks.
func Verify(exp Expectation, status int, headers []Header, chunks [][]byte) (Result, error) {
	return impl.Verify(exp, status, headers, chunks)
}

// ClientConfig is the caller's signed-stream configuration. Set Consumer to
// ConsumerStdio to reject verified message data containing raw CR or LF; the
// zero value selects ConsumerMCP.
type ClientConfig = impl.ClientConfig

// Stream is one open, verified s1 stream.
type Stream = impl.Stream

// VerifiedResponse is an answer to an opted-in stream request that is not an
// s1 stream, verified as an ordinary v1 response (spec 05 section 1.4).
type VerifiedResponse = impl.VerifiedResponse

// NotStreamError reports an answer that is not an s1 stream.
type NotStreamError = impl.NotStreamError

// ErrNotStream reports a response that is not an s1 stream.
var ErrNotStream = impl.ErrNotStream

// ErrClosed is returned by Stream.Next after Stream.Close.
var ErrClosed = impl.ErrClosed
