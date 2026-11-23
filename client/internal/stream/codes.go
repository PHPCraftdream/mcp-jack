package stream

// Code is one terminal client-side stream code of the closed list in spec 05
// section 4.6.
type Code string

const (
	// MissingAuth is 4.2 step 1: the response carries no Jack-Auth header.
	MissingAuth Code = "stream_missing_auth"
	// MalformedAuth is 4.2 step 2: the header repeats or violates the 2.2 grammar.
	MalformedAuth Code = "stream_malformed_auth"
	// UnsupportedVersion is 2.3: the raw scheme is not s1.
	UnsupportedVersion Code = "stream_unsupported_version"
	// UnknownServerKey is 4.2 step 4: the kid is neither pinned nor rotation-known.
	UnknownServerKey Code = "stream_unknown_server_key"
	// OutOfWindow is 4.2 step 5: abs(now - ts) exceeds W.
	OutOfWindow Code = "stream_out_of_window"
	// BadSignature is 4.2 step 7: the signature does not verify.
	BadSignature Code = "stream_bad_signature"
	// BadFrame is 4.3 step 1: the frame grammar of 2.6-2.13 is violated.
	BadFrame Code = "stream_bad_frame"
	// OutOfOrder is 4.3 step 2: seq is not the expected next value.
	OutOfOrder Code = "stream_out_of_order"
	// StaleFrame is 4.3 step 3: ts is outside the window or below the previous frame.
	StaleFrame Code = "stream_stale_frame"
	// Truncated is 4.4: the body ended before an end frame was verified.
	Truncated Code = "stream_truncated"
	// Idle is 4.5: no frame verified within streamIdleMs.
	Idle Code = "stream_idle"
	// FrameTooLarge is 2.17: the data value exceeds frameMaxBytes.
	FrameTooLarge Code = "stream_frame_too_large"
	// AfterCutoff is 5.2: ts is at or after the known successor activation.
	AfterCutoff Code = "stream_after_cutoff"
)

// Codes returns every code of the closed list of 4.6 as a fresh slice, in the
// order of that list.
func Codes() []Code {
	return []Code{
		MissingAuth,
		MalformedAuth,
		UnsupportedVersion,
		UnknownServerKey,
		OutOfWindow,
		BadSignature,
		BadFrame,
		OutOfOrder,
		StaleFrame,
		Truncated,
		Idle,
		FrameTooLarge,
		AfterCutoff,
	}
}

// Valid reports whether c is one of the thirteen codes of 4.6.
func (c Code) Valid() bool {
	switch c {
	case MissingAuth, MalformedAuth, UnsupportedVersion, UnknownServerKey,
		OutOfWindow, BadSignature, BadFrame, OutOfOrder, StaleFrame, Truncated,
		Idle, FrameTooLarge, AfterCutoff:
		return true
	}
	return false
}

// Error is the terminal client-side failure of a stream (4.6). It is never an
// HTTP response: it ends the verified stream and is returned to the caller.
//
// FramesVerified counts every event that passed verification, including the
// end frame and a transport signal.
type Error struct {
	Code           Code
	FramesVerified int
	Message        string
}

// Error implements error as "jack stream: <code>", with ": <message>" appended
// when Message is set.
func (e *Error) Error() string {
	if e.Message == "" {
		return "jack stream: " + string(e.Code)
	}
	return "jack stream: " + string(e.Code) + ": " + e.Message
}

// fail builds the terminal error of code with the given verified frame count.
func fail(code Code, frames int, message string) *Error {
	return &Error{Code: code, FramesVerified: frames, Message: message}
}
