package wire

import (
	"encoding/json"
	"math"
	"regexp"
)

// The message kinds of the parsed body, R1.3.
const (
	// KindEvent is an EventOccurrence, a JSON object without "type".
	KindEvent = "event"
	// KindGap is the gap control envelope of R8.7.
	KindGap = "gap"
	// KindTerminated is the terminated control envelope of R8.8.
	KindTerminated = "terminated"
	// KindVerification is the verification control envelope of R5.6.
	KindVerification = "verification"
)

// The reason strings of R3.18 and R1.3.
const (
	reasonMalformedBody       = "malformed_body"
	reasonUnknownEnvelopeType = "unknown_envelope_type"
)

// Message is one parsed body of R1.3, after every verification step passed.
//
// Kind is the closed kind of the body. Type is the control envelope's "type"
// discriminator and is empty for an event occurrence. Object is the parsed
// top-level JSON object. Raw is a private copy of the body bytes as received.
// Challenge is the verification nonce, and is set only for a verification
// envelope. Cursor is set only when the body carried "cursor" as a JSON
// string, and stays nil for an absent or null cursor.
type Message struct {
	Kind      string
	Type      string
	Object    map[string]any
	Raw       json.RawMessage
	Challenge string
	Cursor    *string
}

// Parse decodes one raw body of R1.3 and reports "" when it is a well formed
// occurrence or control envelope, "malformed_body" when the body is not a JSON
// object or a member of its shape fails, and "unknown_envelope_type" when the
// body carries a "type" that is not gap, terminated or verification.
func Parse(raw []byte) (Message, string) {
	object, ok := parseObject(raw)
	if !ok {
		return Message{}, reasonMalformedBody
	}
	message := Message{
		Object: object,
		Raw:    append(json.RawMessage(nil), raw...),
	}
	ownType, typed := object["type"]
	if typed {
		envelope, isString := ownType.(string)
		if !isString || (envelope != KindGap && envelope != KindTerminated && envelope != KindVerification) {
			return Message{}, reasonUnknownEnvelopeType
		}
		message.Type = envelope
		if !fieldsOk(object, envelope) {
			return Message{}, reasonMalformedBody
		}
		switch envelope {
		case KindGap:
			message.Kind = KindGap
			message.Cursor = stringOrNil(object["cursor"])
		case KindTerminated:
			message.Kind = KindTerminated
		case KindVerification:
			message.Kind = KindVerification
			message.Challenge = object["challenge"].(string)
		}
		return message, ""
	}
	message.Kind = KindEvent
	if !fieldsOk(object, "") {
		return Message{}, reasonMalformedBody
	}
	message.Cursor = stringOrNil(object["cursor"])
	return message, ""
}

// parseObject decodes raw as a JSON object, or reports false for invalid JSON
// and for any non-object top level value.
func parseObject(raw []byte) (map[string]any, bool) {
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, false
	}
	object, ok := parsed.(map[string]any)
	if !ok || object == nil {
		return nil, false
	}
	return object, true
}

// fieldsOk is the field set of one parsed occurrence or control envelope,
// R1.3, R8.8 and R5.6. envelope is the "type" value, and "" for an occurrence.
func fieldsOk(object map[string]any, envelope string) bool {
	switch envelope {
	case KindVerification:
		challenge, ok := object["challenge"].(string)
		return ok && ValidNonce(challenge)
	case KindGap:
		cursor, present := object["cursor"]
		return present && (cursor == nil || isString(cursor))
	case KindTerminated:
		errorValue, present := object["error"]
		if !present {
			return false
		}
		errorObject, ok := errorValue.(map[string]any)
		if !ok || errorObject == nil {
			return false
		}
		code, present := errorObject["code"]
		if !present {
			return false
		}
		number, ok := code.(float64)
		if !ok || !isInteger(number) {
			return false
		}
		if _, ok := errorObject["message"].(string); !ok {
			return false
		}
		data, present := errorObject["data"]
		return !present || isObject(data)
	default:
		data, present := object["data"]
		if !present || !isObject(data) {
			return false
		}
		if cursor, present := object["cursor"]; present && !(cursor == nil || isString(cursor)) {
			return false
		}
		return nonEmpty(object["eventId"]) && nonEmpty(object["name"]) && isoTimestampOk(object["timestamp"])
	}
}

// isObject mirrors the reference isObject: a non-null, non-array JSON object.
func isObject(value any) bool {
	object, ok := value.(map[string]any)
	return ok && object != nil
}

// isString mirrors "typeof value === 'string'".
func isString(value any) bool {
	_, ok := value.(string)
	return ok
}

// nonEmpty mirrors "typeof value === 'string' && value.length > 0".
func nonEmpty(value any) bool {
	s, ok := value.(string)
	return ok && len(s) > 0
}

// isInteger is Number.isInteger over the float64 a JSON number decodes to:
// -32024, -32024.0 and 1e3 are integers, -32024.5 and a string are not.
func isInteger(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && math.Trunc(value) == value
}

// stringOrNil returns a pointer to the value when it is a JSON string, and nil
// for anything else, including an explicit null.
func stringOrNil(value any) *string {
	s, ok := value.(string)
	if !ok {
		return nil
	}
	return &s
}

// isoTimestampRE is the RFC 3339 profile of R1.3: a date, a time, an optional
// fraction and a mandatory zone.
var isoTimestampRE = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$`)

// monthDays is the day count of each month, February in a common year.
var monthDays = [12]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}

// isoTimestampOk validates an occurrence timestamp by arithmetic, never with a
// calendar library, since a normalizing parser would accept an impossible day.
func isoTimestampOk(value any) bool {
	s, ok := value.(string)
	if !ok {
		return false
	}
	match := isoTimestampRE.FindStringSubmatch(s)
	if match == nil {
		return false
	}
	year := digits(match[1])
	month := digits(match[2])
	day := digits(match[3])
	hour := digits(match[4])
	minute := digits(match[5])
	second := digits(match[6])
	if month < 1 || month > 12 {
		return false
	}
	leap := year%4 == 0 && (year%100 != 0 || year%400 == 0)
	days := monthDays[month-1]
	if month == 2 && leap {
		days = 29
	}
	if day < 1 || day > days {
		return false
	}
	if hour > 23 || minute > 59 || second > 59 {
		return false
	}
	if match[7] == "" {
		return true
	}
	return digits(match[7]) <= 23 && digits(match[8]) <= 59
}

// digits converts a run of ASCII decimal digits, as matched by isoTimestampRE,
// to its value.
func digits(s string) int {
	value := 0
	for i := 0; i < len(s); i++ {
		value = value*10 + int(s[i]-'0')
	}
	return value
}
