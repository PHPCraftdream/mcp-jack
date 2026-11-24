package receiver_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/receiver"
)

const (
	fuzzSecret = "0123456789abcdef0123456789abcdef"
	fuzzSub    = "sub_0000000000000001"
	fuzzNow    = int64(1767225600)
)

type receiverFuzzFixture struct {
	Cases []struct {
		Input struct {
			Steps []struct {
				Headers  [][2]string `json:"headers"`
				BodyB64U *string     `json:"body_b64u"`
				BodyText *string     `json:"body_text"`
			} `json:"steps"`
		} `json:"input"`
	} `json:"cases"`
}

// FuzzReceiverHandleNeverAcceptsUnauthenticatedDelivery exercises the raw
// receiver boundary: every accepted or duplicate response must contain a v1
// signature entry that verifies over id.timestamp.body.
func FuzzReceiverHandleNeverAcceptsUnauthenticatedDelivery(f *testing.F) {
	// Pull a modest set of first-step header/body seeds from the checked-in
	// fixture rather than maintaining copies of vector values here.
	data, err := os.ReadFile("../../../spec/fixtures/modern/webhook-receiver-vectors.json")
	if err != nil {
		f.Fatalf("load receiver fixture: %v", err)
	}
	var fixture receiverFuzzFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		f.Fatalf("decode receiver fixture: %v", err)
	}
	var vectorBodies [][]byte
	for _, tc := range fixture.Cases {
		if len(vectorBodies) >= 8 || len(tc.Input.Steps) == 0 {
			break
		}
		step := tc.Input.Steps[0]
		var id, timestamp, signature, sub string
		for _, header := range step.Headers {
			switch strings.ToLower(header[0]) {
			case "webhook-id":
				id = header[1]
			case "webhook-timestamp":
				timestamp = header[1]
			case "webhook-signature":
				signature = header[1]
			case "x-mcp-subscription-id":
				sub = header[1]
			}
		}
		var body []byte
		if step.BodyB64U != nil {
			body, err = base64.RawURLEncoding.DecodeString(*step.BodyB64U)
			if err != nil {
				f.Fatalf("decode receiver fixture body_b64u: %v", err)
			}
		} else if step.BodyText != nil {
			body = []byte(*step.BodyText)
		} else {
			continue
		}
		if id == "" || timestamp == "" || signature == "" || sub == "" {
			continue
		}
		vectorBodies = append(vectorBodies, body)
		f.Add(id, timestamp, signature, sub, body, uint8(0), "X-Vector-Extra", "ignored")
	}
	if len(vectorBodies) == 0 {
		f.Fatal("receiver fixture has no usable first-step seeds")
	}

	// Include a genuine v1 delivery, with an additional allowed v1 entry, so
	// combined-header acceptance is exercised by the fuzz corpus.
	validID := "msg_fuzz_valid_delivery"
	validTimestamp := "1767225600"
	validBody := vectorBodies[0]
	validSignature := independentV1Sign([]byte(fuzzSecret), validID, validTimestamp, validBody)
	f.Add(validID, validTimestamp, validSignature+" "+validSignature, fuzzSub, validBody, uint8(0), "X-Vector-Extra", "ignored")

	// Hand boundaries: empty, syntax/control bytes, malformed UTF-8, body limit,
	// timestamp grammar extremes, and duplicated required-header precedence.
	for _, tc := range []struct {
		id, timestamp, signature, sub string
		body                          []byte
		duplicate                     uint8
	}{
		{"", "", "", "", nil, 0},
		{"msg_empty", "1767225600", "bad", fuzzSub, []byte{}, 0},
		{"msg_nul", "1767225600", "v1,AA==", fuzzSub, []byte{0}, 0},
		{"msg_crlf", "1767225600", "v1,AA==", fuzzSub, []byte("\r\n"), 0},
		{"msg_utf8", "1767225600", "v1,AA==", fuzzSub, []byte{0xff, 0xfe, 0xc0, 0xaf}, 0},
		{"msg_maxish", "1767225600", "v1,AA==", fuzzSub, make([]byte, 4097), 0},
		{"msg_huge", "999999999999999999999999999", "v1,AA==", fuzzSub, []byte(`{}`), 0},
		{"msg_decimal", "1767225600.0", "v1,AA==", fuzzSub, []byte(`{}`), 0},
		{"msg_negative", "-1767225600", "v1,AA==", fuzzSub, []byte(`{}`), 0},
		{"msg_leading_zero", "01767225600", "v1,AA==", fuzzSub, []byte(`{}`), 0},
		{"msg_duplicate_id", "1767225600", "malformed", fuzzSub, []byte(`{}`), 1},
		{"msg_duplicate_timestamp", "1767225600", "malformed", fuzzSub, []byte(`{}`), 2},
		{"msg_duplicate_signature", "1767225600", "malformed", fuzzSub, []byte(`{}`), 3},
		{"msg_duplicate_subscription", "1767225600", "malformed", fuzzSub, []byte(`{}`), 4},
	} {
		f.Add(tc.id, tc.timestamp, tc.signature, tc.sub, tc.body, tc.duplicate, "X-Fuzz-Seed", "boundary")
	}

	f.Fuzz(func(t *testing.T, id, timestamp, signature, sub string, body []byte, duplicate uint8, extraName, extraValue string) {
		if len(id)+len(timestamp)+len(signature)+len(sub)+len(extraName)+len(extraValue)+len(body) > 1<<20 {
			t.Skip()
		}
		headers := [][2]string{
			{"webhook-id", id}, {"webhook-timestamp", timestamp},
			{"webhook-signature", signature}, {"x-mcp-subscription-id", sub},
		}
		requiredNames := [...]string{"webhook-id", "webhook-timestamp", "webhook-signature", "x-mcp-subscription-id"}
		mode := duplicate % 6
		if mode != 0 && mode != 5 {
			index := int(mode) - 1
			headers = append(headers, [2]string{requiredNames[index], "duplicate-value"})
		} else if mode == 5 {
			headers = headers[:2] // omit signature; missing headers precede invalid values
		}
		// Prefixing prevents attacker-controlled name text from becoming a
		// required header; the same unknown pair is the metamorphic variant.
		unknown := [2]string{"x-fuzz-" + extraName, extraValue}
		d := receiver.Delivery{Now: fuzzNow, Headers: headers, Body: body}
		base := fuzzHandle(t, d)
		withUnknown := d
		withUnknown.Headers = append(append([][2]string(nil), headers...), unknown)
		changed := fuzzHandle(t, withUnknown)
		withOtherUnknown := d
		withOtherUnknown.Headers = append(append([][2]string(nil), headers...), [2]string{"x-fuzz-independent", "different"})
		independent := fuzzHandle(t, withOtherUnknown)
		if base.Status != changed.Status || base.Code != changed.Code || string(base.Body) != string(changed.Body) ||
			base.Status != independent.Status || base.Code != independent.Code || string(base.Body) != string(independent.Body) {
			t.Fatalf("unknown header changed verdict: base=(%d,%q) changed=(%d,%q) independent=(%d,%q)", base.Status, base.Code, changed.Status, changed.Code, independent.Status, independent.Code)
		}

		verifiedV1 := independentV1Matches(signature, []byte(fuzzSecret), id, timestamp, body)
		if base.Status/100 == 2 && !verifiedV1 {
			t.Fatalf("unauthenticated 2xx verdict: status=%d code=%q", base.Status, base.Code)
		}
		if mode == 5 && base.Code != "missing_webhook_header" {
			t.Fatalf("missing required header precedence: code=%q", base.Code)
		}

		// Exercise duplicate precedence with otherwise valid routing fields and
		// malformed signature text. This observes API-stage ordering only; it
		// makes no claim that cryptographic work occurred.
		duplicateEnqueues := 0
		dupReceiver := fuzzHandleWithEnqueue(t, func(receiver.Message) error { duplicateEnqueues++; return nil })
		dup := receiver.Delivery{Now: fuzzNow, Body: []byte(`{}`), Headers: [][2]string{
			{"webhook-id", "msg_duplicate_precedence"},
			{"webhook-timestamp", "1767225600"},
			{"webhook-signature", "malformed"},
			{"x-mcp-subscription-id", fuzzSub},
			{"webhook-id", "msg_duplicate_precedence"},
		}}
		dupResult := dupReceiver.Handle(dup)
		if dupResult.Code != "duplicate_webhook_header" || duplicateEnqueues != 0 {
			t.Fatalf("duplicate precedence: code=%q enqueues=%d", dupResult.Code, duplicateEnqueues)
		}
	})
}

func independentV1Sign(secret []byte, id, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(id + "." + timestamp + "."))
	_, _ = mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// independentV1Matches deliberately implements only the header grammar and
// v1 authentication needed by this property; it does not call production dsig.
func independentV1Matches(header string, secret []byte, id, timestamp string, body []byte) bool {
	if header == "" || strings.TrimSpace(header) != header {
		return false
	}
	parts := strings.Split(header, " ")
	var signatures [][]byte
	for _, part := range parts {
		if part == "" || strings.IndexFunc(part, func(r rune) bool {
			return r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f'
		}) >= 0 {
			return false
		}
		comma := strings.IndexByte(part, ',')
		if comma <= 0 || comma == len(part)-1 || strings.IndexByte(part[comma+1:], ',') >= 0 {
			return false
		}
		scheme, value := part[:comma], part[comma+1:]
		for _, c := range scheme {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				return false
			}
		}
		if strings.ContainsAny(value, " \t\n\r\v\f") {
			return false
		}
		if scheme != "v1" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size || base64.StdEncoding.EncodeToString(decoded) != value {
			return false
		}
		signatures = append(signatures, decoded)
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(id + "." + timestamp + "."))
	_, _ = mac.Write(body)
	want := mac.Sum(nil)
	for _, signature := range signatures {
		if hmac.Equal(signature, want) {
			return true
		}
	}
	return false
}

func fuzzHandle(t *testing.T, d receiver.Delivery) receiver.Result {
	return fuzzHandleWithEnqueue(t, func(receiver.Message) error { return nil }).Handle(d)
}

func fuzzHandleWithEnqueue(t *testing.T, enqueue receiver.EnqueueFunc) *receiver.Receiver {
	t.Helper()
	r, err := receiver.New(receiver.Config{
		Secrets: []receiver.Secret{{Key: []byte(fuzzSecret), SubscriptionID: fuzzSub}},
		Routed:  []string{fuzzSub}, MaxBody: 4096,
		Enqueue: enqueue,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
