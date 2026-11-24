package eventsreceiver

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadReceiptsStrictAndDeduplicated(t *testing.T) {
	valid := `{"subscription_id":"sub_1","webhook_id":"evt_1","kind":"event","message":{"eventId":"one"}}` + "\n"
	loaded, err := loadReceipts([]byte(valid))
	if err != nil || !loaded[receiptKey("sub_1", "evt_1")] {
		t.Fatalf("load valid receipt: loaded=%v err=%v", loaded, err)
	}
	for _, invalid := range []string{
		strings.TrimSuffix(valid, "\n"),
		`{"subscription_id":"sub_1","webhook_id":"evt_1","kind":"event","message":{}}` + "\n" + `{"subscription_id":"sub_1","webhook_id":"evt_1","kind":"event","message":{}}` + "\n",
		`{"subscription_id":"sub_1","webhook_id":"evt_1","kind":"event","message":{},"extra":true}` + "\n",
	} {
		if _, err := loadReceipts([]byte(invalid)); err == nil {
			t.Fatalf("accepted invalid receipt log: %q", invalid)
		}
	}
}

func TestPendingSecretRequiresSecretAndCallback(t *testing.T) {
	c := eventsConfigForTest(t)
	tlsDir := t.TempDir()
	c.TLSCertFile = filepath.Join(tlsDir, "cert.pem")
	c.TLSKeyFile = filepath.Join(tlsDir, "key.pem")
	c.Subscriptions = []subscription{{ID: "", Secret: "whsec_" + base64.StdEncoding.EncodeToString(make([]byte, 32)), CallbackURL: "https://example.test/hook"}}
	c.AllowPendingSecret = true
	if err := validate(&c, false); err != nil {
		t.Fatalf("valid pending secret rejected: %v", err)
	}
	c.Subscriptions[0].Secret = ""
	if validate(&c, false) == nil {
		t.Fatal("empty pending secret accepted")
	}
}

func TestStateLimit(t *testing.T) {
	if _, err := loadReceipts(make([]byte, stateLimit+1)); err == nil {
		t.Fatal("oversized in-memory state accepted")
	}
}

func TestEventsReceiveRequiresTLSUnlessExplicitLoopback(t *testing.T) {
	base := eventsConfigForTest(t)
	if validate(&base, false) == nil {
		t.Fatal("expected TLS configuration refusal")
	}
	validTLSDir := t.TempDir()
	base.TLSCertFile, base.TLSKeyFile = filepath.Join(validTLSDir, "cert.pem"), filepath.Join(validTLSDir, "key.pem")
	if validate(&base, false) != nil {
		t.Fatal("valid TLS listener rejected")
	}
	base.TLSCertFile, base.TLSKeyFile = "", ""
	base.Listen = "localhost:8080"
	if validate(&base, true) == nil {
		t.Fatal("hostname loopback must not be accepted")
	}
	base.Listen = "127.0.0.1:8080"
	if validate(&base, true) != nil {
		t.Fatal("literal loopback test listener rejected")
	}
}

func TestEventsReceiveRequiresPrivateConfigFields(t *testing.T) {
	c := eventsConfigForTest(t)
	c.Listen = "0.0.0.0:8080"
	if validate(&c, true) == nil {
		t.Fatal("non-loopback plaintext listener accepted")
	}
	c = eventsConfigForTest(t)
	c.CallbackPath = "/"
	if validate(&c, false) == nil {
		t.Fatal("root callback path accepted")
	}
}

func eventsConfigForTest(t *testing.T) config {
	t.Helper()
	stateFile := filepath.Join(t.TempDir(), "events.log")
	return config{Listen: "127.0.0.1:8080", CallbackPath: "/hooks", StateFile: stateFile, Subscriptions: []subscription{{ID: "sub_0123456789abcdef", Secret: "whsec_" + base64.StdEncoding.EncodeToString(make([]byte, 32))}}}
}
