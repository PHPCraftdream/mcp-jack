package sender

import (
	"crypto/x509"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/endpoint"
)

// UseDeliveryForTest substitutes HTTP responses without exposing a production
// hook that could bypass the HTTPS and address policy.
func UseDeliveryForTest(s *Sender, do func(*http.Request, int64) (*delivery.Response, *delivery.Error)) {
	s.client = testDeliveryFunc(do)
}

type testDeliveryFunc func(*http.Request, int64) (*delivery.Response, *delivery.Error)

func (f testDeliveryFunc) Do(req *http.Request, maxBody int64) (*delivery.Response, *delivery.Error) {
	return f(req, maxBody)
}

const tlsTestChild = "MCP_JACK_SENDER_TLS_TEST_CHILD"

// InTLSChildForTest runs the named test in a subprocess so replacing the
// process-wide fallback roots does not affect any other test.
func InTLSChildForTest(t *testing.T) bool {
	t.Helper()
	if os.Getenv(tlsTestChild) == "1" {
		return true
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.v")
	cmd.Env = append(os.Environ(), tlsTestChild+"=1", "GODEBUG=x509usefallbackroots=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("TLS test subprocess: %v\n%s", err, out)
	}
	return false
}

// GateForTest installs a real gate sharing the sender's hardened client. The
// delivery package's test-only root injection is not available here, so the
// isolated test process trusts cert through the standard x509 verifier.
func GateForTest(t *testing.T, s *Sender, cert *x509.Certificate) *endpoint.Gate {
	t.Helper()
	if os.Getenv(tlsTestChild) != "1" {
		t.Fatal("GateForTest requires InTLSChildForTest")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	x509.SetFallbackRoots(roots)
	gate, err := endpoint.NewGate(endpoint.GateConfig{Client: s.client.(*delivery.Client), Now: s.now})
	if err != nil {
		t.Fatal(err)
	}
	s.verifier = gate
	return gate
}
