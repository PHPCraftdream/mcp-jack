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

// GateForTest builds the real verification gate around client for use in the
// isolated TLS child process, so the sender and the gate share one transport.
// The delivery package's test-only root injection is not available here, so the
// certificate of the httptest server is installed as fallback roots; that
// mutation is process-wide, which is exactly why InTLSChildForTest must have
// isolated this process first. The certificate is optional only because the
// hardened client never exposes it.
func GateForTest(t *testing.T, client *delivery.Client, certs ...*x509.Certificate) *endpoint.Gate {
	t.Helper()
	if os.Getenv(tlsTestChild) != "1" {
		t.Fatal("GateForTest requires InTLSChildForTest")
	}
	if len(certs) > 0 {
		roots := x509.NewCertPool()
		for _, cert := range certs {
			roots.AddCert(cert)
		}
		x509.SetFallbackRoots(roots)
	}
	gate, err := endpoint.NewGate(endpoint.GateConfig{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	return gate
}
