package keys

import (
	"errors"
	"strings"
	"testing"

	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/command"
	"github.com/PHPCraftdream/mcp-jack/internal/cli/internal/transport"
)

// TestEnrollUnauthorizedDiagnostic pins that the 401 diagnostic from enroll
// names the invite/key causes and stays distinct from the generic remote
// failure text, so the Run switch cannot silently fall back to command.ErrRemote.
func TestEnrollUnauthorizedDiagnostic(t *testing.T) {
	var err error = &EnrollUnauthorizedError{}
	var target *EnrollUnauthorizedError
	if !errors.As(err, &target) {
		t.Fatal("errors.As failed for *EnrollUnauthorizedError")
	}
	if target.Error() == command.ErrRemote.Error() {
		t.Fatal("401 diagnostic must differ from the generic remote-failure text")
	}
	for _, want := range []string{"401", "invalid", "expired", "used", "unknown"} {
		if !strings.Contains(target.Error(), want) {
			t.Fatalf("401 diagnostic %q lacks %q", target.Error(), want)
		}
	}
	var verified *transport.VerifiedStatusError
	if errors.As(err, &verified) {
		t.Fatal("401 diagnostic must not be mistaken for a verified status error")
	}
}
