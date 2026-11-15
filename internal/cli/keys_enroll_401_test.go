package cli

import (
	"errors"
	"strings"
	"testing"
)

// TestEnrollUnauthorizedDiagnostic pins that the 401 diagnostic from enroll
// names the invite/key causes and stays distinct from the generic remote
// failure text, so the Run switch cannot silently fall back to errRemote.
func TestEnrollUnauthorizedDiagnostic(t *testing.T) {
	var err error = &enrollUnauthorizedError{}
	var target *enrollUnauthorizedError
	if !errors.As(err, &target) {
		t.Fatal("errors.As failed for *enrollUnauthorizedError")
	}
	if target.Error() == errRemote.Error() {
		t.Fatal("401 diagnostic must differ from the generic remote-failure text")
	}
	for _, want := range []string{"401", "invalid", "expired", "used", "unknown"} {
		if !strings.Contains(target.Error(), want) {
			t.Fatalf("401 diagnostic %q lacks %q", target.Error(), want)
		}
	}
	var verified *verifiedStatusError
	if errors.As(err, &verified) {
		t.Fatal("401 diagnostic must not be mistaken for a verified status error")
	}
}
