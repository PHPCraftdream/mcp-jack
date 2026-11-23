package delivery_test

import (
	"testing"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
)

func TestDeliveryCheck(t *testing.T) {
	const endpoint = "https://hooks.example.test/"
	const first, second = "192.0.0.9", "192.0.0.10"
	status := 302
	answers := []string{first, second}
	allowed := delivery.CheckResult{
		Allow: true, Reason: "pcp_anycast", Address: first,
		HostHeader: "hooks.example.test", SNI: "hooks.example.test", UsesSNI: true,
	}
	withPort := allowed
	withPort.HostHeader += ":8443"

	for _, tt := range []struct {
		name string
		in   delivery.CheckInput
		want delivery.CheckResult
	}{
		{
			name: "url refusal precedes redirect",
			in:   delivery.CheckInput{URL: "http://hooks.example.test/", Redirect: &status},
			want: delivery.CheckResult{Code: "scheme_not_https"},
		},
		{
			name: "url refusal with reason",
			in:   delivery.CheckInput{URL: endpoint + "#fragment"},
			want: delivery.CheckResult{Code: "invalid_callback_url", Reason: "fragment"},
		},
		{
			name: "redirect precedes resolution",
			in:   delivery.CheckInput{URL: endpoint, Redirect: &status},
			want: delivery.CheckResult{Code: "redirect_refused", Reason: "status_302"},
		},
		{
			name: "no answer",
			in:   delivery.CheckInput{URL: endpoint},
			want: delivery.CheckResult{Code: "no_answer", Reason: "no_records"},
		},
		{
			name: "first failing answer wins",
			in:   delivery.CheckInput{URL: endpoint, Answers: []string{"169.254.1.1", "127.0.0.1"}},
			want: delivery.CheckResult{Code: "blocked_address", Reason: "link_local"},
		},
		{
			name: "later blocked answer refuses the attempt",
			in:   delivery.CheckInput{URL: endpoint, Answers: []string{first, "127.0.0.1"}},
			want: delivery.CheckResult{Code: "blocked_address", Reason: "loopback"},
		},
		{
			name: "changed recheck",
			in:   delivery.CheckInput{URL: endpoint, Answers: answers, Recheck: []string{second, first}},
			want: delivery.CheckResult{Code: "dns_rebinding", Reason: "address_changed"},
		},
		{
			name: "invalid recheck",
			in:   delivery.CheckInput{URL: endpoint, Answers: answers, Recheck: []string{"not an IP"}},
			want: delivery.CheckResult{Code: "dns_rebinding", Reason: "address_changed"},
		},
		{
			name: "unchanged recheck checks only first address",
			in:   delivery.CheckInput{URL: endpoint, Answers: answers, Recheck: []string{first, second}},
			want: allowed,
		},
		{
			name: "first allowed address default port",
			in:   delivery.CheckInput{URL: "https://HOOKS.example.test.:443/hook", Answers: answers},
			want: allowed,
		},
		{
			name: "first allowed address nondefault port",
			in:   delivery.CheckInput{URL: "https://hooks.example.test:8443/hook", Answers: answers},
			want: withPort,
		},
		{
			name: "bracketed IPv6 literal ignores answers",
			in:   delivery.CheckInput{URL: "https://[2001:1::1]:8443/hook", Answers: []string{"127.0.0.1"}},
			want: delivery.CheckResult{Allow: true, Reason: "pcp_anycast", Address: "2001:1::1", HostHeader: "[2001:1::1]:8443"},
		},
		{
			name: "operator override",
			in:   delivery.CheckInput{URL: endpoint, Answers: []string{"10.1.2.3"}, AllowedRanges: []string{"malformed", "10.1.0.0/16"}},
			want: delivery.CheckResult{Allow: true, Reason: "allowed_range", Address: "10.1.2.3", HostHeader: "hooks.example.test", SNI: "hooks.example.test", UsesSNI: true},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := delivery.Check(tt.in)
			if got != tt.want {
				t.Fatalf("Check(%+v) = %+v, want %+v", tt.in, got, tt.want)
			}
			wantError := ""
			if !tt.want.Allow {
				wantError = tt.want.Code
				if tt.want.Reason != "" {
					wantError += ": " + tt.want.Reason
				}
			}
			if got.Error() != wantError {
				t.Errorf("Error() = %q, want %q", got.Error(), wantError)
			}
		})
	}
}
