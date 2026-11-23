// Package delivery implements the webhook profile's outbound network policy.
package delivery

import (
	"strconv"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/ipaddr"
	"github.com/PHPCraftdream/mcp-jack/webhook/internal/urlcheck"
)

// CheckInput is one delivery decision (R6.8-R6.10) over a pure model.
type CheckInput struct {
	URL           string
	Answers       []string
	Recheck       []string
	AllowedRanges []string
	Redirect      *int
}

// CheckResult describes either a refusal or a connection. On success, Reason
// is the classification reason of the selected address and Code is empty.
type CheckResult struct {
	Allow                                  bool
	Code, Reason, Address, HostHeader, SNI string
	UsesSNI                                bool
}

// Error returns the refusal code and optional reason, or an empty string on success.
func (r CheckResult) Error() string {
	if r.Allow {
		return ""
	}
	return errorText(r.Code, r.Reason)
}

// Check makes a delivery decision without DNS or network access.
func Check(in CheckInput) CheckResult {
	u, err := urlcheck.Check(in.URL)
	if err != nil {
		return CheckResult{Code: err.Code, Reason: err.Reason}
	}
	return check(u, in)
}

func check(u urlcheck.URL, in CheckInput) CheckResult {
	if in.Redirect != nil {
		return CheckResult{Code: "redirect_refused", Reason: statusReason(*in.Redirect)}
	}
	usesSNI := u.HostKind == "name"
	candidates := in.Answers
	if !usesSNI {
		candidates = []string{u.HostValue}
	}
	if len(candidates) == 0 {
		return CheckResult{Code: "no_answer", Reason: "no_records"}
	}
	var chosen ipaddr.Verdict
	for i, candidate := range candidates {
		verdict := ipaddr.ClassifyWithRanges(candidate, in.AllowedRanges)
		if !verdict.Allow {
			return CheckResult{Code: "blocked_address", Reason: verdict.Reason}
		}
		if i == 0 {
			chosen = verdict
		}
	}
	if len(in.Recheck) != 0 {
		next, ok := ipaddr.ParseAddress(in.Recheck[0])
		if !ok || next.Address != chosen.Address {
			return CheckResult{Code: "dns_rebinding", Reason: "address_changed"}
		}
	}
	result := CheckResult{
		Allow: true, Reason: chosen.Reason, Address: chosen.Address,
		HostHeader: hostHeader(u), UsesSNI: usesSNI,
	}
	if usesSNI {
		result.SNI = u.HostValue
	}
	return result
}

func hostHeader(u urlcheck.URL) string {
	if u.Port == 443 {
		return u.Host
	}
	return u.Host + ":" + strconv.Itoa(u.Port)
}

func statusReason(status int) string {
	return "status_" + strconv.Itoa(status)
}

func errorText(code, reason string) string {
	if reason == "" {
		return code
	}
	return code + ": " + reason
}
