package ipaddr

// Decision reasons that are not a row name (R6.5, R6.6, R6.11).
const (
	reasonGlobal       = "global"
	reasonAllowedRange = "allowed_range"

	chainIPv4Mapped = "ipv4_mapped"
	chainNAT64WKN   = "nat64_well_known"
	chainSixToFour  = "six_to_four"
	chainTeredo     = "teredo"
)

// nat64WellKnown is the 64:ff9b::/96 chain prefix of R6.7, the NAT64_WKN of
// ssrf.mjs: only its first 96 bits take part in the match.
var nat64WellKnown = [16]byte{0x00, 0x64, 0xff, 0x9b}

// Verdict is the outcome of classifying one address literal: the decision, the
// reason string and, when the text parsed, the family and canonical spelling.
type Verdict struct {
	Allow   bool
	Reason  string
	Family  string
	Address string
}

// classifyIPv4 is classifyIPv4 of ssrf.mjs: the longest matching V4Blocks row
// decides, its reachability column picks the decision and its name is the
// reason either way. A row of equal prefix length does not replace the row
// found earlier, so the first row wins a tie. No matching row is allowed with
// reason "global".
func classifyIPv4(bytes [4]byte) (bool, string) {
	var best *Block4
	for i := range V4Blocks {
		row := &V4Blocks[i]
		if best != nil && row.Prefix <= best.Prefix {
			continue
		}
		if matchPrefix(bytes[:], row.Bytes[:], row.Prefix) {
			best = row
		}
	}
	if best == nil {
		return true, reasonGlobal
	}
	return best.Reachable, best.Name
}

// classifyIPv6 is classifyIPv6 of ssrf.mjs: the two inheriting chains run
// first, then the two blocks that never inherit, then the longest matching
// V6Blocks row under the same rule as classifyIPv4.
func classifyIPv6(bytes [16]byte) (bool, string) {
	if isMapped(bytes) {
		allow, reason := classifyIPv4([4]byte{bytes[12], bytes[13], bytes[14], bytes[15]})
		if allow {
			return true, chainIPv4Mapped
		}
		return false, chainIPv4Mapped + "/" + reason
	}
	if matchPrefix(bytes[:], nat64WellKnown[:], 96) {
		allow, reason := classifyIPv4([4]byte{bytes[12], bytes[13], bytes[14], bytes[15]})
		if allow {
			return true, chainNAT64WKN
		}
		return false, chainNAT64WKN + "/" + reason
	}
	if bytes[0] == 0x20 && bytes[1] == 0x02 {
		return false, chainSixToFour
	}
	if bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0 && bytes[3] == 0 {
		return false, chainTeredo
	}
	var best *Block6
	for i := range V6Blocks {
		row := &V6Blocks[i]
		if best != nil && row.Prefix <= best.Prefix {
			continue
		}
		if matchPrefix(bytes[:], row.Bytes[:], row.Prefix) {
			best = row
		}
	}
	if best == nil {
		return true, reasonGlobal
	}
	return best.Reachable, best.Name
}

// classifyParsed is the classifyParsed of ssrf.mjs: run the table of the
// address family and report the family and spelling alongside.
func classifyParsed(parsed Parsed) Verdict {
	verdict := Verdict{Family: parsed.Family, Address: parsed.Address}
	if parsed.Family == familyIPv4 {
		var bytes [4]byte
		copy(bytes[:], parsed.Bytes)
		verdict.Allow, verdict.Reason = classifyIPv4(bytes)
		return verdict
	}
	var bytes [16]byte
	copy(bytes[:], parsed.Bytes)
	verdict.Allow, verdict.Reason = classifyIPv6(bytes)
	return verdict
}

// ClassifyAddress is classifyAddress of ssrf.mjs: classify one address literal
// and report its canonical spelling. An unparsable spelling is rejected with
// reason "not_a_hostname" and no family or address.
func ClassifyAddress(text string) Verdict {
	parsed, ok := ParseAddress(text)
	if !ok {
		return Verdict{Reason: reasonNotAHostname}
	}
	return classifyParsed(parsed)
}

// ClassifyWithRanges is classifyWithRanges of ssrf.mjs: the registry verdict
// first, and only when it is a rejection may one entry of allowedRanges of the
// same family rescue the address with reason "allowed_range" (R6.11).
// Malformed entries are ignored, an allowed registry verdict keeps its reason,
// and an unparsable spelling stays "not_a_hostname".
func ClassifyWithRanges(text string, allowedRanges []string) Verdict {
	parsed, ok := ParseAddress(text)
	if !ok {
		return Verdict{Reason: reasonNotAHostname}
	}
	verdict := classifyParsed(parsed)
	if verdict.Allow {
		return verdict
	}
	for _, entry := range allowedRanges {
		allowed, ok := ParseCIDR(entry)
		if !ok || allowed.Family != parsed.Family {
			continue
		}
		if matchPrefix(parsed.Bytes, allowed.Bytes, allowed.Prefix) {
			verdict.Allow = true
			verdict.Reason = reasonAllowedRange
			return verdict
		}
	}
	return verdict
}
