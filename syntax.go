package jack

import "regexp"

// scopeRe is ^[a-z][a-z0-9_]*(:[a-z0-9_]+)*$ (spec 02 section 2).
var scopeRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(:[a-z0-9_]+)*$`)

// nameRe is 1-64 characters of [A-Za-z0-9._-] (spec 03 section 1).
var nameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ValidScope reports whether s matches ^[a-z][a-z0-9_]*(:[a-z0-9_]+)*$.
func ValidScope(s string) bool {
	return scopeRe.MatchString(s)
}

// ValidName reports whether s is 1-64 characters of [A-Za-z0-9._-].
func ValidName(s string) bool {
	return nameRe.MatchString(s)
}

// MatchPattern reports whether input matches pattern. '*' matches any run of
// characters including none and newlines; every other character is literal and
// case-sensitive; there are no other metacharacters (spec 02 section 3).
// Byte-wise matching is equivalent to rune-wise here because the only
// metacharacter is ASCII '*', and UTF-8 continuation bytes never equal '*'.
func MatchPattern(pattern, input string) bool {
	// Classic greedy matcher: backtrack to the most recent '*' on mismatch.
	var p, i, starP, starI int // starP/starI = last '*' position, and matching input position
	starP, starI = -1, 0
	for i < len(input) {
		if p < len(pattern) && pattern[p] == '*' {
			starP = p
			starI = i
			p++ // '*' can also match the empty run; try advancing first
			continue
		}
		if p < len(pattern) && pattern[p] == input[i] {
			p++
			i++
			continue
		}
		if starP >= 0 {
			// Extend the run matched by the last '*'.
			starI++
			i = starI
			p = starP + 1
			continue
		}
		return false
	}
	// Only trailing '*'s may remain to match the empty remainder.
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
