package jack

import "regexp"

// nameRe is 1-64 characters of [A-Za-z0-9._-] (spec 03 section 1).
var nameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ValidName reports whether s is 1-64 characters of [A-Za-z0-9._-].
func ValidName(s string) bool {
	return nameRe.MatchString(s)
}
