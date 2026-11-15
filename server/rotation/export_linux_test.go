//go:build linux

package rotationserver

// Test-only accessors (the export_test.go pattern).
func SetMaxAnnounceRingKeysForTest(bound int) (restore func()) {
	previous := maxAnnounceRingKeys
	maxAnnounceRingKeys = bound
	return func() { maxAnnounceRingKeys = previous }
}

func MaxAnnounceRingKeysForTest() int { return maxAnnounceRingKeys }
func ServedRetiredKeysForTest() int   { return servedRetiredKeys }
