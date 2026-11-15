package cli

import "testing"

// One request holds a nonce slot until ts+window, and ts may be up to window
// seconds in the future: occupancy rate*(2*window+1) must stay strictly below
// capacity. The test fails if any of the three constants drifts.
func TestGatewayAdmissionBudget(t *testing.T) {
	occupancy := gatewayAdmissionRate * (2*maxDurableWindow + 1)
	if occupancy >= gatewayNonceCapacity {
		t.Fatalf("admission occupancy %d*(2*%d+1)=%d must stay below nonce capacity %d",
			gatewayAdmissionRate, maxDurableWindow, occupancy, gatewayNonceCapacity)
	}
}
