package cli

import "testing"

// Одна заявка занимает слот nonce до ts+window, а ts может быть до window
// секунд в будущем: занятость rate*(2*window+1) обязана оставаться строго
// ниже capacity. Тест падает при дрейфе любой из трёх констант.
func TestGatewayAdmissionBudget(t *testing.T) {
	occupancy := gatewayAdmissionRate * (2*maxDurableWindow + 1)
	if occupancy >= gatewayNonceCapacity {
		t.Fatalf("admission occupancy %d*(2*%d+1)=%d must stay below nonce capacity %d",
			gatewayAdmissionRate, maxDurableWindow, occupancy, gatewayNonceCapacity)
	}
}
