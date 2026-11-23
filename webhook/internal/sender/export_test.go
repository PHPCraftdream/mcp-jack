package sender

import (
	"net/http"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/delivery"
)

// UseDeliveryForTest substitutes HTTP responses without exposing a production
// hook that could bypass the HTTPS and address policy.
func UseDeliveryForTest(s *Sender, do func(*http.Request, int64) (*delivery.Response, *delivery.Error)) {
	s.client = testDeliveryFunc(do)
}

type testDeliveryFunc func(*http.Request, int64) (*delivery.Response, *delivery.Error)

func (f testDeliveryFunc) Do(req *http.Request, maxBody int64) (*delivery.Response, *delivery.Error) {
	return f(req, maxBody)
}
