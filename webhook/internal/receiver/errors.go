package receiver

import "encoding/json"

type rejection struct {
	status  int
	message string
}

// The closed receiver error table from the reference implementation.
var rejections = map[string]rejection{
	"missing_webhook_header":       {400, "a required header is absent"},
	"duplicate_webhook_header":     {400, "a required header is repeated"},
	"malformed_webhook_id":         {400, "webhook-id grammar"},
	"malformed_webhook_timestamp":  {400, "webhook-timestamp grammar"},
	"malformed_subscription_id":    {400, "subscription id grammar"},
	"body_too_large":               {413, "body or declared length above the limit"},
	"unknown_subscription":         {401, "no secret applies to the subscription"},
	"subscription_not_routed":      {503, "the subscription is not routed"},
	"subscription_terminated":      {410, "the subscription is terminated"},
	"stale_timestamp":              {401, "timestamp too old"},
	"future_timestamp":             {401, "timestamp too far ahead"},
	"malformed_signature_header":   {400, "signature header grammar"},
	"unsupported_signature_scheme": {400, "unsupported signature scheme"},
	"malformed_signature":          {400, "signature value length"},
	"bad_signature":                {401, "signature does not verify"},
	"bad_server_signature":         {401, "server signature does not verify"},
	"no_server_keys":               {503, "no accepted server key"},
	"missing_jack_auth":            {401, "jack header absent"},
	"malformed_jack_auth":          {400, "jack header grammar"},
	"webhook_key_is_server_key":    {401, "the webhook key is the mcp server key"},
	"unknown_webhook_key":          {401, "unknown webhook key"},
	"jack_timestamp_out_of_window": {401, "jack timestamp outside the window"},
	"bad_jack_signature":           {401, "jack signature does not verify"},
	"webhook_key_mismatch":         {401, "the webhook key sources disagree"},
	"webhook_key_missing":          {401, "the webhook key source is missing"},
	"enqueue_failed":               {503, "durable enqueue failed"},
	"malformed_body":               {400, "body is not a json object"},
	"unknown_envelope_type":        {400, "unknown envelope type"},
}

// MessageText returns the fixed text for code, or an empty string if unknown.
func MessageText(code string) string {
	return rejections[code].message
}

func reject(code string) Result {
	entry, ok := rejections[code]
	if !ok {
		panic("receiver: unmapped rejection code")
	}
	type detail struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	body, _ := json.Marshal(struct {
		Error detail `json:"error"`
	}{Error: detail{Code: code, Message: entry.message}})
	return Result{Status: entry.status, Code: code, Body: body}
}
