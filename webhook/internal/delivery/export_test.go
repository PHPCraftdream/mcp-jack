package delivery

import "net/http"

// NewClientWithTestRoots keeps the production dial path but trusts a test CA.
var NewClientWithTestRoots = newClient

// NewClientWithTestTransport exercises the body phase without network I/O.
func NewClientWithTestTransport(rt func(*http.Request) (*http.Response, error)) *Client {
	return &Client{http: &http.Client{Transport: roundTripFunc(rt), Timeout: requestTimeout}}
}
