//go:build ignore

package main

import (
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type result struct {
	Capability string `json:"capability"`
	OK         bool   `json:"ok"`
	Detail     string `json:"detail"`
}

func emit(name string) {
	b, _ := json.Marshal(result{Capability: name, OK: false, Detail: "no_probe"})
	fmt.Println(string(b))
}

func main() {
	_ = mcp.NewClient
	_ = mcp.CommandTransport{}
	_ = mcp.CallToolParams{}
	_ = (*mcp.Server)(nil)
	for _, name := range []string{"protocol_2026_07_28", "client_stdio_transport", "server_streamable_http_transport", "stateless_server_mode", "progress_notifications_tool_call", "client_cancellation_api", "subscriptions_listen", "server_discover"} {
		emit(name)
	}
}
