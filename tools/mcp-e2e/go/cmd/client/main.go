// Command go-client is the official SDK end-to-end client fixture.
// It spawns the jack bridge as a stdio MCP server child, then runs
// initialize -> tools/list -> tools/call over the real SDK transport.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const usage = "usage: go-client JACK_BIN CONFIG_PATH MARKER"

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	jackBin, configPath, marker := os.Args[1], os.Args[2], os.Args[3]

	var stderrBuf bytes.Buffer
	cmd := exec.Command(jackBin, "bridge", "--config", configPath)
	cmd.Stderr = &stderrBuf

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	transport := &mcp.CommandTransport{Command: cmd}
	client := mcp.NewClient(
		&mcp.Implementation{Name: "e2e-go-client", Version: "0.0.1"},
		nil,
	)
	session, err := client.Connect(
		ctx,
		transport,
		&mcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"},
	)
	if err != nil {
		fail(stderrBuf.String(), "initialize: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		fail(stderrBuf.String(), "tools/list: %v", err)
	}
	echoListed := false
	for _, tool := range tools.Tools {
		if tool.Name == "echo" {
			echoListed = true
			break
		}
	}
	if !echoListed {
		fail(stderrBuf.String(), "tools/list: echo tool not found")
	}

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "echo",
		Arguments: json.RawMessage(fmt.Sprintf(`{"text":%q}`, marker)),
	})
	if err != nil {
		fail(stderrBuf.String(), "tools/call: %v", err)
	}
	body, err := json.Marshal(res)
	if err != nil {
		fail(stderrBuf.String(), "marshal result: %v", err)
	}
	if res.IsError {
		fail(stderrBuf.String(), "tools/call returned error result: %s", body)
	}
	if !bytes.Contains(body, []byte(marker)) {
		fail(stderrBuf.String(), "marker %q missing from result: %s", marker, body)
	}

	writeSummary(map[string]any{
		"ok":                  true,
		"client":              "go",
		"echo_listed":         true,
		"marker_found":        true,
		"bridge_stderr_bytes": stderrBuf.Len(),
	})
}

func fail(bridgeStderr, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "go-client: "+format+"\n", args...)
	if bridgeStderr != "" {
		fmt.Fprintf(os.Stderr, "bridge stderr: %s\n", bridgeStderr)
	}
	os.Exit(1)
}

func writeSummary(summary map[string]any) {
	data, err := json.Marshal(summary)
	if err != nil {
		fail("", "marshal summary: %v", err)
	}
	fmt.Println(string(data))
}
