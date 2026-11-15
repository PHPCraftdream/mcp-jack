// Command go-server is the official SDK end-to-end server fixture.
// It exposes one echo tool over Streamable HTTP on a UNIX socket and
// optionally logs every HTTP exchange as JSONL for the driver.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const usage = "usage: go-server SOCKET_PATH"

type echoArgs struct {
	Text string `json:"text" jsonschema:"text to echo back"`
}

type echoOut struct {
	Text string `json:"text"`
}

func echo(_ context.Context, _ *mcp.CallToolRequest, args echoArgs) (*mcp.CallToolResult, echoOut, error) {
	return nil, echoOut{Text: args.Text}, nil
}

type requestRecord struct {
	Kind               string   `json:"kind"`
	Method             string   `json:"method"`
	Path               string   `json:"path"`
	Accept             []string `json:"accept"`
	ContentType        string   `json:"content_type"`
	MCPProtocolVersion string   `json:"mcp_protocol_version"`
	Body               string   `json:"body"`
}

type responseRecord struct {
	Kind   string `json:"kind"`
	Status int    `json:"status"`
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

type captureHandler struct {
	next http.Handler
	path string
	mu   sync.Mutex
}

func (c *captureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if c.path == "" {
		c.next.ServeHTTP(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "capture read failed", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	c.log(requestRecord{
		Kind:               "request",
		Method:             r.Method,
		Path:               r.URL.RequestURI(),
		Accept:             r.Header.Values("Accept"),
		ContentType:        r.Header.Get("Content-Type"),
		MCPProtocolVersion: r.Header.Get("MCP-Protocol-Version"),
		Body:               string(body),
	})
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	c.next.ServeHTTP(rec, r)
	c.log(responseRecord{Kind: "response", Status: rec.status})
}

func (c *captureHandler) log(record any) {
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	f, err := os.OpenFile(c.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(data, '\n'))
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	socket := os.Args[1]

	listener, err := net.Listen("unix", socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen %s: %v\n", socket, err)
		os.Exit(1)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "chmod %s: %v\n", socket, err)
		os.Exit(1)
	}

	server := mcp.NewServer(
		&mcp.Implementation{Name: "e2e-go-server", Version: "0.0.1"},
		nil,
	)
	mcp.AddTool(
		server,
		&mcp.Tool{Name: "echo", Description: "Echo the text argument back to the caller"},
		echo,
	)

	handler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	)
	capture := &captureHandler{next: handler, path: os.Getenv("E2E_SERVER_LOG")}

	srv := &http.Server{Handler: capture}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		srv.Close()
	}()

	if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}
