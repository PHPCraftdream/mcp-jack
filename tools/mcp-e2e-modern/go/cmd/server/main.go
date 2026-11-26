// Command server is the official-SDK modern e2e server fixture.
// It serves echo/progress/updated tools and a fixture resource over
// modern Streamable HTTP plus a separate loopback control HTTP server.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const sdkName = "github.com/modelcontextprotocol/go-sdk"

// sdkVer resolves from the build's module graph; "unknown" as fallback.
var sdkVer = "unknown"

func sdkVersionFromBuild() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == sdkName && d.Version != "" {
				return d.Version
			}
		}
	}
	return ""
}

const usage = "usage: server --listen 127.0.0.1:0 --control-listen 127.0.0.1:0 [--legacy-only]"

// One scenario-7 client runs per server process.
type listenCancelSlot struct {
	mu     sync.Mutex
	cancel context.CancelFunc
}

func (s *listenCancelSlot) remember(cancel context.CancelFunc) {
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
}

func (s *listenCancelSlot) cancelLastListen() {
	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func listenContextHandler(next http.Handler, slot *listenCancelSlot) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			next.ServeHTTP(w, req)
			return
		}
		body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20+1))
		if err != nil || len(body) > 1<<20 {
			http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		req.Body = io.NopCloser(strings.NewReader(string(body)))
		if !strings.Contains(string(body), `"subscriptions/listen"`) {
			next.ServeHTTP(w, req)
			return
		}
		child, cancel := context.WithCancel(req.Context())
		slot.remember(cancel)
		defer cancel()
		next.ServeHTTP(w, req.WithContext(child))
	})
}

var scenarioListenCancel listenCancelSlot

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "MCP streamable HTTP listen address")
	controlListen := flag.String("control-listen", "127.0.0.1:0", "control channel listen address")
	legacyOnly := flag.Bool("legacy-only", false, "reject modern requests without initializing")
	flag.Parse()
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "%s\n", usage)
		os.Exit(2)
	}

	reg := newCallRegistry()
	if v := sdkVersionFromBuild(); v != "" {
		sdkVer = v
	}
	srv := newServer(reg)
	var handler http.Handler = listenContextHandler(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{
			Stateless:                    true,
			PropagateRequestCancellation: true,
			DisableLocalhostProtection:   true,
		}), &scenarioListenCancel)
	if *legacyOnly {
		handler = legacyGate(handler)
	}

	mcpLn, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server: listen %s: %v\n", *listen, err)
		os.Exit(1)
	}
	ctrlLn, err := net.Listen("tcp", *controlListen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server: listen %s: %v\n", *controlListen, err)
		os.Exit(1)
	}

	mcpSrv := &http.Server{Handler: handler}
	ctrlSrv := &http.Server{Handler: controlHandler(reg)}
	serveErr := make(chan error, 2)
	go func() { serveErr <- mcpSrv.Serve(mcpLn) }()
	go func() { serveErr <- ctrlSrv.Serve(ctrlLn) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	ready, err := json.Marshal(readyRecord{
		Address:        "http://" + mcpLn.Addr().String(),
		ControlAddress: "http://" + ctrlLn.Addr().String(),
		SDK:            sdkIdentity{Name: sdkName, Version: sdkVer},
		Capabilities:   manifest(),
	})
	if err == nil {
		_, err = os.Stdout.Write(append(ready, '\n'))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "server: write ready line: %v\n", err)
		os.Exit(1)
	}

	select {
	case s := <-sig:
		fmt.Fprintf(os.Stderr, "server: signal %v\n", s)
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, context.Canceled) {
			fmt.Fprintf(os.Stderr, "server: serve: %v\n", err)
		}
	}
	_ = mcpSrv.Close()
	_ = ctrlSrv.Close()
}
