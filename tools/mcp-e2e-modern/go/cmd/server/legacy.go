package main

// --legacy-only deterministic negative control: reject modern requests before
// any SDK initialization or modern protocol serving. Labeled non-SDK coverage
// per CONTRACT.md; the harness treats it as a scripted-style control.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

const modernProtocolVersion = "2026-07-28"

type refusalBody struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id"`
	Error   refusalDetail `json:"error"`
}

type refusalDetail struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type idProbe struct {
	ID     any    `json:"id"`
	Method string `json:"method"`
}

func legacyGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "legacy gate read failed", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		var probe idProbe
		_ = json.Unmarshal(body, &probe)
		modern := r.Header.Get("MCP-Protocol-Version") == modernProtocolVersion ||
			probe.Method == "server/discover" ||
			strings.Contains(string(body), modernProtocolVersion)
		if modern {
			id := probe.ID
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(refusalBody{
				JSONRPC: "2.0",
				ID:      id,
				Error: refusalDetail{
					Code:    -32600,
					Message: "legacy-only fixture refuses modern request",
				},
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
