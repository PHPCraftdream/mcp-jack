package main

// Held-call registry and control HTTP endpoints (/v1/release, /v1/cancelled).
// Cancelled is true only when the real tool-call context was cancelled.

import (
	"encoding/json"
	"net/http"
	"sync"
)

type callRegistry struct {
	mu        sync.Mutex
	held      map[string]chan struct{}
	cancelled map[string]bool
}

func newCallRegistry() *callRegistry {
	return &callRegistry{held: map[string]chan struct{}{}, cancelled: map[string]bool{}}
}

func (r *callRegistry) hold(id string) (<-chan struct{}, func()) {
	ch := make(chan struct{})
	r.mu.Lock()
	r.held[id] = ch
	r.mu.Unlock()
	return ch, func() {
		r.mu.Lock()
		delete(r.held, id)
		r.mu.Unlock()
	}
}

func (r *callRegistry) release(id string) bool {
	r.mu.Lock()
	ch, ok := r.held[id]
	delete(r.held, id)
	r.mu.Unlock()
	if !ok {
		return false
	}
	close(ch)
	return true
}

func (r *callRegistry) markCancelled(id string) {
	r.mu.Lock()
	r.cancelled[id] = true
	r.mu.Unlock()
}

func (r *callRegistry) isCancelled(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cancelled[id]
}

type releaseRequest struct {
	CallID string `json:"call_id"`
}

type releaseResponse struct {
	Released bool   `json:"released"`
	CallID   string `json:"call_id"`
}

type cancelledResponse struct {
	CallID    string `json:"call_id"`
	Cancelled bool   `json:"cancelled"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func controlHandler(reg *callRegistry) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/release", func(w http.ResponseWriter, req *http.Request) {
		var body releaseRequest
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body.CallID == "" {
			writeJSON(w, http.StatusBadRequest, releaseResponse{CallID: body.CallID})
			return
		}
		if reg.release(body.CallID) {
			writeJSON(w, http.StatusOK, releaseResponse{Released: true, CallID: body.CallID})
			return
		}
		writeJSON(w, http.StatusNotFound, releaseResponse{Released: false, CallID: body.CallID})
	})
	mux.HandleFunc("GET /v1/cancelled", func(w http.ResponseWriter, req *http.Request) {
		id := req.URL.Query().Get("call_id")
		writeJSON(w, http.StatusOK, cancelledResponse{CallID: id, Cancelled: reg.isCancelled(id)})
	})
	return mux
}
