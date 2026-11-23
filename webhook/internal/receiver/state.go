package receiver

import "slices"

// SecretState exposes the binding of a configured secret, never its key bytes.
type SecretState struct {
	SubscriptionID, CallbackURL string
}

// State is an independent snapshot. IDs are sorted; secrets retain config order.
type State struct {
	Routed, Terminated, Accepted []string
	Secrets                      []SecretState
}

// Route adds the given IDs to the routed set without clearing termination.
func (r *Receiver) Route(ids []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range ids {
		r.routed[id] = struct{}{}
	}
}

// State returns routing, termination, deduplication and secret binding state.
func (r *Receiver) State() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := State{
		Routed:     sortedKeys(r.routed),
		Terminated: sortedKeys(r.terminated),
		Accepted:   sortedKeys(r.accepted),
		Secrets:    make([]SecretState, len(r.cfg.Secrets)),
	}
	for i, entry := range r.cfg.Secrets {
		state.Secrets[i] = SecretState{SubscriptionID: entry.SubscriptionID, CallbackURL: entry.CallbackURL}
	}
	return state
}

func sortedKeys[V any](set map[string]V) []string {
	keys := make([]string, 0, len(set))
	for id := range set {
		keys = append(keys, id)
	}
	slices.Sort(keys)
	return keys
}
