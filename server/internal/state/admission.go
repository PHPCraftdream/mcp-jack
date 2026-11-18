package state

// AdmissionStateStore serializes the callback with all registry mutations.
// The callback is invoked synchronously exactly once; it must not invoke state, handler, or signature verification.
// The external store must enforce the same gate for each of its writers.
type AdmissionStateStore interface {
	StateStore
	WithAdmission(kid string, check func(RegistryEntry, bool) error) error
}

func (s *MemoryState) WithAdmission(kid string, check func(RegistryEntry, bool) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, known := lookupKey(s.keys, kid)
	return check(entry, known)
}

func (s *FileState) WithAdmission(kid string, check func(RegistryEntry, bool) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, known := lookupKey(s.keys, kid)
	return check(entry, known)
}
