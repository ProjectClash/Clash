package adapter

import "sync"

type proxyStates struct {
	mu     sync.RWMutex
	states map[string]*internalProxyState
}

func (s *proxyStates) Load(url string) (*internalProxyState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.states[url]
	return state, ok
}

func (s *proxyStates) LoadOrStoreFn(url string, fn func() *internalProxyState) (state *internalProxyState, loaded bool) {
	if state, ok := s.Load(url); ok {
		return state, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if state, ok := s.states[url]; ok {
		return state, true
	}
	if s.states == nil {
		s.states = make(map[string]*internalProxyState, 1)
	}
	state = fn()
	s.states[url] = state
	return state, false
}

func (s *proxyStates) Range(f func(url string, state *internalProxyState) bool) {
	s.mu.RLock()
	snapshot := make(map[string]*internalProxyState, len(s.states))
	for url, state := range s.states {
		snapshot[url] = state
	}
	s.mu.RUnlock()
	for url, state := range snapshot {
		if !f(url, state) {
			return
		}
	}
}
