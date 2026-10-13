package outboundgroup

import "sync/atomic"

type groupSelection struct{ name atomic.Pointer[string] }

func (s *groupSelection) Load() string {
	if name := s.name.Load(); name != nil {
		return *name
	}
	return ""
}

func (s *groupSelection) Store(name string) { s.name.Store(&name) }
