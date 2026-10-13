package outbound

import (
	"errors"

	C "github.com/ProjectClash/Clash/constant"
)

type NetworkResetter interface {
	ResetNetwork()
}

var errNetworkChanged = errors.New("network changed")

func AsNetworkResetter(a C.ProxyAdapter) (NetworkResetter, bool) {
	if wrapped, ok := a.(*autoCloseProxyAdapter); ok {
		a = wrapped.ProxyAdapter
	}
	if node, ok := a.(*catalogNode); ok {
		if node.traits&catalogResetter == 0 {
			return nil, false
		}
		return node, true
	}
	resetter, ok := a.(NetworkResetter)
	return resetter, ok
}

func (h *Hysteria2) ResetNetwork() {
	h.clientMu.Lock()
	defer h.clientMu.Unlock()
	if h.closed {
		return
	}
	client := h.client
	h.client, h.clientErr, h.clientTried = nil, nil, false
	if client != nil {
		_ = client.CloseWithError(errNetworkChanged)
	}
}

func (t *Tuic) ResetNetwork() {
	if t.client != nil {
		t.client.Reset()
	}
}

func (t *Tuic) ReleaseSessions() bool {
	if t.client != nil {
		t.client.Release()
	}
	t.clashReleaseConfigs()
	return true
}

func (s *SingMux) ResetNetwork() {
	if s.client != nil {
		s.client.Reset()
	}
	if inner, ok := s.ProxyAdapter.(NetworkResetter); ok {
		inner.ResetNetwork()
	}
}

func (s *SingMux) ReleaseSessions() bool {
	if s.client != nil {
		s.client.Reset()
	}
	if inner, ok := s.ProxyAdapter.(SessionReleaser); ok {
		return inner.ReleaseSessions()
	} else if inner, ok := s.ProxyAdapter.(NetworkResetter); ok {
		inner.ResetNetwork()
	}
	return true
}
