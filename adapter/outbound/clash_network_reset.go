package outbound

import (
	"errors"

	C "github.com/ProjectClash/Clash/constant"
)

type NetworkResetter interface {
	ResetNetwork()
}

var errNetworkChanged = errors.New("network changed")

func keepsOwnSessions(a any) bool {
	if keeper, ok := a.(interface{ keepsOwnSessions() bool }); ok {
		return keeper.keepsOwnSessions()
	}
	return true
}

func resetOnlyOnNetworkChange(a any) bool {
	only, ok := a.(interface{ resetsOnNetworkChangeOnly() bool })
	return ok && only.resetsOnNetworkChangeOnly()
}

func AsNetworkResetter(a C.ProxyAdapter) (NetworkResetter, bool) {
	if wrapped, ok := a.(*autoCloseProxyAdapter); ok {
		a = wrapped.ProxyAdapter
	}
	if node, ok := a.(*catalogNode); ok {
		if node.traits&(catalogResetter|catalogPathResetter) == 0 {
			return nil, false
		}
		return node, true
	}
	resetter, ok := a.(NetworkResetter)
	return resetter, ok && keepsOwnSessions(a)
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

func (t *AnyTLS) ResetNetwork() {
	t.clientMu.Lock()
	client := t.client
	t.clientMu.Unlock()
	if client != nil {
		client.Reset()
	}
}

func (*AnyTLS) resetsOnNetworkChangeOnly() bool { return true }

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
	} else if inner, ok := s.ProxyAdapter.(NetworkResetter); ok && !resetOnlyOnNetworkChange(s.ProxyAdapter) {
		inner.ResetNetwork()
	}
	return true
}
