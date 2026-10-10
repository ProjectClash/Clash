package outbound

import "errors"

type NetworkResetter interface {
	ResetNetwork()
}

var errNetworkChanged = errors.New("network changed")

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

func (s *SingMux) ResetNetwork() {
	if s.client != nil {
		s.client.Reset()
	}
	if inner, ok := s.ProxyAdapter.(NetworkResetter); ok {
		inner.ResetNetwork()
	}
}
