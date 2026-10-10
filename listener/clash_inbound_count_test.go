package listener

import (
	"errors"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
)

type countedInbound struct {
	name   string
	port   int
	refuse bool
}

func (l countedInbound) Name() string { return l.name }
func (l countedInbound) Listen(C.Tunnel) error {
	if l.refuse {
		return errors.New("address in use")
	}
	return nil
}
func (countedInbound) Close() error              { return nil }
func (countedInbound) Address() string           { return "" }
func (countedInbound) RawAddress() string        { return "" }
func (l countedInbound) Config() C.InboundConfig { return countedInboundConfig(l) }

type countedInboundConfig countedInbound

func (c countedInboundConfig) Name() string { return c.name }
func (c countedInboundConfig) Equal(other C.InboundConfig) bool {
	o, ok := other.(countedInboundConfig)
	return ok && o.name == c.name && o.port == c.port
}

func TestInboundListenerCountFollowsThePatchedListeners(t *testing.T) {
	if InboundListenerCount() != 0 {
		t.Skip("another test left inbound listeners open")
	}
	t.Cleanup(func() { PatchInboundListeners(map[string]C.InboundListener{}, nil, true) })
	PatchInboundListeners(map[string]C.InboundListener{
		"lan-mixed": countedInbound{name: "lan-mixed"},
		"lan-socks": countedInbound{name: "lan-socks"},
	}, nil, true)
	if got := InboundListenerCount(); got != 2 {
		t.Fatalf("two listeners open, counted %d", got)
	}
	PatchInboundListeners(map[string]C.InboundListener{"lan-mixed": countedInbound{name: "lan-mixed"}}, nil, true)
	if got := InboundListenerCount(); got != 1 {
		t.Fatalf("one listener left after the reload, counted %d", got)
	}
}

func TestAListenerWhoseReplacementFailsIsGone(t *testing.T) {
	if InboundListenerCount() != 0 {
		t.Skip("another test left inbound listeners open")
	}
	t.Cleanup(func() { PatchInboundListeners(map[string]C.InboundListener{}, nil, true) })
	patch := func(l countedInbound) {
		PatchInboundListeners(map[string]C.InboundListener{l.name: l}, nil, true)
	}
	patch(countedInbound{name: "lan", port: 7890})
	patch(countedInbound{name: "lan", port: 7891, refuse: true})
	if got := InboundListenerCount(); got != 0 {
		t.Fatalf("the replacement failed and the old one is closed, counted %d open", got)
	}
	patch(countedInbound{name: "lan", port: 7891})
	if got := InboundListenerCount(); got != 1 {
		t.Fatalf("the same configuration applied again, counted %d open", got)
	}
}
