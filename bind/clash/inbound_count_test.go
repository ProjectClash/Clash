package clash

import (
	"testing"

	"github.com/ProjectClash/Clash/constant"
	coreListener "github.com/ProjectClash/Clash/listener"
	"github.com/ProjectClash/Clash/tunnel"
)

type inboundStub struct{ name string }

func (l inboundStub) Name() string                   { return l.name }
func (inboundStub) Listen(constant.Tunnel) error     { return nil }
func (inboundStub) Close() error                     { return nil }
func (inboundStub) Address() string                  { return "" }
func (inboundStub) RawAddress() string               { return "" }
func (l inboundStub) Config() constant.InboundConfig { return inboundStubConfig(l) }

type inboundStubConfig inboundStub

func (c inboundStubConfig) Name() string                            { return c.name }
func (c inboundStubConfig) Equal(other constant.InboundConfig) bool { return other.Name() == c.name }

func TestTheInboundCountIncludesListenersInbounds(t *testing.T) {
	if coreListener.InboundListenerCount() != 0 {
		t.Skip("inbound listeners already open")
	}
	baseline := runtimeInboundCount()
	t.Cleanup(func() {
		coreListener.PatchInboundListeners(map[string]constant.InboundListener{}, tunnel.Tunnel, true)
	})
	coreListener.PatchInboundListeners(map[string]constant.InboundListener{"lan-mixed": inboundStub{name: "lan-mixed"}}, tunnel.Tunnel, true)
	if got := runtimeInboundCount(); got != baseline+1 {
		t.Errorf("one listeners: inbound open, count went %d -> %d", baseline, got)
	}
}
