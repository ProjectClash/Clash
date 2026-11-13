package tunnel

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"

	N "github.com/ProjectClash/Clash/common/net"
)

func newEndableSession(t *testing.T) (session blockingPacketConn, end func()) {
	t.Helper()
	remote, peer := net.Pipe()
	session = blockingPacketConn{nothingConn: nothingConn{N.NewExtendedConn(remote)}, closed: make(chan struct{}), once: &sync.Once{}}
	t.Cleanup(func() { _ = session.Close(); _ = remote.Close(); _ = peer.Close() })
	return session, func() { _ = session.Close() }
}

func openUDPFlow(packet C.UDPPacket) {
	metadata := tunFlowTo("192.0.2.1")
	metadata.NetWork = C.UDP
	handleUDPConn(C.NewPacketAdapter(packet, metadata))
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !done(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
	}
}

func waitSessionLeftTable(t *testing.T, key string) {
	t.Helper()
	waitFor(t, "an ended session stayed in the table", func() bool {
		if _, left := natTable.GetOrCreate(key, newPacketSender); !left {
			natTable.Delete(key)
			return true
		}
		return false
	})
}

func TestAUDPSessionThatEndsEndsItsStackSession(t *testing.T) {
	session, end := newEndableSession(t)
	var listens atomic.Int32
	proxy := &dialProxy{doorProxy: doorProxy{name: "out", typ: C.Shadowsocks}, listen: func() (C.PacketConn, error) {
		listens.Add(1)
		return session, nil
	}}
	withVerdictTunnel(t, "out", proxy)

	packet := newFlowPacket(40601)
	openUDPFlow(packet)
	waitFor(t, "the flow's session never opened", func() bool { return listens.Load() == 1 })
	select {
	case <-packet.flowClosed:
		t.Fatal("a flow whose session is open had its stack session ended")
	case <-time.After(200 * time.Millisecond):
	}

	end()
	select {
	case <-packet.flowClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("a session that ended left its stack session reading for the stack's timeout")
	}
	waitSessionLeftTable(t, packet.LocalAddr().String())
}

func TestADatagramAfterAnEndedSessionOpensANewOne(t *testing.T) {
	first, endFirst := newEndableSession(t)
	second, _ := newEndableSession(t)
	var listens atomic.Int32
	proxy := &dialProxy{doorProxy: doorProxy{name: "out", typ: C.Shadowsocks}, listen: func() (C.PacketConn, error) {
		if listens.Add(1) == 1 {
			return first, nil
		}
		return second, nil
	}}
	withVerdictTunnel(t, "out", proxy)

	packet := newFlowPacket(40602)
	openUDPFlow(packet)
	waitFor(t, "the flow's session never opened", func() bool { return listens.Load() == 1 })
	endFirst()
	select {
	case <-packet.flowClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("the ended session's stack session was not ended")
	}
	waitSessionLeftTable(t, packet.LocalAddr().String())

	again := newFlowPacket(40602)
	openUDPFlow(again)
	waitFor(t, "a datagram after an ended session opened no new one", func() bool { return listens.Load() == 2 })
	select {
	case <-again.flowClosed:
		t.Fatal("the new session's flow was ended with the old one")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestAnEndedSessionOfAnInboundWithoutFlowsLeavesTheTable(t *testing.T) {
	session, end := newEndableSession(t)
	var listens atomic.Int32
	proxy := &dialProxy{doorProxy: doorProxy{name: "out", typ: C.Shadowsocks}, listen: func() (C.PacketConn, error) {
		listens.Add(1)
		return session, nil
	}}
	withVerdictTunnel(t, "out", proxy)
	packet := newKeyedPacket(40603)
	openUDPFlow(packet)
	waitFor(t, "the flow's session never opened", func() bool { return listens.Load() == 1 })
	end()
	waitSessionLeftTable(t, packet.LocalAddr().String())
}

func TestARejectedFlowKeepsItsStackSession(t *testing.T) {
	var listens atomic.Int32
	proxy := &dialProxy{doorProxy: doorProxy{name: "out", typ: C.Reject}, listen: func() (C.PacketConn, error) {
		listens.Add(1)
		return nothingPacketConn{}, nil
	}}
	withVerdictTunnel(t, "out", proxy)
	packet := newFlowPacket(40604)
	openUDPFlow(packet)
	waitFor(t, "the rejected flow's session never opened", func() bool { return listens.Load() == 1 })
	waitSessionLeftTable(t, packet.LocalAddr().String())
	select {
	case <-packet.flowClosed:
		t.Fatal("a rejected flow had its stack session ended")
	case <-time.After(300 * time.Millisecond):
	}
}
