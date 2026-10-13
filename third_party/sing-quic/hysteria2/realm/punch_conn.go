package realm

import (
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/metacubex/sing-quic/hysteria2/internal/stun"
	M "github.com/metacubex/sing/common/metadata"
)

type PunchPacketEvent struct {
	AttemptID string
	From      netip.AddrPort
	Type      byte
}

type STUNPacketEvent struct {
	Message *stun.Message
	Address netip.AddrPort
}

type PunchPacketConn struct {
	net.PacketConn
	udp        *net.UDPConn
	access     sync.RWMutex
	attempts   map[string]PunchMetadata
	events     chan PunchPacketEvent
	stunEvents chan STUNPacketEvent
}

func NewPunchPacketConn(conn net.PacketConn, eventBuffer int) *PunchPacketConn {
	udp, _ := conn.(*net.UDPConn)
	return &PunchPacketConn{
		PacketConn: conn,
		udp:        udp,
		attempts:   make(map[string]PunchMetadata),
		events:     make(chan PunchPacketEvent, eventBuffer),
		stunEvents: make(chan STUNPacketEvent, eventBuffer),
	}
}

func (c *PunchPacketConn) SyscallConn() (syscall.RawConn, error) {
	if c.udp == nil {
		return nil, ErrUnsupported
	}
	return c.udp.SyscallConn()
}

func (c *PunchPacketConn) SetReadBuffer(bytes int) error {
	if c.udp == nil {
		return ErrUnsupported
	}
	return c.udp.SetReadBuffer(bytes)
}

func (c *PunchPacketConn) SetWriteBuffer(bytes int) error {
	if c.udp == nil {
		return ErrUnsupported
	}
	return c.udp.SetWriteBuffer(bytes)
}

func (c *PunchPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		data := p[:n]
		if stun.IsMessage(data) {
			message, decodeErr := stun.Decode(data)
			address := M.SocksaddrFromNet(addr).Unwrap().AddrPort()
			if decodeErr == nil && address.IsValid() {
				select {
				case c.stunEvents <- STUNPacketEvent{Message: message, Address: address}:
				default:
				}
			}
			continue
		}
		c.access.RLock()
		if len(c.attempts) == 0 {
			c.access.RUnlock()
			return n, addr, nil
		}
		matched := false
		from := M.SocksaddrFromNet(addr).Unwrap().AddrPort()
		addressOK := from.IsValid()
		for attemptID, metadata := range c.attempts {
			packetType, decodeErr := DecodePunchPacket(data, metadata)
			if decodeErr != nil {
				continue
			}
			if addressOK {
				select {
				case c.events <- PunchPacketEvent{AttemptID: attemptID, From: from, Type: packetType}:
				default:
				}
			}
			matched = true
			break
		}
		c.access.RUnlock()
		if matched {
			continue
		}
		return n, addr, nil
	}
}

func (c *PunchPacketConn) AddAttempt(id string, metadata PunchMetadata) {
	c.access.Lock()
	defer c.access.Unlock()
	c.attempts[id] = metadata
}

func (c *PunchPacketConn) RemoveAttempt(id string) {
	c.access.Lock()
	defer c.access.Unlock()
	delete(c.attempts, id)
}

func (c *PunchPacketConn) Events() <-chan PunchPacketEvent {
	return c.events
}

func (c *PunchPacketConn) STUNEvents() <-chan STUNPacketEvent {
	return c.stunEvents
}

func (c *PunchPacketConn) Upstream() any {
	return c.PacketConn
}
