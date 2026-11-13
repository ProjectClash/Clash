package clash

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/listener/sing_tun"
	"golang.org/x/sys/unix"
)

func stunRequest() []byte {
	message := make([]byte, 28)
	binary.BigEndian.PutUint16(message[0:], 0x0001)
	binary.BigEndian.PutUint16(message[2:], 8)
	binary.BigEndian.PutUint32(message[4:], 0x2112a442)
	binary.BigEndian.PutUint16(message[20:], 0x8022)
	binary.BigEndian.PutUint16(message[22:], 4)
	return message
}

func TestTheGoStackGivesAUDPFlowItsProtocolsTimeout(t *testing.T) {
	handler := goStackHandler{handler: &sing_tun.ListenerHandler{}, door: &fakeDoor{}}
	app := netip.MustParseAddrPort("198.18.0.1:50000")
	for _, c := range []struct {
		name        string
		destination string
		datagram    []byte
		want        time.Duration
	}{
		{"a STUN request on Google's STUN port", "192.0.2.1:19302", stunRequest(), 10 * time.Second},
		{"anything to the STUN port", "192.0.2.1:3478", []byte("hello"), 10 * time.Second},
		{"anything to QUIC's port", "192.0.2.1:443", []byte("hello"), 30 * time.Second},
		{"a game's datagram", "192.0.2.1:27015", []byte("hello"), 0},
	} {
		verdict := handler.JudgeFlow(unix.IPPROTO_UDP, app, netip.MustParseAddrPort(c.destination), c.datagram)
		if verdict.UDPTimeout != c.want {
			t.Errorf("%s: the stack is told to keep the session %v, want %v", c.name, verdict.UDPTimeout, c.want)
		}
	}
	if verdict := handler.JudgeFlow(unix.IPPROTO_TCP, app, netip.MustParseAddrPort("192.0.2.1:3478"), nil); verdict.UDPTimeout != 0 {
		t.Errorf("a TCP flow was given a UDP timeout of %v", verdict.UDPTimeout)
	}
}
