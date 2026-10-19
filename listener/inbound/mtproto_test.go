package inbound_test

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/listener/inbound"
)

const mtprotoSecret = "0123456789abcdef0123456789abcdef"

func mtprotoOption(secret string) *inbound.MTProtoOption {
	return &inbound.MTProtoOption{
		BaseOption: inbound.BaseOption{NameStr: "mtproto_inbound", Listen: "127.0.0.1", Port: "0"},
		Secret:     secret,
	}
}

func TestNewMTProtoRefusesBadSecrets(t *testing.T) {
	for _, c := range []struct {
		name, secret, mention string
	}{
		{"missing", "", "required"},
		{"fake TLS", "ee" + mtprotoSecret + "7777772e676f6f676c652e636f6d", "fake-TLS"},
		{"short", mtprotoSecret[:31], "32 hex"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := inbound.NewMTProto(mtprotoOption(c.secret))
			if err == nil || !strings.Contains(err.Error(), c.mention) {
				t.Fatalf("NewMTProto(secret %q) = %v, want an error mentioning %q", c.secret, err, c.mention)
			}
		})
	}
}

func TestInboundMTProtoListens(t *testing.T) {
	for _, secret := range []string{mtprotoSecret, "dd" + mtprotoSecret} {
		in, err := inbound.NewMTProto(mtprotoOption(secret))
		if err != nil {
			t.Fatal(err)
		}
		tunnel := &TestTunnel{HandleTCPConnFn: func(conn net.Conn, metadata *C.Metadata) { _ = conn.Close() }}
		if err := in.Listen(tunnel); err != nil {
			t.Fatal(err)
		}
		addr, err := netip.ParseAddrPort(in.Address())
		if err != nil || !addr.Addr().IsLoopback() || addr.Port() == 0 {
			_ = in.Close()
			t.Fatalf("Address() = %q (%v)", in.Address(), err)
		}
		if err := in.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
