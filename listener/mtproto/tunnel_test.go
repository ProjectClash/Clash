package mtproto

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/rules"
	"github.com/ProjectClash/Clash/tunnel"
)

func TestServerThroughTheTunnel(t *testing.T) {
	upload := bytes.Repeat([]byte("ping"), 8192)
	reply := bytes.Repeat([]byte("pong"), 8192)
	dc := newFakeDC(t, len(upload), reply)
	useDCTable(t, []dataCenter{{v4: dcFamily{general: []netip.AddrPort{dc.addr()}}}})

	inType, err := rules.ParseRule("IN-TYPE", "MTPROTO", "DIRECT", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	match, err := rules.ParseRule("MATCH", "", "REJECT", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	tunnel.UpdateProxies(map[string]C.Proxy{
		"DIRECT": adapter.NewProxy(outbound.NewDirect()),
		"REJECT": adapter.NewProxy(outbound.NewReject()),
	}, nil)
	tunnel.UpdateRules([]C.Rule{inType, match}, nil, nil)
	tunnel.SetMode(tunnel.Rule)
	tunnel.OnRunning()
	t.Cleanup(tunnel.OnSuspend)

	proxy := startTestListener(t, "dd"+testSecretHex, tunnel.Tunnel)
	secret := mustSecret(t, testSecretHex)
	client := dialTestClient(t, proxy, secret.key[:], tagPaddedBytes, -1)
	client.send(t, upload)
	if got := dc.read(t); got.tag != tagPaddedBytes || got.dc != -1 || !bytes.Equal(got.payload, upload) {
		t.Fatalf("the DC read tag %x dc %d and %d bytes", got.tag, got.dc, len(got.payload))
	}
	if back := client.receive(t, len(reply)); !bytes.Equal(back, reply) {
		t.Fatal("the client read another reply")
	}
}
