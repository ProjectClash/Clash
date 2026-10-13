package outbound

import (
	"context"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/ca"
	"github.com/ProjectClash/Clash/transport/tuic"

	"github.com/metacubex/tls"
)


func clashTuicOption() TuicOption {
	return TuicOption{
		Name: "tuic", Server: "127.0.0.1", Port: 9,
		UUID: "9f3fe162-0d26-475b-9f8c-7f121923206a", Password: "password",
		SNI: "example.com", SkipCertVerify: true, ALPN: []string{"h3"},
		CongestionController: "bbr", UdpRelayMode: "native",
	}
}

const (
	clashTuicParsedNodes = 64
	clashTuicParsedNodeMaxHeap = 1400
)

func TestParsedTuicNodesHoldNoDialConfigs(t *testing.T) {
	nodes := make([]io.Closer, 0, clashTuicParsedNodes)
	t.Cleanup(func() {
		for _, node := range nodes {
			_ = node.Close()
		}
	})
	before, _ := clashSettle()
	for i := 0; i < clashTuicParsedNodes; i++ {
		node, err := NewTuic(clashTuicOption())
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, node)
	}
	after, _ := clashSettle()
	runtime.KeepAlive(nodes)
	perNode := (after - before) / clashTuicParsedNodes
	t.Logf("each parsed TUIC node holds %d bytes of live heap", perNode)
	if perNode > clashTuicParsedNodeMaxHeap {
		t.Errorf("each parsed TUIC node holds %d bytes (> %d); its TLS and QUIC configs must wait for the first dial", perNode, clashTuicParsedNodeMaxHeap)
	}
}

func clashTuicDial(node *Tuic) error {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	conn, err := node.DialContext(ctx, clashTCPMetadata())
	if err == nil {
		_ = conn.Close()
	}
	return err
}

func clashTuicNode(t *testing.T, option TuicOption) *Tuic {
	t.Helper()
	option.Port = clashClosedPort(t, "udp")
	node, err := NewTuic(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	return node
}

func TestTuicFirstDialsBuildTheConfigsOnceAndAReleaseDropsThem(t *testing.T) {
	node := clashTuicNode(t, clashTuicOption())
	if node.clashConfigs.built.Load() != nil {
		t.Fatal("parsing kept the configurations")
	}
	var dials sync.WaitGroup
	for i := 0; i < 16; i++ {
		dials.Add(1)
		go func() {
			defer dials.Done()
			_ = clashTuicDial(node)
		}()
	}
	dials.Wait()
	if builds := node.clashConfigBuilds(); builds != 1 {
		t.Fatalf("16 racing first dials built the configurations %d times, want 1", builds)
	}
	if !node.ReleaseSessions() {
		t.Fatal("TUIC declined a release")
	}
	if node.clashConfigs.built.Load() != nil {
		t.Fatal("the release kept the configurations")
	}
	_ = clashTuicDial(node)
	if builds := node.clashConfigBuilds(); builds != 2 {
		t.Fatalf("the dial after the release built %d times in all, want 2", builds)
	}
}

func TestATuicConfigBuildThatFailsIsNotKept(t *testing.T) {
	node := clashTuicNode(t, clashTuicOption())
	fingerprint := node.option.Fingerprint
	node.option.Fingerprint = "not a fingerprint"
	if err := clashTuicDial(node); err == nil || node.clashConfigs.built.Load() != nil {
		t.Fatalf("a failed build: dial error %v, configurations kept %v", err, node.clashConfigs.built.Load() != nil)
	}
	node.option.Fingerprint = fingerprint
	_ = clashTuicDial(node)
	if node.clashConfigs.built.Load() == nil || node.clashConfigBuilds() != 1 {
		t.Fatalf("the dial after a failed build built %d times", node.clashConfigBuilds())
	}
}

func TestTuicRefusesABadTLSSettingWhileParsing(t *testing.T) {
	option := clashTuicOption()
	option.Fingerprint = "not a fingerprint"
	_, err := NewTuic(option)
	if err == nil {
		t.Fatal("a bad fingerprint parsed")
	}
	_, want := ca.GetTLSConfig(ca.Option{TLSConfig: &tls.Config{}, Fingerprint: option.Fingerprint})
	if want == nil || err.Error() != want.Error() {
		t.Fatalf("parse error %q, want upstream's %v", err, want)
	}
}

func TestTuicDialConfigsCarryWhatNewTuicFilledIn(t *testing.T) {
	option := clashTuicOption()
	option.ALPN = nil
	node := clashTuicNode(t, option)
	tlsConfig, quicConfig, err := node.clashDialConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.ServerName != "example.com" || len(tlsConfig.NextProtos) != 1 || tlsConfig.NextProtos[0] != "h3" || tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("TLS: server name %q, ALPN %v, min version %x", tlsConfig.ServerName, tlsConfig.NextProtos, tlsConfig.MinVersion)
	}
	if quicConfig.KeepAlivePeriod != 10*time.Second || quicConfig.MaxIncomingStreams != 110 ||
		quicConfig.MaxDatagramFrameSize != int64(1252+tuic.PacketOverHeadV5) || !quicConfig.EnableDatagrams ||
		quicConfig.MaxStreamReceiveWindow != tuic.DefaultStreamReceiveWindow {
		t.Fatalf("QUIC: %+v", quicConfig)
	}

	option.DisableSni = true
	tlsConfig, _, err = clashTuicNode(t, option).clashDialConfigs()
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.ServerName != "" || !tlsConfig.InsecureSkipVerify {
		t.Fatalf("disable-sni: server name %q, insecure %v", tlsConfig.ServerName, tlsConfig.InsecureSkipVerify)
	}
}

func TestATuicNodeWithAClientCertificateKeepsItsConfigs(t *testing.T) {
	certificate, privateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	option := clashTuicOption()
	option.Certificate, option.PrivateKey = certificate, privateKey
	node := clashTuicNode(t, option)
	if node.clashConfigs.built.Load() == nil {
		t.Fatal("a node with a client certificate did not keep its configurations")
	}
	_ = clashTuicDial(node)
	node.ReleaseSessions()
	if node.clashConfigs.built.Load() == nil || node.clashConfigBuilds() != 0 {
		t.Fatalf("a node with a client certificate let its configurations go or built again (%d)", node.clashConfigBuilds())
	}
}
