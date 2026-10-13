//go:build with_gvisor

package clash

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
)

func goroutinesDownTo(want int, within time.Duration) int {
	deadline := time.Now().Add(within)
	for {
		runtime.GC()
		if now := runtime.NumGoroutine(); now <= want || time.Now().After(deadline) {
			return now
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func settledGoroutines() int {
	last := -1
	for i := 0; i < 100; i++ {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
		now := runtime.NumGoroutine()
		if now == last {
			return now
		}
		last = now
	}
	return last
}

func goroutinesIn(frames ...string) int {
	var profile strings.Builder
	_ = pprof.Lookup("goroutine").WriteTo(&profile, 1)
	count := 0
	_, groups, _ := strings.Cut(profile.String(), "\n")
	for _, group := range strings.Split(groups, "\n\n") {
		header, _, _ := strings.Cut(strings.TrimSpace(group), " @ ")
		n, err := strconv.Atoi(header)
		if err != nil {
			continue
		}
		for _, frame := range frames {
			if strings.Contains(group, frame) {
				count += n
				break
			}
		}
	}
	return count
}

func pinSessionReleaseOff(t *testing.T) {
	t.Helper()
	adapter.SetURLTestFinished(nil)
	t.Cleanup(func() { adapter.SetURLTestFinished(nil) })
}

type releaseCheck struct {
	clientFrames []string
	serverSlack  int
}

const gvisorProcessor = "tcp.(*processor).start"

func requireReleaseAndRedial(t *testing.T, proxy C.Proxy, target string, requests *atomic.Int32, check releaseCheck) {
	t.Helper()
	pinSessionReleaseOff(t)
	parsed := settledGoroutines()
	parsedProcessors := goroutinesIn(gvisorProcessor)
	for round := 1; round <= 2; round++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		_, err := proxy.URLTest(ctx, target, nil)
		cancel()
		if err != nil {
			t.Fatalf("round %d: URLTest() error = %v", round, err)
		}
		if got := requests.Load(); got != int32(round) {
			t.Fatalf("round %d: the target saw %d requests", round, got)
		}
		built := settledGoroutines()
		builtClient := goroutinesIn(check.clientFrames...)
		outbound.ReleaseProbedSession(proxy.Adapter())
		released := goroutinesDownTo(parsed+check.serverSlack, 5*time.Second)
		releasedClient := goroutinesIn(check.clientFrames...)
		releasedProcessors := goroutinesIn(gvisorProcessor)
		t.Logf("round %d: goroutines parsed %d, after the probe %d (node %d), after the release %d (node %d); gVisor processors parsed %d, after the release %d",
			round, parsed, built, builtClient, released, releasedClient, parsedProcessors, releasedProcessors)
		if builtClient == 0 {
			t.Fatalf("round %d: the probe built nothing the check recognises", round)
		}
		if releasedClient != 0 {
			t.Fatalf("round %d: %d of the node's goroutines run after the release", round, releasedClient)
		}
		if releasedProcessors > parsedProcessors {
			t.Fatalf("round %d: %d gVisor processors after the release, %d when parsed", round, releasedProcessors, parsedProcessors)
		}
		if released > parsed+check.serverSlack {
			t.Fatalf("round %d: %d goroutines after the release, %d when parsed", round, released, parsed)
		}
	}
}

func parseKeepingOutbound(t *testing.T, mapping map[string]any) C.Proxy {
	t.Helper()
	previous := adapter.SetNodeCatalog(false)
	defer adapter.SetNodeCatalog(previous)
	proxy, err := adapter.ParseProxy(mapping)
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	return proxy
}

func controlledWireGuardReleaseFixture(t *testing.T, mode string) (map[string]any, string, *atomic.Int32, releaseCheck) {
	t.Helper()
	serverPrivate, serverPublic := generateControlledWireGuardKeyPair(t)
	clientPrivate, clientPublic := generateControlledWireGuardKeyPair(t)
	peerAddress4 := netip.MustParseAddr("10.77.0.1")
	peerAddress6 := netip.MustParseAddr("fd00:77::1")
	var targetRequests, dnsQueries atomic.Int32
	serverPort, tcpPort4, _, _, _, _, _ := startControlledWireGuardPeer(t, peerAddress4, peerAddress6, serverPrivate, clientPublic, &targetRequests, &dnsQueries)
	mapping := map[string]any{
		"name":        "controlled-wireguard-release",
		"type":        "wireguard",
		"server":      "127.0.0.1",
		"port":        serverPort,
		"ip":          "10.77.0.2",
		"ipv6":        "fd00:77::2",
		"private-key": base64.StdEncoding.EncodeToString(clientPrivate),
		"public-key":  base64.StdEncoding.EncodeToString(serverPublic),
		"udp":         true,
		"ip-stack":    map[string]any{"mode": mode},
	}
	target := "http://" + net.JoinHostPort(peerAddress4.String(), strconv.Itoa(int(tcpPort4)))
	return mapping, target, &targetRequests, releaseCheck{clientFrames: []string{"sing-wireguard.(*ClientBind)", "adapter/outbound.(*WireGuard)"}}
}

func TestControlledWireGuardReleaseAndRedial(t *testing.T) {
	for _, mode := range []string{"auto", "mips"} {
		t.Run(mode, func(t *testing.T) {
			pinUnifiedDelayOff(t)
			mapping, target, requests, check := controlledWireGuardReleaseFixture(t, mode)
			proxy := parseKeepingOutbound(t, mapping)
			defer proxy.Close()
			requireReleaseAndRedial(t, proxy, target, requests, check)
		})
	}
}

func controlledMASQUEReleaseFixture(t *testing.T) (map[string]any, string, *atomic.Int32, releaseCheck) {
	t.Helper()
	serverCertificate, _, serverPublicKey := newControlledMASQUEIdentity(t, "localhost")
	_, clientPrivateKey, _ := newControlledMASQUEIdentity(t, "client.controlled.test")
	peerAddress := netip.MustParseAddr("10.88.0.1")
	targetRequests := &atomic.Int32{}
	peer := startControlledMASQUEPeer(t, targetRequests, peerAddress)
	serverPort := startControlledMASQUEServer(t, serverCertificate, peer.tun, []netip.Prefix{netip.MustParsePrefix("10.88.0.2/32")})
	privateKeyDER, err := x509.MarshalECPrivateKey(clientPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(serverPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	mapping := map[string]any{
		"name":              "controlled-masque-release",
		"type":              "masque",
		"server":            "127.0.0.1",
		"port":              serverPort,
		"private-key":       base64.StdEncoding.EncodeToString(privateKeyDER),
		"public-key":        base64.StdEncoding.EncodeToString(publicKeyDER),
		"ip":                "10.88.0.2",
		"uri":               fmt.Sprintf("https://localhost:%d/connect-ip", serverPort),
		"sni":               "localhost",
		"udp":               true,
		"handshake-timeout": 10,
	}
	target := "http://" + net.JoinHostPort(peerAddress.String(), strconv.Itoa(int(peer.tcpPorts[peerAddress])))
	return mapping, target, targetRequests, releaseCheck{
		clientFrames: []string{"adapter/outbound.(*Masque)", "quic-go.(*Transport).doDial", "http3.(*Transport).NewClientConn", "http3.(*ClientConn)"},
		serverSlack:  1,
	}
}

func TestControlledMASQUEReleaseAndRedial(t *testing.T) {
	pinUnifiedDelayOff(t)
	mapping, target, requests, check := controlledMASQUEReleaseFixture(t)
	proxy := parseKeepingOutbound(t, mapping)
	defer proxy.Close()
	requireReleaseAndRedial(t, proxy, target, requests, check)
}

func TestControlledCatalogNodeReleasesAndRedials(t *testing.T) {
	pinUnifiedDelayOff(t)
	mapping, target, requests, check := controlledWireGuardReleaseFixture(t, "auto")
	proxy, err := adapter.ParseProxy(mapping)
	if err != nil {
		t.Fatalf("ParseProxy() error = %v", err)
	}
	defer proxy.Close()
	if catalog, _ := outbound.IsCatalogNode(proxy.Adapter()); !catalog {
		t.Fatal("not a catalog node")
	}
	requireReleaseAndRedial(t, proxy, target, requests, check)
}

func TestControlledMASQUEH2ReleaseAndRedial(t *testing.T) {
	pinUnifiedDelayOff(t)
	serverCertificate, serverPrivateKey, serverPublicKey := newControlledMASQUEIdentity(t, "localhost")
	_, clientPrivateKey, _ := newControlledMASQUEIdentity(t, "client.controlled.test")
	peerAddress := netip.MustParseAddr("10.89.0.1")
	var targetRequests atomic.Int32
	peer := startControlledMASQUEPeer(t, &targetRequests, peerAddress)
	serverPort := startControlledMASQUEH2Server(t, stdtls.Certificate{
		Certificate: serverCertificate.Certificate,
		PrivateKey:  serverPrivateKey,
		Leaf:        serverCertificate.Leaf,
	}, peer.tun)
	privateKeyDER, err := x509.MarshalECPrivateKey(clientPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(serverPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	mapping := map[string]any{
		"name":              "controlled-masque-h2-release",
		"type":              "masque",
		"server":            "127.0.0.1",
		"port":              serverPort,
		"private-key":       base64.StdEncoding.EncodeToString(privateKeyDER),
		"public-key":        base64.StdEncoding.EncodeToString(publicKeyDER),
		"ip":                "10.89.0.2",
		"uri":               fmt.Sprintf("https://localhost:%d/connect-ip", serverPort),
		"sni":               "localhost",
		"network":           "h2",
		"udp":               true,
		"handshake-timeout": 10,
	}
	proxy := parseKeepingOutbound(t, mapping)
	defer proxy.Close()
	target := "http://" + net.JoinHostPort(peerAddress.String(), strconv.Itoa(int(peer.tcpPorts[peerAddress])))
	requireReleaseAndRedial(t, proxy, target, &targetRequests, releaseCheck{
		clientFrames: []string{"adapter/outbound.(*Masque)"},
		serverSlack:  1,
	})
}

func TestControlledWireGuardInteropWithSessionReleaseArmed(t *testing.T) {
	for _, mode := range []string{"auto", "mips", "gvisor"} {
		t.Run(mode, func(t *testing.T) {
			armedSessionRelease(t)
			testControlledWireGuardInterop(t, mode)
		})
	}
}
