package clash

import (
	"fmt"
	"net"
	"strconv"
	"testing"

	coreListener "github.com/ProjectClash/Clash/listener"
)

func portIsFree(port int) bool {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

func udpPortIsFree(port int) bool {
	conn, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func TestCloseReleasesEveryInboundTheConfigurationOpened(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	ports := map[string]int{}
	for _, name := range []string{"port", "socks-port", "mixed-port", "listener", "dns", "tunnel"} {
		port, _ := strconv.Atoi(freeLoopbackPort(t))
		ports[name] = port
	}
	udp := map[string]bool{"socks-port": true, "mixed-port": true, "listener": true, "dns": true, "tunnel": true}
	config := fmt.Sprintf(`mode: rule
allow-lan: false
bind-address: 127.0.0.1
port: %d
socks-port: %d
mixed-port: %d
listeners:
  - {name: extra, type: mixed, port: %d, listen: 127.0.0.1, udp: true}
tunnels:
  - {network: [tcp, udp], address: 127.0.0.1:%d, target: 127.0.0.1:9, proxy: DIRECT}
dns:
  enable: true
  listen: 127.0.0.1:%d
  nameserver: [8.8.8.8]
rules:
  - MATCH,DIRECT
`, ports["port"], ports["socks-port"], ports["mixed-port"], ports["listener"], ports["tunnel"], ports["dns"])

	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	for round := 1; round <= 2; round++ {
		if err := service.Start(config); err != nil {
			t.Fatalf("Start round %d: %v", round, err)
		}
		for name, port := range ports {
			if portIsFree(port) {
				t.Fatalf("round %d: %s %d is not listening on TCP after Start", round, name, port)
			}
			if udp[name] && udpPortIsFree(port) {
				t.Fatalf("round %d: %s %d is not listening on UDP after Start", round, name, port)
			}
		}
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
		for name, port := range ports {
			if !portIsFree(port) {
				t.Fatalf("round %d: %s %d is still held on TCP after Close", round, name, port)
			}
			if udp[name] && !udpPortIsFree(port) {
				t.Fatalf("round %d: %s %d is still held on UDP after Close", round, name, port)
			}
		}
		if count := coreListener.InboundListenerCount(); count != 0 {
			t.Fatalf("round %d: %d listeners: entries survive Close", round, count)
		}
		if ports := coreListener.GetPorts(); ports.Port != 0 || ports.SocksPort != 0 || ports.MixedPort != 0 {
			t.Fatalf("round %d: the core still reports ports after Close: %+v", round, ports)
		}
	}
}
