package clash

import (
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/log"
)

func hostLANAddress(t *testing.T) netip.Addr {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range interfaces {
		if candidate.Flags&net.FlagUp == 0 || candidate.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := candidate.Addrs()
		for _, a := range addrs {
			prefix, err := netip.ParsePrefix(a.String())
			if err != nil || !prefix.Addr().Is4() || prefix.Addr().IsLinkLocalUnicast() {
				continue
			}
			return prefix.Addr()
		}
	}
	t.Skip("no up interface with an IPv4 address on this machine")
	return netip.Addr{}
}

func mixedDocument(port int, allowLAN bool, extra string) string {
	return strings.Replace(helloYAML, "mode: rule",
		"mixed-port: "+strconv.Itoa(port)+"\nallow-lan: "+strconv.FormatBool(allowLAN)+"\n"+extra+"mode: rule", 1)
}

func socksAnswers(address string) bool {
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return false
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return false
	}
	return reply[0] == 5
}

func startedServiceForReload(t *testing.T, document string) *BoxService {
	t.Helper()
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(document); err != nil {
		t.Fatal(err)
	}
	return service
}

func TestAReloadThatTurnsAllowLanOnOpensTheMixedPortToTheLAN(t *testing.T) {
	lan := hostLANAddress(t)
	port := reserveProxySharePort(t)
	service := startedServiceForReload(t, mixedDocument(port, false, ""))
	loopback, fromLAN := net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), net.JoinHostPort(lan.String(), strconv.Itoa(port))
	if !socksAnswers(loopback) || socksAnswers(fromLAN) {
		t.Fatal("fixture: allow-lan false should answer on the loopback only")
	}
	if err := service.Reload(mixedDocument(port, true, "")); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !socksAnswers(fromLAN) {
		t.Fatalf("after a reload with allow-lan true, %s is still not answered: the listener was not rebuilt", fromLAN)
	}
	if err := service.Reload(mixedDocument(port, false, "")); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if socksAnswers(fromLAN) {
		t.Fatalf("after a reload with allow-lan false, %s is still answered", fromLAN)
	}
	if !socksAnswers(loopback) {
		t.Fatal("after allow-lan false the loopback is not answered")
	}
}

func TestAReloadMovesTheMixedPort(t *testing.T) {
	first, second := reserveProxySharePort(t), reserveProxySharePort(t)
	service := startedServiceForReload(t, mixedDocument(first, false, ""))
	if err := service.Reload(mixedDocument(second, false, "")); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !socksAnswers(net.JoinHostPort("127.0.0.1", strconv.Itoa(second))) {
		t.Fatal("the new mixed-port is not answered after the reload")
	}
	if socksAnswers(net.JoinHostPort("127.0.0.1", strconv.Itoa(first))) {
		t.Fatal("the old mixed-port is still answered after the reload")
	}
}

func TestAReloadKeepsAnUnchangedMixedListener(t *testing.T) {
	port := reserveProxySharePort(t)
	document := mixedDocument(port, false, "")
	service := startedServiceForReload(t, document)
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)
	if err := service.Reload(document); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	deadline := time.After(300 * time.Millisecond)
	for {
		select {
		case event := <-sub:
			if strings.Contains(event.Payload, "Mixed(http+socks) proxy listening at") {
				t.Fatalf("an unchanged mixed listener was rebuilt: %q", event.Payload)
			}
		case <-deadline:
			if !socksAnswers(net.JoinHostPort("127.0.0.1", strconv.Itoa(port))) {
				t.Fatal("the mixed-port is not answered after an unchanged reload")
			}
			return
		}
	}
}

func TestAReloadAppliesLanAllowedIPs(t *testing.T) {
	lan := hostLANAddress(t)
	port := reserveProxySharePort(t)
	fromLAN := net.JoinHostPort(lan.String(), strconv.Itoa(port))
	service := startedServiceForReload(t, mixedDocument(port, true, ""))
	if !socksAnswers(fromLAN) {
		t.Fatal("fixture: allow-lan true should answer the LAN address")
	}
	if err := service.Reload(mixedDocument(port, true, "lan-allowed-ips:\n  - 10.255.255.254/32\n")); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if socksAnswers(fromLAN) {
		t.Fatalf("after a reload that allows only 10.255.255.254/32, %s (from %s) is still answered", fromLAN, lan)
	}
}
