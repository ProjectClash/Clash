package common

import (
	"testing"

	C "github.com/ProjectClash/Clash/constant"
)

func TestNewProtocolTakesTheSurgeAndStashNames(t *testing.T) {
	for payload, want := range map[string]string{
		"TCP": "TCP", "udp": "UDP", "HTTP": "HTTP", "HTTPS": "HTTPS", "TLS": "HTTPS",
		"QUIC": "QUIC", "STUN": "STUN", "MTProto": "MTPROTO", "MTPROTO": "MTPROTO",
	} {
		rule, err := NewProtocol(payload, "P")
		if err != nil {
			t.Errorf("PROTOCOL,%s refused: %v", payload, err)
			continue
		}
		if rule.protocol != want || rule.RuleType() != C.Protocol || rule.Adapter() != "P" {
			t.Errorf("PROTOCOL,%s read as %q (%s, %s), want %q", payload, rule.protocol, rule.RuleType(), rule.Adapter(), want)
		}
	}
	for _, payload := range []string{"DOH", "DOT", "DNS"} {
		rule, err := NewProtocol(payload, "P")
		if err != nil {
			t.Errorf("PROTOCOL,%s refused: %v", payload, err)
			continue
		}
		if matched, _ := rule.Match(&C.Metadata{NetWork: C.TCP}, C.RuleMatchHelper{Protocol: func() string { return ProtocolHTTPS }}); matched {
			t.Errorf("PROTOCOL,%s matched an app's flow; it names only Surge's own DNS", payload)
		}
	}
	for _, payload := range []string{"ICMP", "", "HTTP3"} {
		if _, err := NewProtocol(payload, "P"); err == nil {
			t.Errorf("PROTOCOL,%s was accepted", payload)
		}
	}
}

func TestProtocolTCPAndUDPAreTheNetwork(t *testing.T) {
	tcp, _ := NewProtocol("TCP", "P")
	udp, _ := NewProtocol("UDP", "P")
	for network, want := range map[C.NetWork][2]bool{C.TCP: {true, false}, C.UDP: {false, true}} {
		metadata := &C.Metadata{NetWork: network, Type: C.MTPROTO}
		if got, _ := tcp.Match(metadata, C.RuleMatchHelper{}); got != want[0] {
			t.Errorf("PROTOCOL,TCP on %s: %v", network, got)
		}
		if got, _ := udp.Match(metadata, C.RuleMatchHelper{}); got != want[1] {
			t.Errorf("PROTOCOL,UDP on %s: %v", network, got)
		}
	}
}
