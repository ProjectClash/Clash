package common

import (
	"fmt"
	"strings"
	"sync/atomic"

	C "github.com/ProjectClash/Clash/constant"
)

var protocolReadersParsed atomic.Bool

func ProtocolReadersParsed() bool { return protocolReadersParsed.Load() }

func SetProtocolReadersParsedForTest(parsed bool) bool { return protocolReadersParsed.Swap(parsed) }

type Protocol struct {
	Base
	protocol string
	adapter  string
	payload  string
}

const (
	ProtocolHTTP    = "HTTP"
	ProtocolHTTPS   = "HTTPS"
	ProtocolQUIC    = "QUIC"
	ProtocolSTUN    = "STUN"
	ProtocolMTProto = "MTPROTO"
)

func NewProtocol(payload, adapter string) (*Protocol, error) {
	name := strings.ToUpper(strings.TrimSpace(payload))
	switch name {
	case "TCP", "UDP", ProtocolHTTP, ProtocolHTTPS, ProtocolQUIC, ProtocolSTUN, ProtocolMTProto:
	case "TLS":
	case "DOH", "DOH3", "DOQ", "DOT", "DNS":
	default:
		return nil, fmt.Errorf("unsupported protocol %q, only TCP/UDP/HTTP/HTTPS/TLS/QUIC/STUN/MTPROTO", payload)
	}
	protocol := name
	if protocol == "TLS" {
		protocol = ProtocolHTTPS
	}
	switch protocol {
	case ProtocolHTTP, ProtocolHTTPS, ProtocolQUIC, ProtocolSTUN:
		protocolReadersParsed.Store(true)
	}
	return &Protocol{protocol: protocol, adapter: adapter, payload: name}, nil
}

func (p *Protocol) RuleType() C.RuleType { return C.Protocol }

func (p *Protocol) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	switch p.protocol {
	case "TCP":
		return metadata.NetWork == C.TCP, p.adapter
	case "UDP":
		return metadata.NetWork == C.UDP, p.adapter
	case ProtocolMTProto:
		return metadata.Type == C.MTPROTO, p.adapter
	case "DOH", "DOH3", "DOQ", "DOT", "DNS":
		return false, ""
	case ProtocolHTTP, ProtocolHTTPS:
		if metadata.NetWork != C.TCP {
			return false, ""
		}
	default:
		if metadata.NetWork != C.UDP {
			return false, ""
		}
	}
	if helper.Protocol == nil {
		return false, ""
	}
	return helper.Protocol() == p.protocol, p.adapter
}

func (p *Protocol) Adapter() string { return p.adapter }

func (p *Protocol) Payload() string { return p.payload }

var _ C.Rule = (*Protocol)(nil)
