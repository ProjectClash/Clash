package tunnel

import (
	"time"

	RC "github.com/ProjectClash/Clash/rules/common"
)

const (
	udpProtocolDNS  = "DNS"
	udpProtocolNTP  = "NTP"
	udpProtocolDTLS = "DTLS"
)

var udpPortProtocols = map[uint16]string{
	53:   udpProtocolDNS,
	123:  udpProtocolNTP,
	3478: RC.ProtocolSTUN,
	443:  RC.ProtocolQUIC,
}

var udpProtocolTimeouts = map[string]time.Duration{
	udpProtocolDNS:  10 * time.Second,
	udpProtocolNTP:  10 * time.Second,
	RC.ProtocolSTUN: 10 * time.Second,
	RC.ProtocolQUIC: 30 * time.Second,
	udpProtocolDTLS: 30 * time.Second,
}

func isDTLSRecord(datagram []byte) bool {
	if len(datagram) < 13 {
		return false
	}
	switch datagram[0] {
	case 20, 21, 22, 23, 25:
	default:
		return false
	}
	return datagram[1] == 0xfe && (datagram[2] == 0xff || datagram[2] == 0xfd)
}

func udpFlowTimeout(classified string, datagram []byte, port uint16) time.Duration {
	protocol := classified
	if protocol == "" && isDTLSRecord(datagram) {
		protocol = udpProtocolDTLS
	}
	if protocol == "" {
		protocol = udpPortProtocols[port]
	}
	return udpProtocolTimeouts[protocol]
}

func UDPProtocolTimeout(firstDatagram []byte, port uint16) time.Duration {
	return udpFlowTimeout(classifyDatagram(firstDatagram), firstDatagram, port)
}

func udpSessionTimeout(classified string, firstDatagram []byte, port uint16) time.Duration {
	if timeout := udpFlowTimeout(classified, firstDatagram, port); timeout > 0 {
		return timeout
	}
	return udpTimeout
}
