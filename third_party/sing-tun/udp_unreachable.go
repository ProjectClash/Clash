package tun

import (
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/sing-tun/internal/gtcpip/header"
)

type UDPUnreachableReporter interface {
	ReportUnreachable() error
}

func udpUnreachableQuote(source, destination netip.AddrPort) []byte {
	if source.Addr().Is4() {
		quote := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize)
		ipHdr := header.IPv4(quote)
		ipHdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(quote)),
			TTL:         64,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     source.Addr(),
			DstAddr:     destination.Addr(),
		})
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		header.UDP(ipHdr.Payload()).Encode(&header.UDPFields{
			SrcPort: source.Port(),
			DstPort: destination.Port(),
			Length:  header.UDPMinimumSize,
		})
		return quote
	}
	quote := make([]byte, header.IPv6MinimumSize+header.UDPMinimumSize)
	ipHdr := header.IPv6(quote)
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     header.UDPMinimumSize,
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           source.Addr(),
		DstAddr:           destination.Addr(),
	})
	header.UDP(ipHdr.Payload()).Encode(&header.UDPFields{
		SrcPort: source.Port(),
		DstPort: destination.Port(),
		Length:  header.UDPMinimumSize,
	})
	return quote
}

func udpUnreachableAnswerable(source, destination netip.Addr) bool {
	if !source.IsValid() || source.IsUnspecified() || source.IsMulticast() {
		return false
	}
	if !destination.IsValid() || destination.IsUnspecified() || destination.IsMulticast() {
		return false
	}
	return destination != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

type icmpErrorLimiter struct {
	access sync.Mutex
	tokens float64
	last   time.Time
}

const (
	icmpErrorsPerSecond = 1000
	icmpErrorBurst      = 50
)

func (l *icmpErrorLimiter) allow() bool {
	l.access.Lock()
	defer l.access.Unlock()
	now := time.Now()
	if l.last.IsZero() {
		l.tokens = icmpErrorBurst
	} else {
		l.tokens += now.Sub(l.last).Seconds() * icmpErrorsPerSecond
		if l.tokens > icmpErrorBurst {
			l.tokens = icmpErrorBurst
		}
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
