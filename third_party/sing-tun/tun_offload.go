package tun

import (
	"encoding/binary"
	"fmt"

	"github.com/metacubex/sing-tun/internal/gtcpip"
	"github.com/metacubex/sing-tun/internal/gtcpip/checksum"
	"github.com/metacubex/sing-tun/internal/gtcpip/header"
)

const (
	gsoMaxSize     = 65536
	idealBatchSize = 128
)

type GSOType int

const (
	GSONone GSOType = iota
	GSOTCPv4
	GSOTCPv6
	GSOUDPL4
)

func (g GSOType) String() string {
	switch g {
	case GSONone:
		return "GSONone"
	case GSOTCPv4:
		return "GSOTCPv4"
	case GSOTCPv6:
		return "GSOTCPv6"
	case GSOUDPL4:
		return "GSOUDPL4"
	default:
		return "unknown"
	}
}

type GSOOptions struct {
	GSOType GSOType
	HdrLen uint16
	CsumStart uint16
	CsumOffset uint16
	GSOSize uint16
	NeedsCsum bool
}

const (
	ipv4SrcAddrOffset = 12
	ipv6SrcAddrOffset = 8
)

const tcpFlagsOffset = 13

const (
	tcpFlagFIN uint8 = 0x01
	tcpFlagPSH uint8 = 0x08
	tcpFlagACK uint8 = 0x10
)

const (
	ipProtoTCP = 6
	ipProtoUDP = 17
)

func GSOSplit(in []byte, options GSOOptions, outBufs [][]byte, sizes []int, outOffset int) (int, error) {
	cSumAt := int(options.CsumStart) + int(options.CsumOffset)
	if cSumAt+1 >= len(in) {
		return 0, fmt.Errorf("end of checksum offset (%d) exceeds packet length (%d)", cSumAt+1, len(in))
	}

	if len(in) < int(options.HdrLen) {
		return 0, fmt.Errorf("length of packet (%d) < GSO HdrLen (%d)", len(in), options.HdrLen)
	}

	payloadLen := len(in) - int(options.HdrLen)
	if options.GSOType == GSONone || payloadLen < int(options.GSOSize) {
		if len(in) > len(outBufs[0][outOffset:]) {
			return 0, fmt.Errorf("length of packet (%d) exceeds output element length (%d)", len(in), len(outBufs[0][outOffset:]))
		}
		if options.NeedsCsum {
			initial := binary.BigEndian.Uint16(in[cSumAt:])
			in[cSumAt], in[cSumAt+1] = 0, 0
			binary.BigEndian.PutUint16(in[cSumAt:], ^checksum.Checksum(in[options.CsumStart:], initial))
		}
		sizes[0] = copy(outBufs[0][outOffset:], in)
		return 1, nil
	}

	if options.HdrLen < options.CsumStart {
		return 0, fmt.Errorf("GSO HdrLen (%d) < GSO CsumStart (%d)", options.HdrLen, options.CsumStart)
	}

	ipVersion := in[0] >> 4
	switch ipVersion {
	case 4:
		if options.GSOType != GSOTCPv4 && options.GSOType != GSOUDPL4 {
			return 0, fmt.Errorf("ip header version: %d, GSO type: %s", ipVersion, options.GSOType)
		}
		if len(in) < 20 {
			return 0, fmt.Errorf("length of packet (%d) < minimum ipv4 header size (%d)", len(in), 20)
		}
	case 6:
		if options.GSOType != GSOTCPv6 && options.GSOType != GSOUDPL4 {
			return 0, fmt.Errorf("ip header version: %d, GSO type: %s", ipVersion, options.GSOType)
		}
		if len(in) < 40 {
			return 0, fmt.Errorf("length of packet (%d) < minimum ipv6 header size (%d)", len(in), 40)
		}
	default:
		return 0, fmt.Errorf("invalid ip header version: %d", ipVersion)
	}

	iphLen := int(options.CsumStart)
	srcAddrOffset := ipv6SrcAddrOffset
	addrLen := 16
	if ipVersion == 4 {
		srcAddrOffset = ipv4SrcAddrOffset
		addrLen = 4
	}
	transportCsumAt := int(options.CsumStart + options.CsumOffset)
	var firstTCPSeqNum uint32
	var srcTCPFlags uint8
	var protocol uint8
	if options.GSOType == GSOTCPv4 || options.GSOType == GSOTCPv6 {
		protocol = ipProtoTCP
		if len(in) < int(options.CsumStart)+20 {
			return 0, fmt.Errorf("length of packet (%d) < GSO CsumStart (%d) + minimum TCP header size (%d)",
				len(in), options.CsumStart, 20)
		}
		firstTCPSeqNum = binary.BigEndian.Uint32(in[options.CsumStart+4:])
		srcTCPFlags = in[options.CsumStart+tcpFlagsOffset]
	} else {
		protocol = ipProtoUDP
	}
	pseudoSumBase := header.PseudoHeaderChecksum(tcpip.TransportProtocolNumber(protocol), in[srcAddrOffset:srcAddrOffset+addrLen], in[srcAddrOffset+addrLen:srcAddrOffset+addrLen*2], 0)
	nextSegmentDataAt := int(options.HdrLen)
	i := 0
	for ; nextSegmentDataAt < len(in); i++ {
		if i == len(outBufs) {
			return i - 1, ErrTooManySegments
		}
		nextSegmentEnd := nextSegmentDataAt + int(options.GSOSize)
		if nextSegmentEnd > len(in) {
			nextSegmentEnd = len(in)
		}
		segmentDataLen := nextSegmentEnd - nextSegmentDataAt
		totalLen := int(options.HdrLen) + segmentDataLen
		sizes[i] = totalLen
		out := outBufs[i][outOffset:]

		copy(out[:options.HdrLen], in[:options.HdrLen])
		if ipVersion == 4 {
			if i > 0 {
				id := binary.BigEndian.Uint16(out[4:])
				id += uint16(i)
				binary.BigEndian.PutUint16(out[4:], id)
			}
			out[10], out[11] = 0, 0
			binary.BigEndian.PutUint16(out[2:], uint16(totalLen))
			ipv4CSum := ^checksum.Checksum(out[:iphLen], 0)
			binary.BigEndian.PutUint16(out[10:], ipv4CSum)
		} else {
			binary.BigEndian.PutUint16(out[4:], uint16(totalLen-iphLen))
		}

		if protocol == ipProtoTCP {
			tcpSeq := firstTCPSeqNum + uint32(options.GSOSize*uint16(i))
			binary.BigEndian.PutUint32(out[options.CsumStart+4:], tcpSeq)
			tcpFlags := srcTCPFlags
			if nextSegmentEnd != len(in) {
				tcpFlags &^= tcpFlagFIN | tcpFlagPSH
			}
			out[options.CsumStart+tcpFlagsOffset] = tcpFlags
		} else {
			binary.BigEndian.PutUint16(out[options.CsumStart+4:], uint16(segmentDataLen)+(options.HdrLen-options.CsumStart))
		}

		copy(out[options.HdrLen:], in[nextSegmentDataAt:nextSegmentEnd])

		out[transportCsumAt], out[transportCsumAt+1] = 0, 0
		transportHeaderLen := int(options.HdrLen - options.CsumStart)
		lenForPseudo := uint16(transportHeaderLen + segmentDataLen)
		transportCSum := checksum.Combine(pseudoSumBase, lenForPseudo)
		transportCSum = ^checksum.Checksum(out[options.CsumStart:totalLen], transportCSum)
		binary.BigEndian.PutUint16(out[options.CsumStart+options.CsumOffset:], transportCSum)

		nextSegmentDataAt += int(options.GSOSize)
	}
	return i, nil
}
