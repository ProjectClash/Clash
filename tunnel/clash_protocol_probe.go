package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	C "github.com/ProjectClash/Clash/constant"
	RC "github.com/ProjectClash/Clash/rules/common"
)


const protocolProbeTimeout = time.Second

type protocolProbeKey struct{}

func withProtocolProbe(parent context.Context, probe func() string) context.Context {
	return context.WithValue(parent, protocolProbeKey{}, probe)
}

func protocolProbeOf(ctx context.Context) func() string {
	if ctx == nil {
		return nil
	}
	probe, _ := ctx.Value(protocolProbeKey{}).(func() string)
	return probe
}

func tcpProtocolProbe(conn *N.BufferedConn, peek *sync.Mutex, metadata *C.Metadata) func() string {
	return func() string {
		peek.Lock()
		defer peek.Unlock()
		if conn.Buffered() == 0 {
			if sniffingStandsAside(conn, metadata) || serverSpeaksFirst(metadata.DstPort) {
				return ""
			}
			_ = conn.SetReadDeadline(time.Now().Add(protocolProbeTimeout))
			_, _ = conn.Peek(1)
			_ = conn.SetReadDeadline(time.Time{})
		}
		n := conn.Buffered()
		if n == 0 {
			return ""
		}
		if n > 16 {
			n = 16
		}
		first, _ := conn.Peek(n)
		return classifyStreamStart(first)
	}
}

var httpRequestStarts = [...][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("DELETE "),
	[]byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "), []byte("TRACE "),
	[]byte("PRI * HTTP/2.0"),
}

func classifyStreamStart(b []byte) string {
	if len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01 {
		return RC.ProtocolHTTPS
	}
	for _, start := range httpRequestStarts {
		if bytes.HasPrefix(b, start) {
			return RC.ProtocolHTTP
		}
	}
	return ""
}

const (
	quicVersion1 = 0x00000001
	quicVersion2 = 0x6b3343cf
)

const stunMagicCookie = 0x2112A442

func classifyDatagram(b []byte) string {
	if len(b) >= 1200 && b[0]&0xc0 == 0xc0 {
		version := binary.BigEndian.Uint32(b[1:5])
		packetType := (b[0] & 0x30) >> 4
		switch {
		case version == quicVersion1 && packetType == 0,
			version == quicVersion2 && packetType == 1,
			version&0xffffff00 == 0xff000000 && packetType == 0:
			return RC.ProtocolQUIC
		}
	}
	if len(b) >= 20 && b[0]&0xc0 == 0 && binary.BigEndian.Uint32(b[4:8]) == stunMagicCookie {
		if length := int(binary.BigEndian.Uint16(b[2:4])); length%4 == 0 && 20+length == len(b) {
			return RC.ProtocolSTUN
		}
	}
	return ""
}

func (f *flowMatch) flowProtocol() string {
	if f.metadata.Type == C.MTPROTO {
		return RC.ProtocolMTProto
	}
	if !f.protocolRead {
		f.protocolRead = true
		if f.protocolProbe != nil && f.metadata.Type != C.INNER {
			f.protocol = f.protocolProbe()
		}
	}
	return f.protocol
}
