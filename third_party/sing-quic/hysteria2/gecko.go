package hysteria2

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	rand2 "github.com/metacubex/randv2"
)

const ObfsTypeGecko = "gecko"

const (
	geckoFragmentFlag         = 0x80
	geckoHeaderLen            = 5
	geckoMinChunks            = 2
	geckoMaxChunks            = 8
	geckoMaxOnWireSize        = 2048
	geckoDefaultMinPacketSize = 512
	geckoDefaultMaxPacketSize = 1200
	geckoReassemblyTTL        = 8 * time.Second
	geckoMaxReassembly        = 4096
	geckoMaxPerSource         = 8
)

type GeckoPacketConn struct {
	net.PacketConn
	minPacketSize int
	maxPacketSize int
	msgIDCounter  atomic.Uint32

	readAccess       sync.Mutex
	reassemblyAccess sync.Mutex
	reassembly       map[geckoReassemblyKey]*geckoReassemblyEntry
	perSource        map[string]int

	lastSweep time.Time
}

type geckoReassemblyKey struct {
	addr  string
	msgID uint8
}

type geckoReassemblyEntry struct {
	chunks   [][]byte
	received int
	total    uint8
	deadline time.Time
}

func NewGeckoConn(conn net.PacketConn, password []byte, minPacketSize, maxPacketSize int) net.PacketConn {
	g := &GeckoPacketConn{
		PacketConn:    NewSalamanderConn(conn, password),
		minPacketSize: minPacketSize,
		maxPacketSize: maxPacketSize,
		reassembly:    make(map[geckoReassemblyKey]*geckoReassemblyEntry),
		perSource:     make(map[string]int),
		lastSweep:     time.Now(),
	}
	return g
}

func (g *GeckoPacketConn) Upstream() any {
	return g.PacketConn
}

func (g *GeckoPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if p[0]&geckoFragmentFlag == 0 {
		return g.PacketConn.WriteTo(p, addr)
	}
	return g.writeFragmented(p, addr)
}

func (g *GeckoPacketConn) writeFragmented(p []byte, addr net.Addr) (int, error) {
	chunks := geckoMinChunks + rand2.IntN(geckoMaxChunks-geckoMinChunks+1)
	chunkSize := len(p) / chunks
	msgID := uint8(g.msgIDCounter.Add(1))
	for i := 0; i < chunks; i++ {
		start := i * chunkSize
		end := len(p)
		if i < chunks-1 {
			end = start + chunkSize
		}
		chunk := p[start:end]
		padLen := g.randomPadLen(len(chunk))
		frame := make([]byte, geckoHeaderLen+int(padLen)+len(chunk))
		frame[0] = geckoFragmentFlag
		frame[1] = msgID
		frame[2] = byte(i)<<4 | byte(chunks)&0x0f
		binary.BigEndian.PutUint16(frame[3:5], padLen)
		if padLen > 0 {
			_, randErr := rand.Read(frame[geckoHeaderLen : geckoHeaderLen+int(padLen)])
			if randErr != nil {
				return 0, randErr
			}
		}
		copy(frame[geckoHeaderLen+int(padLen):], chunk)
		_, err := g.PacketConn.WriteTo(frame, addr)
		if err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (g *GeckoPacketConn) randomPadLen(chunkLen int) uint16 {
	base := salamanderSaltLen + geckoHeaderLen + chunkLen
	lo := g.minPacketSize
	if base > lo {
		lo = base
	}
	if lo > g.maxPacketSize {
		return 0
	}
	return uint16(lo - base + rand2.IntN(g.maxPacketSize-lo+1))
}

func (g *GeckoPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	g.readAccess.Lock()
	defer g.readAccess.Unlock()
	for {
		n, addr, err := g.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		if n == 0 {
			continue
		}
		if p[0]&geckoFragmentFlag == 0 {
			return n, addr, nil
		}
		if n < geckoHeaderLen {
			continue
		}
		msgID := p[1]
		chunkIdx := p[2] >> 4
		totalChunks := p[2] & 0x0f
		padLen := binary.BigEndian.Uint16(p[3:5])
		if totalChunks < geckoMinChunks || totalChunks > geckoMaxChunks {
			continue
		}
		if chunkIdx >= totalChunks {
			continue
		}
		payloadStart := geckoHeaderLen + int(padLen)
		if payloadStart > n {
			continue
		}
		out, ready := g.acceptChunk(addr, msgID, chunkIdx, totalChunks, p[payloadStart:n])
		if !ready {
			continue
		}
		return copy(p, out), addr, nil
	}
}

func (g *GeckoPacketConn) acceptChunk(addr net.Addr, msgID, chunkIdx, totalChunks uint8, payload []byte) ([]byte, bool) {
	addrString := addr.String()
	key := geckoReassemblyKey{addr: addrString, msgID: msgID}

	g.reassemblyAccess.Lock()
	defer g.reassemblyAccess.Unlock()

	now := time.Now()
	if now.Sub(g.lastSweep) >= geckoReassemblyTTL/2 {
		g.sweepExpiredLocked(now)
	}

	entry, loaded := g.reassembly[key]
	if !loaded {
		if g.perSource[addrString] >= geckoMaxPerSource {
			return nil, false
		}
		if len(g.reassembly) >= geckoMaxReassembly {
			g.evictOldestLocked()
		}
		entry = &geckoReassemblyEntry{
			chunks:   make([][]byte, totalChunks),
			total:    totalChunks,
			deadline: time.Now().Add(geckoReassemblyTTL),
		}
		g.reassembly[key] = entry
		g.perSource[addrString]++
	} else if entry.total != totalChunks {
		return nil, false
	}
	if int(chunkIdx) >= len(entry.chunks) || entry.chunks[chunkIdx] != nil {
		return nil, false
	}
	payloadCopy := make([]byte, len(payload))
	copy(payloadCopy, payload)
	entry.chunks[chunkIdx] = payloadCopy
	entry.received++
	if entry.received < int(entry.total) {
		return nil, false
	}
	var out []byte
	for _, chunk := range entry.chunks {
		out = append(out, chunk...)
	}
	g.dropEntryLocked(key)
	return out, true
}

func (g *GeckoPacketConn) dropEntryLocked(key geckoReassemblyKey) {
	_, loaded := g.reassembly[key]
	if !loaded {
		return
	}
	delete(g.reassembly, key)
	g.perSource[key.addr]--
	if g.perSource[key.addr] <= 0 {
		delete(g.perSource, key.addr)
	}
}

func (g *GeckoPacketConn) evictOldestLocked() {
	var oldestKey geckoReassemblyKey
	var oldestDeadline time.Time
	first := true
	for key, entry := range g.reassembly {
		if first || entry.deadline.Before(oldestDeadline) {
			oldestKey = key
			oldestDeadline = entry.deadline
			first = false
		}
	}
	if !first {
		g.dropEntryLocked(oldestKey)
	}
}

func (g *GeckoPacketConn) sweepExpiredLocked(now time.Time) {
	for key, entry := range g.reassembly {
		if now.After(entry.deadline) {
			g.dropEntryLocked(key)
		}
	}
	g.lastSweep = now
}

func (g *GeckoPacketConn) Close() error {
	return g.PacketConn.Close()
}
