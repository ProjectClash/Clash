//go:build darwin

package tun

import (
	"bytes"
	"testing"

	"golang.org/x/sys/unix"
)

func TestASpliceVectorClearsItsScratchInBothDirections(t *testing.T) {
	local, remote := splicePeer(t)
	e := spliceScratchEngine()
	holder := &goSlabHolder{}
	chain := &goSlabChain{maxSlots: goTransmitCapacityMax/goSlabSize + 1, pool: e.slabPool, holder: holder}
	length := goSlabSize + goSlabSize/4
	chain.reserve(0, length)
	payload := bytes.Repeat([]byte{0x5a}, length)
	if n, err := unix.Write(remote, payload); err != nil || n != length {
		t.Fatalf("the remote wrote %d of %d bytes (%v); the socket pair is too small for the test", n, length, err)
	}
	socket := &goSocket{fd: local}
	n, errno := e.spliceVector(socket, chain, 0, length, (*goSocket).readVector)
	if errno != 0 || n != length {
		t.Fatalf("read %d (%v), want %d", n, errno, length)
	}
	if held := spliceScratchHeld(e); len(held) != 0 {
		t.Fatalf("after a read the scratch holds %d pointer(s)", len(held))
	}
	back := make([]byte, length)
	chain.readAt(0, back)
	if !bytes.Equal(back, payload) {
		t.Fatal("the read did not land in the chain's slabs")
	}
	n, errno = e.spliceVector(socket, chain, 0, length, (*goSocket).writeVector)
	if errno != 0 || n != length {
		t.Fatalf("wrote %d (%v), want %d", n, errno, length)
	}
	if held := spliceScratchHeld(e); len(held) != 0 {
		t.Fatalf("after a write the scratch holds %d pointer(s)", len(held))
	}
	chain.releaseAll()
}
