//go:build darwin

package tun

import (
	"bytes"
	"fmt"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)


func splicePeer(t *testing.T) (local, remote int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		if err := unix.SetNonblock(fd, true); err != nil {
			t.Fatal(err)
		}
		for _, option := range []int{unix.SO_SNDBUF, unix.SO_RCVBUF} {
			if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, option, 1<<20); err != nil {
				t.Fatalf("socket buffer: %v", err)
			}
		}
	}
	t.Cleanup(func() { _ = unix.Close(fds[0]); _ = unix.Close(fds[1]) })
	return fds[0], fds[1]
}

func spliceScratchEngine() *goEngine {
	return &goEngine{
		spliceSegments: make([][]byte, 0, 8),
		spliceIovecs:   make([]goIOVector, 0, 8),
		slabPool:       newGoSlabPool(nil, 8),
	}
}

func spliceScratchHeld(e *goEngine) []uintptr {
	var held []uintptr
	for _, segment := range e.spliceSegments[:cap(e.spliceSegments)] {
		if segment != nil {
			held = append(held, uintptr(unsafe.Pointer(unsafe.SliceData(segment))))
		}
	}
	for _, iovec := range e.spliceIovecs[:cap(e.spliceIovecs)] {
		if iovec.Base != nil {
			held = append(held, uintptr(unsafe.Pointer(iovec.Base)))
		}
	}
	return held
}

func arenaChunks(t *testing.T, pool *goSlabPool) []*goSlabChunk {
	t.Helper()
	store, ok := pool.store.(*goArenaSlabStore)
	if !ok {
		t.Fatalf("the pool's store is %T, not the arena", pool.store)
	}
	return store.chunks
}

func TestASplicedUploadLeavesNoPointerIntoItsSlabs(t *testing.T) {
	local, remote := splicePeer(t)
	e := spliceScratchEngine()
	conn := &GoConn{engine: e, receiveCapacity: 1 << 20, sentEdge: 1 << 40}
	conn.receiveChain = goSlabChain{maxSlots: goReceiveCapacityMax/goSlabSize + 1, pool: e.slabPool, holder: &conn.slabHolder}
	conn.splice = &goSpliceStream{conn: conn, socket: goSocket{fd: local}}

	data := bytes.Repeat([]byte("splice"), (goSlabSize+goSlabSize/2)/6)
	e.spliceDeliver(conn, data)
	chunks := arenaChunks(t, e.slabPool)
	if len(chunks) != 1 {
		t.Fatalf("%d slab chunks, want 1", len(chunks))
	}
	lo := chunks[0].base
	hi := lo + goSlabChunkSize
	e.spliceFlushUpload(conn)
	if conn.splice.blocked {
		t.Fatal("the upload blocked: the socket pair is too small for the test")
	}

	var got []byte
	for block := make([]byte, 64<<10); len(got) < len(data); {
		n, err := unix.Read(remote, block)
		if n <= 0 || err != nil {
			break
		}
		got = append(got, block[:n]...)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("the remote read %d bytes, want the %d sent", len(got), len(data))
	}
	if n, err := unix.Read(remote, make([]byte, 1)); n > 0 || err != unix.EAGAIN {
		t.Fatalf("the remote has more than was sent: read %d (%v)", n, err)
	}
	if held := conn.receiveChain.held.Load(); held != 0 {
		t.Fatalf("the connection still holds %d slab(s) after the upload drained", held)
	}
	e.slabPool.close()
	if left := arenaChunks(t, e.slabPool); len(left) != 0 {
		t.Fatalf("%d chunk(s) still in the pool after it closed", len(left))
	}
	for _, p := range spliceScratchHeld(e) {
		where := ""
		if p >= lo && p < hi {
			where = fmt.Sprintf(", in the chunk the pool gave back [%#x, %#x)", lo, hi)
		}
		t.Errorf("the engine's splice scratch still points at %#x after the call returned%s", p, where)
	}
}
