package vmess

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gobwas/ws"
)


func wsControlPeer(t *testing.T, state ws.State) (*websocketConn, net.Conn) {
	t.Helper()
	local, peer := net.Pipe()
	t.Cleanup(func() { _ = local.Close(); _ = peer.Close() })
	return newWebsocketConn(local, state), peer
}

func wsControlFrame(peer net.Conn, state ws.State, header ws.Header, payload []byte) error {
	header.Length = int64(len(payload))
	if state.ServerSide() {
		header.Masked = true
		header.Mask = [4]byte{1, 2, 3, 4}
		masked := append([]byte(nil), payload...)
		ws.Cipher(masked, header.Mask, 0)
		payload = masked
	}
	if err := ws.WriteHeader(peer, header); err != nil {
		return err
	}
	_, err := peer.Write(payload)
	return err
}

func wsControlReadAll(t *testing.T, conn *websocketConn, peer net.Conn, frames func() error) ([]byte, error) {
	t.Helper()
	go func() { _ = frames() }()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	timer := time.AfterFunc(2*time.Second, func() { _ = peer.Close() })
	defer timer.Stop()
	buffer := make([]byte, 64)
	var read []byte
	for {
		n, err := conn.Read(buffer)
		read = append(read, buffer[:n]...)
		if err != nil {
			return read, err
		}
	}
}

var wsControlSides = []struct {
	name  string
	state ws.State
}{{"client", ws.StateClientSide}, {"server", ws.StateServerSide}}

func TestAControlFrameOfMoreThan125BytesIsAProtocolError(t *testing.T) {
	for _, side := range wsControlSides {
		for _, op := range []struct {
			name string
			code ws.OpCode
		}{{"close", ws.OpClose}, {"ping", ws.OpPing}, {"pong", ws.OpPong}} {
			t.Run(side.name+"/"+op.name, func(t *testing.T) {
				conn, peer := wsControlPeer(t, side.state)
				_, err := wsControlReadAll(t, conn, peer, func() error {
					return wsControlFrame(peer, side.state, ws.Header{Fin: true, OpCode: op.code}, bytes.Repeat([]byte{'x'}, 126))
				})
				if !errors.Is(err, ws.ErrProtocolControlPayloadOverflow) {
					t.Errorf("read error = %v, want %v", err, ws.ErrProtocolControlPayloadOverflow)
				}
			})
		}
	}
}

func TestAControlFrameBetweenFragmentsIsHeldToTheSameBound(t *testing.T) {
	for _, side := range wsControlSides {
		t.Run(side.name, func(t *testing.T) {
			conn, peer := wsControlPeer(t, side.state)
			read, err := wsControlReadAll(t, conn, peer, func() error {
				if err := wsControlFrame(peer, side.state, ws.Header{Fin: false, OpCode: ws.OpBinary}, []byte("abc")); err != nil {
					return err
				}
				return wsControlFrame(peer, side.state, ws.Header{Fin: true, OpCode: ws.OpClose}, bytes.Repeat([]byte{'x'}, 126))
			})
			if string(read) != "abc" {
				t.Errorf("read %q before the close, want %q", read, "abc")
			}
			if !errors.Is(err, ws.ErrProtocolControlPayloadOverflow) {
				t.Errorf("read error = %v, want %v", err, ws.ErrProtocolControlPayloadOverflow)
			}
		})
	}
}

func TestAFragmentedControlFrameIsAProtocolError(t *testing.T) {
	for _, side := range wsControlSides {
		t.Run(side.name, func(t *testing.T) {
			conn, peer := wsControlPeer(t, side.state)
			read, err := wsControlReadAll(t, conn, peer, func() error {
				if err := wsControlFrame(peer, side.state, ws.Header{Fin: false, OpCode: ws.OpPing}, []byte("ping")); err != nil {
					return err
				}
				return wsControlFrame(peer, side.state, ws.Header{Fin: true, OpCode: ws.OpBinary}, []byte("ok"))
			})
			if !errors.Is(err, ws.ErrProtocolControlNotFinal) {
				t.Errorf("read %q, error = %v, want %v", read, err, ws.ErrProtocolControlNotFinal)
			}
		})
	}
}

func TestAPingWithinTheBoundIsAnsweredAndTheDataAfterItIsRead(t *testing.T) {
	local, peer := net.Pipe()
	t.Cleanup(func() { _ = local.Close(); _ = peer.Close() })
	conn := newWebsocketConn(local, ws.StateClientSide)
	ping := bytes.Repeat([]byte{'p'}, ws.MaxControlFramePayloadSize)
	pong := make(chan []byte, 1)
	go func() {
		if wsControlFrame(peer, ws.StateClientSide, ws.Header{Fin: true, OpCode: ws.OpPing}, ping) != nil {
			return
		}
		header, err := ws.ReadHeader(peer)
		if err != nil || header.OpCode != ws.OpPong {
			pong <- nil
			return
		}
		payload := make([]byte, header.Length)
		if _, err := io.ReadFull(peer, payload); err != nil {
			pong <- nil
			return
		}
		if header.Masked {
			ws.Cipher(payload, header.Mask, 0)
		}
		pong <- payload
		_ = wsControlFrame(peer, ws.StateClientSide, ws.Header{Fin: true, OpCode: ws.OpBinary}, []byte("ok"))
	}()
	_ = local.SetDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 64)
	n, err := conn.Read(buffer)
	if err != nil || string(buffer[:n]) != "ok" {
		t.Fatalf("read %q, %v; want %q", buffer[:n], err, "ok")
	}
	select {
	case answer := <-pong:
		if !bytes.Equal(answer, ping) {
			t.Errorf("answered the ping with %d bytes, want its 125 bytes back as a pong", len(answer))
		}
	default:
		t.Error("the ping was not answered")
	}
}
