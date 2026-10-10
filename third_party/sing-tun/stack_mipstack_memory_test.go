package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	mips "github.com/metacubex/mipstack"
	"github.com/metacubex/sing/common"
	M "github.com/metacubex/sing/common/metadata"
)

func TestMipsMemoryProfileBackpressureAndStream(t *testing.T) {
	for _, addresses := range [][2]string{
		{"198.18.0.2", "192.0.2.1"}, {"fd00::2", "2001:db8::1"},
	} {
		t.Run(addresses[0], func(t *testing.T) {
			device := newMemoryTun()
			accepted := make(chan *mips.TCPConn, 1)
			resume := make(chan struct{})
			defer close(resume)
			handler := &testHandler{tcp: func(_ context.Context, conn net.Conn, _ M.Metadata) error {
				defer conn.Close()
				accepted <- conn.(*mips.TCPConn)
				select {
				case <-resume:
				case <-device.done:
				}
				return nil
			}}
			testStack(t, device, handler, nil)
			source, target := netip.MustParseAddr(addresses[0]), netip.MustParseAddr(addresses[1])
			client, err := mips.New(mips.Config{MTU: 1500, LocalAddresses: []netip.Prefix{netip.PrefixFrom(source, source.BitLen())}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if err = client.Start(); err != nil {
				t.Fatal(err)
			}
			go func() {
				buffers, sizes := [][]byte{make([]byte, 65535)}, make([]int, 1)
				for {
					n, err := client.Read(buffers, sizes, 0)
					if err != nil {
						return
					}
					for i := 0; i < n; i++ {
						select {
						case device.in <- bytes.Clone(buffers[i][:sizes[i]]):
						case <-device.done:
							return
						}
					}
				}
			}()
			go func() {
				for {
					select {
					case packet := <-device.out:
						if _, err := client.Write([][]byte{packet}, 0); err != nil {
							return
						}
					case <-device.done:
						return
					}
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := client.DialTCP(ctx, "tcp", netip.AddrPort{}, netip.AddrPortFrom(target, 443))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			var server *mips.TCPConn
			select {
			case server = <-accepted:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			_ = server.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte("0123456789abcdef"), 128*1024)
			done := make(chan error, 1)
			go func() { _, err := conn.Write(payload); done <- err }()
			limit := time.Now().Add(2 * time.Second)
			for server.Info().ReceiveBufferSize < 32*1024 && time.Now().Before(limit) {
				time.Sleep(time.Millisecond)
			}
			info := server.Info()
			if info.ReceiveBufferSize < 32*1024 {
				t.Fatal("failed to fill receive window")
			}
			if common.LowMemory && (info.ReceiveBufferSize > 128*1024 || info.ReceiveBufferCapacity > 128*1024) {
				t.Fatalf("paused receiver exceeded memory profile: %+v", info)
			}
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(server, received); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, received) {
				t.Fatal("upload data mismatch")
			}
			go func() { _, err := server.Write(received); done <- err }()
			if _, err := io.ReadFull(conn, received); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, received) {
				t.Fatal("download data mismatch")
			}
			info = server.Info()
			if common.LowMemory && (info.ReceiveBufferCapacity > 128*1024 || info.SendBufferCapacity > 128*1024 ||
				info.MaximumReceiveBuffer != 128*1024 || info.MaximumSendBuffer != 128*1024) {
				t.Fatalf("stream escaped the memory profile: %+v", info)
			}
		})
	}
}

func TestMipsAcceptedTCPMemoryProfile(t *testing.T) {
	for _, addresses := range [][2]string{
		{"198.18.0.1", "192.0.2.1"}, {"fd00::1", "2001:db8::1"},
	} {
		t.Run(addresses[0], func(t *testing.T) {
			device := newMemoryTun()
			info := make(chan mips.TCPConnInfo, 1)
			handler := &testHandler{tcp: func(_ context.Context, conn net.Conn, _ M.Metadata) error {
				defer conn.Close()
				info <- conn.(*mips.TCPConn).Info()
				return nil
			}}
			testStack(t, device, handler, nil)
			source, target := netip.MustParseAddr(addresses[0]), netip.MustParseAddr(addresses[1])
			device.in <- tcpPacket(source, target, 100, 0, 2, nil)
			synAck := readPacket(t, device)
			offset := 20
			if source.Is6() {
				offset = 40
			}
			if synAck[offset+13]&18 != 18 {
				t.Fatalf("expected SYN ACK: %x", synAck)
			}
			ack := binary.BigEndian.Uint32(synAck[offset+4:]) + 1
			device.in <- tcpPacket(source, target, 101, ack, 16, nil)
			select {
			case got := <-info:
				wantReceive, wantSend, wantMax := 1024*1024, 256*1024, 16*1024*1024
				if common.LowMemory {
					wantReceive, wantSend, wantMax = 32*1024, 32*1024, 128*1024
				}
				if got.ReceiveBufferCapacity != wantReceive || got.SendBufferCapacity != wantSend ||
					got.MaximumReceiveBuffer != wantMax || got.MaximumSendBuffer != wantMax {
					t.Fatalf("TCP memory profile receive=%d/%d send=%d/%d, want %d/%d and %d/%d",
						got.ReceiveBufferCapacity, got.MaximumReceiveBuffer, got.SendBufferCapacity, got.MaximumSendBuffer,
						wantReceive, wantMax, wantSend, wantMax)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("accepted connection did not report its memory profile")
			}
		})
	}
}
