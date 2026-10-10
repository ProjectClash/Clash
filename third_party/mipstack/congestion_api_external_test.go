package mipstack_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mipstack"
)

var externalCongestionName atomic.Uint64

type externalCongestionController struct{}

func (*externalCongestionController) HandleCongestionEvent(event *mipstack.CongestionEvent) {
	if event.Type == mipstack.CongestionEventInitialize {
		event.State.CongestionWindow = 16 * uint32(event.State.MaximumSegmentSize)
	}
}

func bridgeExternalStacks(t *testing.T, left, right *mipstack.Stack) {
	t.Helper()
	copyPackets := func(source, target *mipstack.Stack) {
		buffers := make([][]byte, source.BatchSize())
		sizes := make([]int, len(buffers))
		for index := range buffers {
			buffers[index] = make([]byte, 1500)
		}
		for {
			count, err := source.Read(buffers, sizes, 0)
			if err != nil {
				return
			}
			packets := make([][]byte, count)
			for index := 0; index < count; index++ {
				packets[index] = buffers[index][:sizes[index]]
			}
			if _, err = target.Write(packets, 0); err != nil {
				return
			}
		}
	}
	go copyPackets(left, right)
	go copyPackets(right, left)
}

func TestPublicCongestionControllerAPI(t *testing.T) {
	sample := new(mipstack.CongestionRateSample)
	_, _, _, _, _ = sample.PriorDeliveredBytes(), sample.DeliveredBytes(), sample.AcknowledgedBytes(), sample.LostBytes(), sample.PriorBytesInFlight()
	_, _, _, _, _ = sample.BytesInFlight(), sample.Interval(), sample.RTT(), sample.SmoothedRTT(), sample.ACKTime()
	_, _, _, _, _, _, _ = sample.ApplicationLimited(), sample.SchedulerLimited(), sample.Retransmitted(), sample.InRecovery(), sample.InFastRecovery(), sample.ACKDelayed(), sample.Valid()
	_, _ = sample.PacketState(), sample.TailLossProbeACK()

	name := fmt.Sprintf("external-test-%d", externalCongestionName.Add(1))
	factory, err := mipstack.NewCongestionControlFactory(mipstack.CongestionControlDefinition{
		Name: name,
		New: func(mipstack.CongestionControlContext) mipstack.CongestionController {
			return &externalCongestionController{}
		},
		Features: mipstack.CongestionControlFeatureDeliveryRate,
	})
	if err != nil {
		t.Fatal(err)
	}
	if factory.Name() != name {
		t.Fatalf("factory name = %q, want %q", factory.Name(), name)
	}
	for _, available := range mipstack.AvailableCongestionControls() {
		if available == name {
			t.Fatalf("unregistered local factory %q is discoverable", name)
		}
	}
	if err = mipstack.RegisterCongestionControl(factory); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, available := range mipstack.AvailableCongestionControls() {
		if available == name {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("registered controller %q is not discoverable", name)
	}
}

func TestPublicLocalCongestionControlFactoryConnection(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.240")
	serverAddress := netip.MustParseAddr("192.0.2.241")
	contexts := make(chan mipstack.CongestionControlContext, 2)
	name := fmt.Sprintf("external-local-%d", externalCongestionName.Add(1))
	factory, err := mipstack.NewCongestionControlFactory(mipstack.CongestionControlDefinition{
		Name: name,
		New: func(context mipstack.CongestionControlContext) mipstack.CongestionController {
			contexts <- context
			return &externalCongestionController{}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	newStack := func(address netip.Addr) *mipstack.Stack {
		stack, stackErr := mipstack.New(mipstack.Config{
			LocalAddresses: []netip.Prefix{netip.PrefixFrom(address, 32)},
			MTU:            1500,
			TCP:            mipstack.TCPSocketDefaults{CongestionControlFactory: factory},
		})
		if stackErr != nil {
			t.Fatal(stackErr)
		}
		if stackErr = stack.Start(); stackErr != nil {
			t.Fatal(stackErr)
		}
		return stack
	}
	client, server := newStack(clientAddress), newStack(serverAddress)
	defer client.Close()
	defer server.Close()
	bridgeExternalStacks(t, client, server)
	listener, err := server.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			acceptErrors <- acceptErr
			return
		}
		accepted <- connection
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	clientConnection, err := client.DialTCP(ctx, "tcp4", netip.AddrPort{}, listener.Addr().(*net.TCPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()
	var serverConnection net.Conn
	select {
	case serverConnection = <-accepted:
		defer serverConnection.Close()
	case err = <-acceptErrors:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	payload := []byte("local factory public API")
	read := make([]byte, len(payload))
	if _, err = clientConnection.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(serverConnection, read); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read, payload) {
		t.Fatalf("TCP payload = %q, want %q", read, payload)
	}
	seenActive, seenPassive := false, false
	for count := 0; count < 2; count++ {
		select {
		case factoryContext := <-contexts:
			if factoryContext.LocalAddress.Addr() == clientAddress && !factoryContext.Passive && !factoryContext.Forwarded {
				seenActive = true
			}
			if factoryContext.LocalAddress == listener.Addr().(*net.TCPAddr).AddrPort() && factoryContext.Passive && !factoryContext.Forwarded {
				seenPassive = true
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if !seenActive || !seenPassive || clientConnection.(*mipstack.TCPConn).Info().CongestionControl != name || serverConnection.(*mipstack.TCPConn).Info().CongestionControl != name {
		t.Fatalf("local factory contexts active/passive = %t/%t", seenActive, seenPassive)
	}
}
