//go:build with_gvisor && darwin

package tun

import (
	"errors"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/qdisc/fifo"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/sing-tun/internal/fdbased_darwin"
	"github.com/metacubex/sing-tun/internal/rawfile_darwin"

	"golang.org/x/sys/unix"
)

var _ GVisorTun = (*NativeTun)(nil)

func (t *NativeTun) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	views := pkt.AsSlices()
	numIovecs := len(views)
	numIovecs++

	var iovecsArr [8]unix.Iovec
	iovecs := iovecsArr[:0]
	if numIovecs > len(iovecsArr) {
		iovecs = make([]unix.Iovec, 0, numIovecs)
	}

	if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
		iovecs = append(iovecs, packetHeaderVec4)
	} else {
		iovecs = append(iovecs, packetHeaderVec6)
	}
	var dataLen int
	for _, packetSlice := range views {
		dataLen += len(packetSlice)
		iovec := unix.Iovec{
			Base: &packetSlice[0],
		}
		iovec.SetLen(len(packetSlice))
		iovecs = append(iovecs, iovec)
	}
	t.writeAccess.Lock()
	defer t.writeAccess.Unlock()
	errno := rawfile.NonBlockingWriteIovec(t.tunFd, iovecs)
	if errno == 0 {
		return dataLen, nil
	} else {
		return 0, errno
	}
}

func (t *NativeTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	fdbased.ResetPacketIOStats()
	ep, err := fdbased.New(&fdbased.Options{
		FDs:                  []int{t.tunFd},
		MTU:                  t.options.MTU,
		RXChecksumOffload:    true,
		ProcessorsPerChannel: t.options.EXP_ProcessorsPerChannel,
		RecvMsgX:             t.options.EXP_RecvMsgX,
		SendMsgX:             t.options.EXP_SendMsgX,
		WriteAccess: &t.writeAccess,
		ClosedFunc: t.endpointClosed,
	})
	if err != nil {
		return nil, stack.NICOptions{}, err
	}
	GVisorPacketIOSnapshot = func() GVisorPacketIOReport {
		snapshot := fdbased.PacketIOStatsSnapshot()
		return GVisorPacketIOReport{
			IngressReadCalls:         snapshot.IngressReadCalls,
			IngressReadWouldBlock:    snapshot.IngressReadWouldBlock,
			IngressReadPackets:       snapshot.IngressReadPackets,
			IngressReadBytes:         snapshot.IngressReadBytes,
			IngressReadErrors:        snapshot.IngressReadErrors,
			IngressDispatchPackets:   snapshot.IngressDispatchPackets,
			IngressDispatchBytes:     snapshot.IngressDispatchBytes,
			ProcessorQueueDepth:      snapshot.ProcessorQueueDepth,
			ProcessorQueuePeak:       snapshot.ProcessorQueuePeak,
			EgressWriteCalls:         snapshot.EgressWriteCalls,
			EgressWritePackets:       snapshot.EgressWritePackets,
			EgressWriteBytes:         snapshot.EgressWriteBytes,
			EgressWriteErrors:        snapshot.EgressWriteErrors,
			EgressWriteWaits:         snapshot.EgressWriteWaits,
			EgressWriteWaitExhausted: snapshot.EgressWriteWaitExhausted,
		}
	}
	return ep, stack.NICOptions{
		QDisc: fifo.New(ep, 1, 1000),
	}, nil
}

func (t *NativeTun) endpointClosed(err tcpip.Error) {
	if err != nil {
		t.reportFailure(errors.New(err.String()))
	}
}
