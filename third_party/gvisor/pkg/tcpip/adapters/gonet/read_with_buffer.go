// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gonet

import (
	"io"
	"net"
	"net/netip"
	"syscall"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/waiter"
)

func (c *TCPConn) ReadWithBuffer(getBuffer func(sizeHint int) []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	n, err := commonReadWithBuffer(getBuffer, c.ep, c.wq, c.readCancel(), nil, c)
	if n != 0 {
		c.ep.ModerateRecvBuf(n)
	}
	return n, err
}

func (c *UDPConn) ReadWithBuffer(getBuffer func(sizeHint int) []byte) (int, error) {
	return commonReadWithBuffer(getBuffer, c.ep, c.wq, c.readCancel(), nil, c)
}

func (c *UDPConn) ReadFromWithBuffer(getBuffer func(sizeHint int) []byte) (int, net.Addr, error) {
	var address tcpip.FullAddress
	n, err := commonReadWithBuffer(getBuffer, c.ep, c.wq, c.readCancel(), &address, c)
	if err != nil {
		return 0, nil, err
	}
	return n, fullToUDPAddr(address), nil
}

func (c *UDPConn) ReadFromUDPAddrPortWithBuffer(getBuffer func(sizeHint int) []byte) (int, netip.AddrPort, error) {
	var address tcpip.FullAddress
	n, err := commonReadWithBuffer(getBuffer, c.ep, c.wq, c.readCancel(), &address, c)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return n, fullToUDPAddrPort(address), nil
}

const readWithBufferEvents = waiter.ReadableEvents | waiter.EventErr | waiter.EventHUp | waiter.EventRdHUp

func readWithBufferReady(ep tcpip.Endpoint) (int, bool, tcpip.Error) {
	if size, err := ep.GetSockOptInt(tcpip.ReceiveQueueSizeOption); err == nil && size > 0 {
		return size, true, nil
	}

	result, readErr := ep.Read(io.Discard, tcpip.ReadOptions{Peek: true})
	if readErr == nil {
		return int(result.Total), true, nil
	}
	if _, wouldBlock := readErr.(*tcpip.ErrWouldBlock); wouldBlock {
		return 0, false, nil
	}
	return 0, false, readErr
}

func readWithBufferError(err tcpip.Error, errorer opErrorer) error {
	if _, closed := err.(*tcpip.ErrClosedForReceive); closed {
		return io.EOF
	}
	return errorer.newOpError("read", TranslateNetstackError(err))
}

func waitForReadWithBuffer(ep tcpip.Endpoint, wq *waiter.Queue, deadline <-chan struct{}, errorer opErrorer) (int, error) {
	select {
	case <-deadline:
		return 0, errorer.newOpError("read", &timeoutError{})
	default:
	}

	size, ready, err := readWithBufferReady(ep)
	if err != nil {
		return 0, readWithBufferError(err, errorer)
	}
	if ready {
		return size, nil
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(readWithBufferEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	for {
		size, ready, err = readWithBufferReady(ep)
		if err != nil {
			return 0, readWithBufferError(err, errorer)
		}
		if ready {
			return size, nil
		}

		select {
		case <-deadline:
			return 0, errorer.newOpError("read", &timeoutError{})
		case <-notifyCh:
		}
	}
}

func commonReadWithBuffer(
	getBuffer func(sizeHint int) []byte,
	ep tcpip.Endpoint,
	wq *waiter.Queue,
	deadline <-chan struct{},
	addr *tcpip.FullAddress,
	errorer opErrorer,
) (int, error) {
	if getBuffer == nil {
		return 0, errorer.newOpError("read", syscall.EINVAL)
	}

	sizeHint, err := waitForReadWithBuffer(ep, wq, deadline, errorer)
	if err != nil {
		return 0, err
	}

	select {
	case <-deadline:
		return 0, errorer.newOpError("read", &timeoutError{})
	default:
	}

	buffer := getBuffer(sizeHint)
	opts := tcpip.ReadOptions{NeedRemoteAddr: addr != nil}
	for {
		writer := tcpip.SliceWriter(buffer)
		result, readErr := ep.Read(&writer, opts)
		if _, wouldBlock := readErr.(*tcpip.ErrWouldBlock); wouldBlock {
			if _, err = waitForReadWithBuffer(ep, wq, deadline, errorer); err != nil {
				return 0, err
			}
			continue
		}

		if readErr != nil {
			return 0, readWithBufferError(readErr, errorer)
		}
		if addr != nil {
			*addr = result.RemoteAddr
		}
		return result.Count, nil
	}
}

func fullToUDPAddrPort(addr tcpip.FullAddress) netip.AddrPort {
	ip, ok := netip.AddrFromSlice(addr.Addr.AsSlice())
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip, addr.Port)
}
