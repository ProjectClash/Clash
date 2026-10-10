// Copyright 2021 The gVisor Authors.
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

//go:build linux
// +build linux

package sharedmem

import (
	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/cleanup"
	"github.com/metacubex/gvisor/pkg/eventfd"
	"github.com/metacubex/gvisor/pkg/tcpip/link/sharedmem/pipe"
	"github.com/metacubex/gvisor/pkg/tcpip/link/sharedmem/queue"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

type serverTx struct {
	fillPipe pipe.Rx

	completionPipe pipe.Tx

	data []byte

	eventFD eventfd.Eventfd

	sharedData []byte

	sharedEventFDState *atomicbitops.Uint32
}

func (s *serverTx) init(c *QueueConfig) error {
	fillPipeMem, err := getBuffer(c.TxPipeFD)
	if err != nil {
		return err
	}
	cu := cleanup.Make(func() { unix.Munmap(fillPipeMem) })
	defer cu.Clean()

	completionPipeMem, err := getBuffer(c.RxPipeFD)
	if err != nil {
		return err
	}
	cu.Add(func() { unix.Munmap(completionPipeMem) })

	data, err := getBuffer(c.DataFD)
	if err != nil {
		return err
	}
	cu.Add(func() { unix.Munmap(data) })

	sharedData, err := getBuffer(c.SharedDataFD)
	if err != nil {
		return err
	}
	cu.Add(func() { unix.Munmap(sharedData) })

	efd, err := c.EventFD.Dup()
	if err != nil {
		return err
	}
	cu.Add(func() { efd.Close() })

	cu.Release()

	s.fillPipe.Init(fillPipeMem)
	s.completionPipe.Init(completionPipeMem)
	s.data = data
	s.eventFD = efd
	s.sharedData = sharedData
	s.sharedEventFDState = sharedDataPointer(sharedData)

	return nil
}

func (s *serverTx) cleanup() {
	unix.Munmap(s.fillPipe.Bytes())
	unix.Munmap(s.completionPipe.Bytes())
	unix.Munmap(s.data)
	unix.Munmap(s.sharedData)
	s.eventFD.Close()
}

func (s *serverTx) acquireBuffers(pktBuffer buffer.Buffer, buffers []queue.RxBuffer) (acquiredBuffers []queue.RxBuffer) {
	acquiredBuffers = buffers[:0]
	wantBytes := int(pktBuffer.Size())
	for wantBytes > 0 {
		var b []byte
		if b = s.fillPipe.Pull(); b == nil {
			s.fillPipe.Abort()
			return nil
		}
		rxBuffer := queue.DecodeRxBufferHeader(b)
		acquiredBuffers = append(acquiredBuffers, rxBuffer)
		wantBytes -= int(rxBuffer.Size)
	}
	return acquiredBuffers
}

func (s *serverTx) fillPacket(pktBuffer buffer.Buffer, buffers []queue.RxBuffer) (filledBuffers []queue.RxBuffer, totalCopied uint32) {
	bufs := s.acquireBuffers(pktBuffer, buffers)
	if bufs == nil {
		pktBuffer.Release()
		return nil, 0
	}
	br := pktBuffer.AsBufferReader()
	defer br.Close()

	for i := 0; br.Len() > 0 && i < len(bufs); i++ {
		buf := bufs[i]
		copied, err := br.Read(s.data[buf.Offset:][:buf.Size])
		buf.Size = uint32(copied)
		totalCopied += bufs[i].Size
		if err != nil {
			return bufs, totalCopied
		}
	}
	return bufs, totalCopied
}

func (s *serverTx) transmit(pkt *stack.PacketBuffer) bool {
	buffers := make([]queue.RxBuffer, 8)
	buffers, totalCopied := s.fillPacket(pkt.ToBuffer(), buffers)
	if totalCopied == 0 {
		return false
	}
	b := s.completionPipe.Push(queue.RxCompletionSize(len(buffers)))
	if b == nil {
		return false
	}
	queue.EncodeRxCompletion(b, totalCopied, 0)
	for i := 0; i < len(buffers); i++ {
		queue.EncodeRxCompletionBuffer(b, i, buffers[i])
	}
	s.completionPipe.Flush()
	s.fillPipe.Flush()
	return true
}

func (s *serverTx) notificationsEnabled() bool {
	return s.sharedEventFDState.Load() != queue.EventFDDisabled
}

func (s *serverTx) notify() {
	if s.notificationsEnabled() {
		s.eventFD.Notify()
	}
}
