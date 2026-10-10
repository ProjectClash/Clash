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
)

type serverRx struct {
	packetPipe pipe.Rx

	completionPipe pipe.Tx

	data []byte

	eventFD eventfd.Eventfd

	sharedData []byte

	sharedEventFDState *atomicbitops.Uint32
}

func (s *serverRx) init(c *QueueConfig) error {
	packetPipeMem, err := getBuffer(c.TxPipeFD)
	if err != nil {
		return err
	}
	cu := cleanup.Make(func() { unix.Munmap(packetPipeMem) })
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

	s.packetPipe.Init(packetPipeMem)
	s.completionPipe.Init(completionPipeMem)
	s.data = data
	s.eventFD = efd
	s.sharedData = sharedData
	s.sharedEventFDState = sharedDataPointer(sharedData)

	cu.Release()
	return nil
}

func (s *serverRx) cleanup() {
	unix.Munmap(s.packetPipe.Bytes())
	unix.Munmap(s.completionPipe.Bytes())
	unix.Munmap(s.data)
	unix.Munmap(s.sharedData)
	s.eventFD.Close()
}

func (s *serverRx) EnableNotification() {
	s.sharedEventFDState.Store(queue.EventFDEnabled)
}

func (s *serverRx) DisableNotification() {
	s.sharedEventFDState.Store(queue.EventFDDisabled)
}

const completionNotificationSize = 8

func (s *serverRx) receive() *buffer.View {
	desc := s.packetPipe.Pull()
	if desc == nil {
		return nil
	}

	pktInfo := queue.DecodeTxPacketHeader(desc)
	contents := buffer.NewView(int(pktInfo.Size))
	toCopy := pktInfo.Size
	for i := 0; i < pktInfo.BufferCount; i++ {
		txBuf := queue.DecodeTxBufferHeader(desc, i)
		if txBuf.Size <= toCopy {
			contents.Write(s.data[txBuf.Offset:][:txBuf.Size])
			toCopy -= txBuf.Size
			continue
		}
		contents.Write(s.data[txBuf.Offset:][:toCopy])
		break
	}

	s.packetPipe.Flush()
	b := s.completionPipe.Push(completionNotificationSize)
	queue.EncodeTxCompletion(b, pktInfo.ID)
	s.completionPipe.Flush()
	return contents
}

func (s *serverRx) waitForPackets() {
	s.eventFD.Wait()
}
