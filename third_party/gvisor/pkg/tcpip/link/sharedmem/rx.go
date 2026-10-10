// Copyright 2018 The gVisor Authors.
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
	"github.com/metacubex/gvisor/pkg/eventfd"
	"github.com/metacubex/gvisor/pkg/tcpip/link/sharedmem/queue"
)

type rx struct {
	data       []byte
	sharedData []byte
	q          queue.Rx
	eventFD    eventfd.Eventfd
}

func (r *rx) init(mtu uint32, c *QueueConfig) error {
	txPipe, err := getBuffer(c.TxPipeFD)
	if err != nil {
		return err
	}

	rxPipe, err := getBuffer(c.RxPipeFD)
	if err != nil {
		unix.Munmap(txPipe)
		return err
	}

	data, err := getBuffer(c.DataFD)
	if err != nil {
		unix.Munmap(txPipe)
		unix.Munmap(rxPipe)
		return err
	}

	sharedData, err := getBuffer(c.SharedDataFD)
	if err != nil {
		unix.Munmap(txPipe)
		unix.Munmap(rxPipe)
		unix.Munmap(data)
		return err
	}

	efd, err := c.EventFD.Dup()
	if err != nil {
		unix.Munmap(txPipe)
		unix.Munmap(rxPipe)
		unix.Munmap(data)
		unix.Munmap(sharedData)
		return err
	}

	r.q.Init(txPipe, rxPipe, sharedDataPointer(sharedData))
	r.data = data
	r.eventFD = efd
	r.sharedData = sharedData

	return nil
}

func (r *rx) cleanup() {
	a, b := r.q.Bytes()
	unix.Munmap(a)
	unix.Munmap(b)

	unix.Munmap(r.data)
	unix.Munmap(r.sharedData)
}

func (r *rx) notify() {
	r.eventFD.Notify()
}

func (r *rx) postAndReceive(b []queue.RxBuffer, stopRequested *atomicbitops.Uint32) ([]queue.RxBuffer, uint32) {
	if len(b) != 0 && !r.q.PostBuffers(b) {
		r.q.EnableNotification()
		for !r.q.PostBuffers(b) {
			r.eventFD.Wait()
			if stopRequested.Load() != 0 {
				r.q.DisableNotification()
				return nil, 0
			}
		}
		r.q.DisableNotification()
	}

	b, n := r.q.Dequeue(b[:0])
	if len(b) != 0 {
		return b, n
	}

	r.q.EnableNotification()
	for {
		b, n = r.q.Dequeue(b)
		if len(b) != 0 {
			break
		}

		r.eventFD.Wait()
		if stopRequested.Load() != 0 {
			r.q.DisableNotification()
			return nil, 0
		}
	}
	r.q.DisableNotification()

	return b, n
}
