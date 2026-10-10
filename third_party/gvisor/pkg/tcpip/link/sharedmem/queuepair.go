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
	"fmt"
	"os"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/eventfd"
)

const (
	DefaultQueueDataSize = 1 << 20

	DefaultQueuePipeSize = 64 << 10

	DefaultSharedDataSize = 4 << 10

	DefaultBufferSize = 2048

	DefaultTmpDir = "/dev/shm"
)

type QueuePair struct {
	txCfg QueueConfig

	rxCfg QueueConfig
}

type QueueOptions struct {
	SharedMemPath string
}

func NewQueuePair(opts QueueOptions) (*QueuePair, error) {
	txCfg, err := createQueueFDs(opts.SharedMemPath, queueSizes{
		dataSize:       DefaultQueueDataSize,
		txPipeSize:     DefaultQueuePipeSize,
		rxPipeSize:     DefaultQueuePipeSize,
		sharedDataSize: DefaultSharedDataSize,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create tx queue: %s", err)
	}

	rxCfg, err := createQueueFDs(opts.SharedMemPath, queueSizes{
		dataSize:       DefaultQueueDataSize,
		txPipeSize:     DefaultQueuePipeSize,
		rxPipeSize:     DefaultQueuePipeSize,
		sharedDataSize: DefaultSharedDataSize,
	})

	if err != nil {
		closeFDs(txCfg)
		return nil, fmt.Errorf("failed to create rx queue: %s", err)
	}

	return &QueuePair{
		txCfg: txCfg,
		rxCfg: rxCfg,
	}, nil
}

func (q *QueuePair) Close() {
	closeFDs(q.txCfg)
	closeFDs(q.rxCfg)
}

func (q *QueuePair) TXQueueConfig() QueueConfig {
	return q.txCfg
}

func (q *QueuePair) RXQueueConfig() QueueConfig {
	return q.rxCfg
}

type queueSizes struct {
	dataSize       int64
	txPipeSize     int64
	rxPipeSize     int64
	sharedDataSize int64
}

func createQueueFDs(sharedMemPath string, s queueSizes) (QueueConfig, error) {
	success := false
	var eventFD eventfd.Eventfd
	var dataFD, txPipeFD, rxPipeFD, sharedDataFD int
	defer func() {
		if success {
			return
		}
		closeFDs(QueueConfig{
			EventFD:      eventFD,
			DataFD:       dataFD,
			TxPipeFD:     txPipeFD,
			RxPipeFD:     rxPipeFD,
			SharedDataFD: sharedDataFD,
		})
	}()
	eventFD, err := eventfd.Create()
	if err != nil {
		return QueueConfig{}, fmt.Errorf("eventfd failed: %v", err)
	}
	dataFD, err = createFile(sharedMemPath, s.dataSize, false)
	if err != nil {
		return QueueConfig{}, fmt.Errorf("failed to create dataFD: %s", err)
	}
	txPipeFD, err = createFile(sharedMemPath, s.txPipeSize, true)
	if err != nil {
		return QueueConfig{}, fmt.Errorf("failed to create txPipeFD: %s", err)
	}
	rxPipeFD, err = createFile(sharedMemPath, s.rxPipeSize, true)
	if err != nil {
		return QueueConfig{}, fmt.Errorf("failed to create rxPipeFD: %s", err)
	}
	sharedDataFD, err = createFile(sharedMemPath, s.sharedDataSize, false)
	if err != nil {
		return QueueConfig{}, fmt.Errorf("failed to create sharedDataFD: %s", err)
	}
	success = true
	return QueueConfig{
		EventFD:      eventFD,
		DataFD:       dataFD,
		TxPipeFD:     txPipeFD,
		RxPipeFD:     rxPipeFD,
		SharedDataFD: sharedDataFD,
	}, nil
}

func createFile(sharedMemPath string, size int64, initQueue bool) (fd int, err error) {
	var tmpDir = DefaultTmpDir
	if sharedMemPath != "" {
		tmpDir = sharedMemPath
	}
	f, err := os.CreateTemp(tmpDir, "sharedmem_test")
	if err != nil {
		return -1, fmt.Errorf("TempFile failed: %v", err)
	}
	defer f.Close()
	unix.Unlink(f.Name())

	if initQueue {
		if _, err := f.WriteAt([]byte{0, 0, 0, 0, 0, 0, 0, 0x80}, 0); err != nil {
			return -1, fmt.Errorf("WriteAt failed: %v", err)
		}
	}

	fd, err = unix.Dup(int(f.Fd()))
	if err != nil {
		return -1, fmt.Errorf("unix.Dup(%d) failed: %v", f.Fd(), err)
	}

	if err := unix.Ftruncate(fd, size); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("ftruncate(%d, %d) failed: %v", fd, size, err)
	}

	return fd, nil
}

func closeFDs(c QueueConfig) {
	unix.Close(c.DataFD)
	c.EventFD.Close()
	unix.Close(c.TxPipeFD)
	unix.Close(c.RxPipeFD)
	unix.Close(c.SharedDataFD)
}
