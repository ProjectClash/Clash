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

package fdnotifier

import (
	"fmt"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/waiter"
)

type fdInfo struct {
	queue   *waiter.Queue
	waiting bool
}

type notifier struct {
	epFD int

	pauseMu sync.Mutex

	mu sync.Mutex

	fdMap map[int32]*fdInfo
}

func newNotifier() (*notifier, error) {
	epfd, err := unix.EpollCreate1(0)
	if err != nil {
		return nil, err
	}

	w := &notifier{
		epFD:  epfd,
		fdMap: make(map[int32]*fdInfo),
	}

	go w.waitAndNotify()

	return w, nil
}

func (n *notifier) waitFD(fd int32, fi *fdInfo, mask waiter.EventMask) error {
	if !fi.waiting && mask == 0 {
		return nil
	}

	e := unix.EpollEvent{
		Events: mask.ToLinux() | unix.EPOLLET,
		Fd:     fd,
	}

	switch {
	case !fi.waiting && mask != 0:
		if err := unix.EpollCtl(n.epFD, unix.EPOLL_CTL_ADD, int(fd), &e); err != nil {
			return err
		}
		fi.waiting = true
	case fi.waiting && mask == 0:
		unix.EpollCtl(n.epFD, unix.EPOLL_CTL_DEL, int(fd), nil)
		fi.waiting = false
	case fi.waiting && mask != 0:
		if err := unix.EpollCtl(n.epFD, unix.EPOLL_CTL_MOD, int(fd), &e); err != nil {
			return err
		}
	}

	return nil
}

func (n *notifier) addFD(fd int32, queue *waiter.Queue) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if _, ok := n.fdMap[fd]; ok {
		panic(fmt.Sprintf("File descriptor %v added twice", fd))
	}

	info := &fdInfo{queue: queue}
	if err := n.waitFD(fd, info, queue.Events()); err != nil {
		return err
	}
	n.fdMap[fd] = info
	return nil
}

func (n *notifier) updateFD(fd int32) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if fi, ok := n.fdMap[fd]; ok {
		return n.waitFD(fd, fi, fi.queue.Events())
	}

	return nil
}

func (n *notifier) removeFD(fd int32) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.waitFD(fd, n.fdMap[fd], 0)
	delete(n.fdMap, fd)
}

func (n *notifier) hasFD(fd int32) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	_, ok := n.fdMap[fd]
	return ok
}

func (n *notifier) waitAndNotify() error {
	e := make([]unix.EpollEvent, 100)
	for {
		v, err := epollWait(n.epFD, e, -1)
		if err == unix.EINTR {
			continue
		}

		if err != nil {
			return err
		}

		notified := false
		n.pauseMu.Lock()
		n.mu.Lock()
		for i := 0; i < v; i++ {
			if fi, ok := n.fdMap[e[i].Fd]; ok {
				fi.queue.Notify(waiter.EventMaskFromLinux(e[i].Events))
				notified = true
			}
		}
		n.mu.Unlock()
		n.pauseMu.Unlock()
		if notified {
			sync.Goyield()
		}
	}
}

func (n *notifier) pause() {
	n.pauseMu.Lock()
}

func (n *notifier) resume() {
	n.pauseMu.Unlock()
}

var shared struct {
	notifier *notifier
	once     sync.Once
	initErr  error
}

func ensureSharedNotifier() {
	shared.once.Do(func() {
		shared.notifier, shared.initErr = newNotifier()
	})
}

func AddFD(fd int32, queue *waiter.Queue) error {
	ensureSharedNotifier()
	if shared.initErr != nil {
		return shared.initErr
	}

	return shared.notifier.addFD(fd, queue)
}

func UpdateFD(fd int32) error {
	return shared.notifier.updateFD(fd)
}

func RemoveFD(fd int32) {
	shared.notifier.removeFD(fd)
}

func HasFD(fd int32) bool {
	return shared.notifier.hasFD(fd)
}

func Pause() {
	ensureSharedNotifier()
	shared.notifier.pause()
}

func Resume() {
	shared.notifier.resume()
}
