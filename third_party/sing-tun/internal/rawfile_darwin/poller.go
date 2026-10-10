//go:build darwin

package rawfile

import (
	"sync"

	"golang.org/x/sys/unix"
)

type Poller struct {
	closeOnce sync.Once
	kq        int
	stopFD    int

	registration [3]unix.Kevent_t
	results      [3]unix.Kevent_t
}

func NewPoller(stopFD int) (*Poller, error) {
	kq, err := unix.Kqueue()
	if err != nil {
		return nil, err
	}
	return &Poller{kq: kq, stopFD: stopFD}, nil
}

func (p *Poller) Close() error {
	var err error
	p.closeOnce.Do(func() {
		err = unix.Close(p.kq)
	})
	return err
}

func (p *Poller) Poll(fd int, events int16) (bool, unix.Errno) {
	count := 0

	p.registration[count] = unix.Kevent_t{
		Ident:  uint64(p.stopFD),
		Filter: unix.EVFILT_READ,
		Flags:  unix.EV_ADD | unix.EV_ENABLE,
	}
	count++

	if events&unix.POLLIN != 0 {
		p.registration[count] = unix.Kevent_t{
			Ident:  uint64(fd),
			Filter: unix.EVFILT_READ,
			Flags:  unix.EV_ADD | unix.EV_ENABLE,
		}
		count++
	}
	if events&unix.POLLOUT != 0 {
		p.registration[count] = unix.Kevent_t{
			Ident:  uint64(fd),
			Filter: unix.EVFILT_WRITE,
			Flags:  unix.EV_ADD | unix.EV_ENABLE,
		}
		count++
	}

	n, err := unix.Kevent(p.kq, p.registration[:count], p.results[:count], nil)
	if err != nil {
		if errno, ok := err.(unix.Errno); ok {
			return false, errno
		}
		return false, unix.EINVAL
	}

	stopped := false
	var errno unix.Errno
	for i := 0; i < n; i++ {
		event := &p.results[i]
		if int(event.Ident) == p.stopFD && event.Filter == unix.EVFILT_READ {
			stopped = true
			continue
		}
		if int(event.Ident) == fd && event.Flags&unix.EV_ERROR != 0 {
			errno = unix.Errno(event.Data)
		}
	}
	return stopped, errno
}
