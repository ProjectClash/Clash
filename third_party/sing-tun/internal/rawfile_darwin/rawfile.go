package rawfile

import (
	"reflect"
	"unsafe"

	"golang.org/x/sys/unix"
)

const SizeofIovec = unsafe.Sizeof(unix.Iovec{})

const MaxIovs = 1024

func IovecFromBytes(bs []byte) unix.Iovec {
	iov := unix.Iovec{
		Base: &bs[0],
	}
	iov.SetLen(len(bs))
	return iov
}

func bytesFromIovec(iov unix.Iovec) (bs []byte) {
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&bs))
	sh.Data = uintptr(unsafe.Pointer(iov.Base))
	sh.Len = int(iov.Len)
	sh.Cap = int(iov.Len)
	return
}

func AppendIovecFromBytes(iovs []unix.Iovec, bs []byte, max int) []unix.Iovec {
	if len(bs) == 0 {
		return iovs
	}
	if len(iovs) < max {
		return append(iovs, IovecFromBytes(bs))
	}
	iovs[len(iovs)-1] = IovecFromBytes(append(bytesFromIovec(iovs[len(iovs)-1]), bs...))
	return iovs
}

type MsgHdrX struct {
	Msg     unix.Msghdr
	DataLen uint32
}

func NonBlockingSendMMsg(fd int, msgHdrs []MsgHdrX) (int, unix.Errno) {
	n, _, e := unix.RawSyscall6(unix.SYS_SENDMSG_X, uintptr(fd), uintptr(unsafe.Pointer(&msgHdrs[0])), uintptr(len(msgHdrs)), unix.MSG_DONTWAIT, 0, 0)
	return int(n), e
}

const SizeofMsgHdrX = unsafe.Sizeof(MsgHdrX{})

func NonBlockingWriteIovec(fd int, iovec []unix.Iovec) unix.Errno {
	iovecLen := uintptr(len(iovec))
	_, _, e := unix.RawSyscall(unix.SYS_WRITEV, uintptr(fd), uintptr(unsafe.Pointer(&iovec[0])), iovecLen)
	return e
}

func BlockingReadvUntilStopped(efd int, fd int, iovecs []unix.Iovec) (int, unix.Errno) {
	for {
		n, _, e := unix.RawSyscall(unix.SYS_READV, uintptr(fd), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)))
		recordPacketReadResult(e)
		if e == 0 {
			return int(n), 0
		}
		if e != 0 && e != unix.EWOULDBLOCK {
			return 0, e
		}
		stopped, e := BlockingPollUntilStopped(efd, fd, unix.POLLIN)
		if stopped {
			return -1, e
		}
		if e != 0 && e != unix.EINTR {
			return 0, e
		}
	}
}

func BlockingReadvUntilStoppedPolled(poller *Poller, fd int, iovecs []unix.Iovec) (int, unix.Errno) {
	for {
		n, _, e := unix.RawSyscall(unix.SYS_READV, uintptr(fd), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)))
		recordPacketReadResult(e)
		if e == 0 {
			return int(n), 0
		}
		if e != 0 && e != unix.EWOULDBLOCK {
			return 0, e
		}
		stopped, e := poller.Poll(fd, unix.POLLIN)
		if stopped {
			return -1, e
		}
		if e != 0 && e != unix.EINTR {
			return 0, e
		}
	}
}

func BlockingRecvMMsgUntilStoppedPolled(poller *Poller, fd int, msgHdrs []MsgHdrX) (int, unix.Errno) {
	for {
		n, _, e := unix.RawSyscall6(unix.SYS_RECVMSG_X, uintptr(fd), uintptr(unsafe.Pointer(&msgHdrs[0])), uintptr(len(msgHdrs)), unix.MSG_DONTWAIT, 0, 0)
		recordPacketReadResult(e)
		if e == 0 {
			return int(n), 0
		}
		if e != 0 && e != unix.EWOULDBLOCK {
			return 0, e
		}
		stopped, e := poller.Poll(fd, unix.POLLIN)
		if stopped {
			return -1, e
		}
		if e != 0 && e != unix.EINTR {
			return 0, e
		}
	}
}

func BlockingRecvMMsgUntilStopped(efd int, fd int, msgHdrs []MsgHdrX) (int, unix.Errno) {
	for {
		n, _, e := unix.RawSyscall6(unix.SYS_RECVMSG_X, uintptr(fd), uintptr(unsafe.Pointer(&msgHdrs[0])), uintptr(len(msgHdrs)), unix.MSG_DONTWAIT, 0, 0)
		recordPacketReadResult(e)
		if e == 0 {
			return int(n), e
		}

		if e != 0 && e != unix.EWOULDBLOCK {
			return 0, e
		}

		stopped, e := BlockingPollUntilStopped(efd, fd, unix.POLLIN)
		if stopped {
			return -1, e
		}
		if e != 0 && e != unix.EINTR {
			return 0, e
		}
	}
}

func BlockingPollUntilStopped(efd int, fd int, events int16) (bool, unix.Errno) {
	kq, err := unix.Kqueue()
	if err != nil {
		return false, unix.Errno(err.(unix.Errno))
	}
	defer unix.Close(kq)

	var kevents []unix.Kevent_t

	kevents = append(kevents, unix.Kevent_t{
		Ident:  uint64(efd),
		Filter: unix.EVFILT_READ,
		Flags:  unix.EV_ADD | unix.EV_ENABLE,
	})

	if events&unix.POLLIN != 0 {
		kevents = append(kevents, unix.Kevent_t{
			Ident:  uint64(fd),
			Filter: unix.EVFILT_READ,
			Flags:  unix.EV_ADD | unix.EV_ENABLE,
		})
	}
	if events&unix.POLLOUT != 0 {
		kevents = append(kevents, unix.Kevent_t{
			Ident:  uint64(fd),
			Filter: unix.EVFILT_WRITE,
			Flags:  unix.EV_ADD | unix.EV_ENABLE,
		})
	}

	_, err = unix.Kevent(kq, kevents, nil, nil)
	if err != nil {
		return false, unix.Errno(err.(unix.Errno))
	}

	revents := make([]unix.Kevent_t, len(kevents))
	n, err := unix.Kevent(kq, nil, revents, nil)
	if err != nil {
		return false, unix.Errno(err.(unix.Errno))
	}

	var efdHasData bool
	var errno unix.Errno

	for i := 0; i < n; i++ {
		ev := &revents[i]

		if int(ev.Ident) == efd && ev.Filter == unix.EVFILT_READ {
			efdHasData = true
		}

		if int(ev.Ident) == fd {
			if ev.Flags&unix.EV_EOF != 0 {
				errno = unix.ECONNRESET
			} else if ev.Flags&unix.EV_ERROR != 0 {
				if ev.Data != 0 {
					errno = unix.Errno(ev.Data)
				} else {
					errno = unix.ECONNRESET
				}
			}
		}
	}

	return efdHasData, errno
}
