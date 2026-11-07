package tun

import "golang.org/x/sys/unix"

func (t *NativeTun) UtunFileDescriptor() int {
	return t.tunFd
}

func (t *NativeTun) DetachFromRuntimePoller() error {
	flags, err := unix.FcntlInt(uintptr(t.tunFd), unix.F_GETFD, 0)
	if err != nil {
		return err
	}
	duplicated, err := unix.FcntlInt(uintptr(t.tunFd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(duplicated)
	if err = unix.Dup2(duplicated, t.tunFd); err != nil {
		return err
	}
	_, err = unix.FcntlInt(uintptr(t.tunFd), unix.F_SETFD, flags)
	return err
}
