package tun

import (
	"strings"

	"golang.org/x/sys/unix"
)

func UtunControlName(fd int) (string, bool) {
	peer, ok := kernelControlPeer(fd)
	if !ok {
		return "", false
	}
	if utun, ok := kernelControlID(fd, "com.apple.net.utun_control"); !ok || peer != utun {
		return "", false
	}
	name, err := unix.GetsockoptString(fd, 2, 2)
	if err != nil || !strings.HasPrefix(name, "utun") {
		return "", false
	}
	return name, true
}

func kernelControlPeer(fd int) (uint32, bool) {
	peer, err := unix.Getpeername(fd)
	if err != nil {
		return 0, false
	}
	control, ok := peer.(*unix.SockaddrCtl)
	if !ok {
		return 0, false
	}
	return control.ID, true
}

func kernelControlID(fd int, name string) (uint32, bool) {
	info := &unix.CtlInfo{}
	copy(info.Name[:], name)
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		return 0, false
	}
	return info.Id, true
}
