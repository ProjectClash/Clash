package tun

import "golang.org/x/sys/unix"

func ipRewriteFrame(packet []byte) []byte {
	frame := make([]byte, PacketOffset+len(packet))
	frame[3] = unix.AF_INET
	if packet[0]>>4 == 6 {
		frame[3] = unix.AF_INET6
	}
	copy(frame[PacketOffset:], packet)
	return frame
}
