package tschecksum

import "golang.org/x/sys/cpu"

var checksum = checksumAMD64

func Checksum(data []byte, initial uint16) uint16 {
	return checksum(data, initial)
}

func init() {
	if cpu.X86.HasAVX && cpu.X86.HasAVX2 && cpu.X86.HasBMI2 {
		checksum = checksumAVX2
		return
	}
	if cpu.X86.HasSSE2 {
		checksum = checksumSSE2
		return
	}
}
