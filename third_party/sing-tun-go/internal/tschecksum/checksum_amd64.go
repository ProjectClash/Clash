package tschecksum

import "golang.org/x/sys/cpu"

var (
	useAVX2 = cpu.X86.HasAVX && cpu.X86.HasAVX2 && cpu.X86.HasBMI2
	useSSE2 = cpu.X86.HasSSE2
)

func Checksum(data []byte, initial uint16) uint16 {
	if useAVX2 {
		return checksumAVX2(data, initial)
	}
	if useSSE2 {
		return checksumSSE2(data, initial)
	}
	return checksumAMD64(data, initial)
}
