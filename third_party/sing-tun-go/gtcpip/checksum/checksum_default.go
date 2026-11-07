//go:build !amd64 && !arm64

package checksum

func Checksum(buf []byte, initial uint16) uint16 {
	return ChecksumDefault(buf, initial)
}
