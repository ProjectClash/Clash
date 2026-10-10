//go:build !amd64

package checksum

func Checksum(buf []byte, initial uint16) uint16 {
	s, _ := calculateChecksum(buf, false, initial)
	return s
}
