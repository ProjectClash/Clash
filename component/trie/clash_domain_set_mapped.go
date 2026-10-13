package trie

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"unsafe"
)


var mappedDomainSetMagic = [4]byte{'C', 'D', 'S', '1'}

const mappedDomainSetHeader = 8 + 5*8

func (ss *DomainSet) WriteMapped(w io.Writer) error {
	if !littleEndian() {
		return errors.New("the mapped domain set form needs a little-endian machine")
	}
	var leaves, bitmap []uint64
	var labels []byte
	var ranks, selects []int32
	if ss != nil {
		leaves, bitmap, labels, ranks, selects = ss.leaves, ss.labelBitmap, ss.labels, ss.ranks, ss.selects
	}
	digest := sha256.New()
	out := io.MultiWriter(w, digest)
	header := make([]byte, mappedDomainSetHeader)
	copy(header, mappedDomainSetMagic[:])
	for i, n := range []int{len(leaves), len(bitmap), len(labels), len(ranks), len(selects)} {
		binary.LittleEndian.PutUint64(header[8+8*i:], uint64(n))
	}
	if _, err := out.Write(header); err != nil {
		return err
	}
	write := func(data []byte) error {
		if _, err := out.Write(data); err != nil {
			return err
		}
		if pad := padTo8(len(data)) - len(data); pad > 0 {
			_, err := out.Write(make([]byte, pad))
			return err
		}
		return nil
	}
	for _, part := range [][]byte{wordBytes(leaves), wordBytes(bitmap), labels, int32Bytes(ranks), int32Bytes(selects)} {
		if err := write(part); err != nil {
			return err
		}
	}
	_, err := w.Write(digest.Sum(nil))
	return err
}

func OpenMappedDomainSet(data []byte) (*DomainSet, error) {
	if !littleEndian() {
		return nil, errors.New("the mapped domain set form needs a little-endian machine")
	}
	if len(data) < mappedDomainSetHeader+sha256.Size {
		return nil, fmt.Errorf("a mapped domain set of %d bytes is shorter than its header", len(data))
	}
	if uintptr(unsafe.Pointer(&data[0]))%8 != 0 {
		return nil, errors.New("a mapped domain set must begin on an 8-byte boundary")
	}
	if [4]byte(data[:4]) != mappedDomainSetMagic {
		return nil, errors.New("not a mapped domain set")
	}
	var lengths [5]uint64
	for i := range lengths {
		lengths[i] = binary.LittleEndian.Uint64(data[8+8*i:])
		if lengths[i] > math.MaxInt32 {
			return nil, fmt.Errorf("a mapped domain set's length %d is out of range", lengths[i])
		}
	}
	sizes := [5]int{8 * int(lengths[0]), 8 * int(lengths[1]), int(lengths[2]), 4 * int(lengths[3]), 4 * int(lengths[4])}
	total := mappedDomainSetHeader
	for _, size := range sizes {
		total += padTo8(size)
	}
	if total+sha256.Size != len(data) {
		return nil, fmt.Errorf("a mapped domain set's lengths say %d bytes, the data is %d", total+sha256.Size, len(data))
	}
	if sum := sha256.Sum256(data[:total]); [sha256.Size]byte(data[total:]) != sum {
		return nil, errors.New("a mapped domain set's checksum does not match its bytes")
	}
	if lengths[0] == 0 {
		return nil, nil
	}
	if lengths[1] == 0 || lengths[3] == 0 {
		return nil, errors.New("a mapped domain set without its bitmap or ranks")
	}
	offset := mappedDomainSetHeader
	part := func(i int) []byte {
		p := data[offset : offset+sizes[i]]
		offset += padTo8(sizes[i])
		return p
	}
	ss := &DomainSet{}
	ss.leaves = bytesAsWords(part(0))
	ss.labelBitmap = bytesAsWords(part(1))
	ss.labels = part(2)
	ss.ranks = bytesAsInt32s(part(3))
	ss.selects = bytesAsInt32s(part(4))
	return ss, nil
}

func padTo8(n int) int { return (n + 7) &^ 7 }

func littleEndian() bool {
	probe := uint16(1)
	return *(*byte)(unsafe.Pointer(&probe)) == 1
}

func wordBytes(words []uint64) []byte {
	if len(words) == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), 8*len(words))
}

func int32Bytes(values []int32) []byte {
	if len(values) == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&values[0])), 4*len(values))
}

func bytesAsWords(data []byte) []uint64 {
	if len(data) == 0 {
		return nil
	}
	return unsafe.Slice((*uint64)(unsafe.Pointer(&data[0])), len(data)/8)
}

func bytesAsInt32s(data []byte) []int32 {
	if len(data) == 0 {
		return nil
	}
	return unsafe.Slice((*int32)(unsafe.Pointer(&data[0])), len(data)/4)
}
