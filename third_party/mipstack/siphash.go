package mipstack

import (
	"encoding/binary"
	"math/bits"
)

func sipHash24(key [16]byte, message []byte) uint64 {
	length := len(message)
	k0 := binary.LittleEndian.Uint64(key[0:8])
	k1 := binary.LittleEndian.Uint64(key[8:16])
	v0 := uint64(0x736f6d6570736575) ^ k0
	v1 := uint64(0x646f72616e646f6d) ^ k1
	v2 := uint64(0x6c7967656e657261) ^ k0
	v3 := uint64(0x7465646279746573) ^ k1

	for len(message) >= 8 {
		word := binary.LittleEndian.Uint64(message[:8])
		v3 ^= word
		sipHashRound(&v0, &v1, &v2, &v3)
		sipHashRound(&v0, &v1, &v2, &v3)
		v0 ^= word
		message = message[8:]
	}
	last := uint64(length) << 56
	for index, value := range message {
		last |= uint64(value) << (8 * index)
	}
	v3 ^= last
	sipHashRound(&v0, &v1, &v2, &v3)
	sipHashRound(&v0, &v1, &v2, &v3)
	v0 ^= last
	v2 ^= 0xff
	for round := 0; round < 4; round++ {
		sipHashRound(&v0, &v1, &v2, &v3)
	}
	return v0 ^ v1 ^ v2 ^ v3
}

func sipHashRound(v0, v1, v2, v3 *uint64) {
	*v0 += *v1
	*v1 = bits.RotateLeft64(*v1, 13)
	*v1 ^= *v0
	*v0 = bits.RotateLeft64(*v0, 32)
	*v2 += *v3
	*v3 = bits.RotateLeft64(*v3, 16)
	*v3 ^= *v2
	*v0 += *v3
	*v3 = bits.RotateLeft64(*v3, 21)
	*v3 ^= *v0
	*v2 += *v1
	*v1 = bits.RotateLeft64(*v1, 17)
	*v1 ^= *v2
	*v2 = bits.RotateLeft64(*v2, 32)
}
