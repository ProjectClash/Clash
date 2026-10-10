package mipstack

import "testing"

func TestSipHash24ReferenceVectors(t *testing.T) {
	var key [16]byte
	var message [64]byte
	for index := range key {
		key[index] = byte(index)
	}
	for index := range message {
		message[index] = byte(index)
	}
	for _, test := range []struct {
		length int
		want   uint64
	}{
		{length: 0, want: 0x726fdb47dd0e0e31},
		{length: 7, want: 0xab0200f58b01d137},
		{length: 15, want: 0xa129ca6149be45e5},
		{length: 31, want: 0x32d892fad841c342},
		{length: 63, want: 0x958a324ceb064572},
	} {
		if got := sipHash24(key, message[:test.length]); got != test.want {
			t.Fatalf("SipHash-2-4 length %d = %#016x, want %#016x", test.length, got, test.want)
		}
	}
}
