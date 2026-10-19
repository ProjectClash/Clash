package clashindex

import (
	"math/bits"
)

const (
	magic   = "CRI1\x00\x00\x00\x00"
	version = 1

	kindOther   = 0
	kindDomain  = 1
	kindSuffix  = 2
	kindKeyword = 3
	kindIP      = 4

	flagNoResolve = 1
	flagWrittenIPv6 = 2

	ruleEntry  = 12
	keyEntry   = 12
	targetEntr = 12

	singlePost = 0x80000000
	noList = 0xffffffff
	noRule = 0xffffffff

	maxRules   = 1<<31 - 1
	maxTargets = 1 << 24
)

const (
	secTargets = iota
	secTargetPool
	secRules
	secPool
	secExact
	secSuffix
	secKeyword
	secKeywordLengths
	secIPv4Starts
	secIPv4Lists
	secIPv6Starts
	secIPv6Lists
	secNodeLists
	secNodes
	secIPPosts
	secResolvers
	sectionCount
)

const (
	sourceAt   = 8 + 4*4
	sectionsAt = sourceAt + 32
	headerSize = sectionsAt + 8*sectionCount
)

func hashOf(s []byte) uint64 {
	const (
		p0 = 0xa0761d6478bd642f
		p1 = 0xe7037ed1a0b428db
		p2 = 0x8ebc6af09c88c6e3
	)
	h := uint64(len(s)) ^ p0
	for ; len(s) >= 8; s = s[8:] {
		w := uint64(s[0]) | uint64(s[1])<<8 | uint64(s[2])<<16 | uint64(s[3])<<24 |
			uint64(s[4])<<32 | uint64(s[5])<<40 | uint64(s[6])<<48 | uint64(s[7])<<56
		h = mix(h^p1, w^p2)
	}
	var tail uint64
	for i := 0; i < len(s); i++ {
		tail |= uint64(s[i]) << (8 * i)
	}
	return mix(h^p2, tail^p1)
}

func mix(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	return hi ^ lo
}

func hashOfString(s string) uint64 {
	return hashOf(unsafeBytes(s))
}

func align4(n int) int { return (n + 3) &^ 3 }

func tableSlots(n int) int {
	if n == 0 {
		return 0
	}
	size := 8
	for size < n+n/4 {
		size <<= 1
	}
	return size
}
