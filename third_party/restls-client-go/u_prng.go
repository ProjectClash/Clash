/*
 * Copyright (c) 2019, Psiphon Inc.
 * All rights reserved.
 *
 * Released under utls licence:
 * https://github.com/refraction-networking/utls/blob/master/LICENSE
 */


package tls

import (
	crypto_rand "crypto/rand"
	"encoding/binary"
	"io"
	"math"
	"math/rand"
	"sync"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	PRNGSeedLength = 32
)

type PRNGSeed [PRNGSeedLength]byte

func NewPRNGSeed() (*PRNGSeed, error) {
	seed := new(PRNGSeed)
	_, err := crypto_rand.Read(seed[:])
	if err != nil {
		return nil, err
	}
	return seed, nil
}

func newSaltedPRNGSeed(seed *PRNGSeed, salt string) (*PRNGSeed, error) {
	saltedSeed := new(PRNGSeed)
	_, err := io.ReadFull(
		hkdf.New(sha3.New256, seed[:], []byte(salt), nil), saltedSeed[:])
	if err != nil {
		return nil, err
	}
	return saltedSeed, nil
}

type prng struct {
	rand              *rand.Rand
	randomStreamMutex sync.Mutex
	randomStream      sha3.ShakeHash
}

func newPRNG() (*prng, error) {
	seed, err := NewPRNGSeed()
	if err != nil {
		return nil, err
	}
	return newPRNGWithSeed(seed)
}

func newPRNGWithSeed(seed *PRNGSeed) (*prng, error) {
	shake := sha3.NewShake256()
	_, err := shake.Write(seed[:])
	if err != nil {
		return nil, err
	}
	p := &prng{
		randomStream: shake,
	}
	p.rand = rand.New(p)
	return p, nil
}

func newPRNGWithSaltedSeed(seed *PRNGSeed, salt string) (*prng, error) {
	saltedSeed, err := newSaltedPRNGSeed(seed, salt)
	if err != nil {
		return nil, err
	}
	return newPRNGWithSeed(saltedSeed)
}

func (p *prng) Read(b []byte) (int, error) {
	p.randomStreamMutex.Lock()
	defer p.randomStreamMutex.Unlock()

	_, _ = io.ReadFull(p.randomStream, b)

	return len(b), nil
}

func (p *prng) Int63() int64 {
	i := p.Uint64()
	return int64(i & (1<<63 - 1))
}

func (p *prng) Uint64() uint64 {
	var b [8]byte
	p.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}

func (p *prng) Seed(_ int64) {
}

func (p *prng) FlipWeightedCoin(weight float64) bool {
	if weight > 1.0 {
		weight = 1.0
	}
	f := float64(p.Int63()) / float64(math.MaxInt64)
	return f > 1.0-weight
}

func (p *prng) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	return p.rand.Intn(n)
}

func (p *prng) Int63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return p.rand.Int63n(n)
}

func (p *prng) Perm(n int) []int {
	return p.rand.Perm(n)
}

func (p *prng) Range(min, max int) int {
	if min < 0 {
		min = 0
	}
	if max < min {
		return min
	}
	n := p.Intn(max - min + 1)
	n += min
	return n
}
