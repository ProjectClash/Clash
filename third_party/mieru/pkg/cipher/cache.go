// Copyright (C) 2022  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package cipher

import (
	"errors"
	"fmt"
	mrand "math/rand"
	"sync"
	"time"
)

const (
	cacheValidInterval    = KeyRefreshInterval / 4
	cacheValidMaxJitterMs = 5000
)

type cachedCiphers struct {
	cipherList []*aeadBlockCipher
	createTime time.Time
	epoch      int64
}

var blockCipherCache = sync.Map{}

var errUnableToDecrypt = errors.New("unable to decrypt from supplied cipher blocks")

func getBlockCipherList(password string, stateless bool) ([]*aeadBlockCipher, error) {
	entry, err := getCachedCiphers(password, time.Now())
	if err != nil {
		return nil, err
	}
	blocks := make([]*aeadBlockCipher, len(entry.cipherList))
	for i, block := range entry.cipherList {
		if stateless {
			blocks[i] = block
		} else {
			blocks[i] = block.cloneStatelessFast()
			blocks[i].SetImplicitNonceMode(true)
		}
	}
	return blocks, nil
}

func getCachedCiphers(password string, now time.Time) (*cachedCiphers, error) {
	c, ok := blockCipherCache.Load(password)
	if ok {
		entry := c.(*cachedCiphers)
		jitter := time.Duration(mrand.Intn(cacheValidMaxJitterMs)) * time.Millisecond
		if entry.epoch != cipherKeyEpoch(now) || entry.createTime.Add(cacheValidInterval-jitter).Before(now) {
			ok = false
		}
	}
	if ok {
		return c.(*cachedCiphers), nil
	}

	blockCiphers, err := newBlockCipherList([]byte(password), now)
	if err != nil {
		return nil, fmt.Errorf("newBlockCipherList() failed: %v", err)
	}

	entry := &cachedCiphers{
		cipherList: blockCiphers,
		createTime: now,
		epoch:      cipherKeyEpoch(now),
	}
	blockCipherCache.Store(password, entry)
	return entry, nil
}

func newBlockCipherList(password []byte, now time.Time) ([]*aeadBlockCipher, error) {
	salts := saltFromTime(now)
	blockCiphers := make([]*aeadBlockCipher, 0, 3)
	for i := 0; i < 3; i++ {
		keygen := pbkdf2Gen{
			Salt: salts[i],
			Iter: KeyIter,
		}
		cipherKey, err := keygen.NewKey(password, DefaultKeyLen)
		if err != nil {
			return nil, fmt.Errorf("NewKey() failed: %w", err)
		}
		blockCipher, err := newXChaCha20Poly1305BlockCipher(cipherKey)
		if err != nil {
			return nil, fmt.Errorf("newXChaCha20Poly1305BlockCipher() failed: %w", err)
		}
		blockCiphers = append(blockCiphers, blockCipher)
	}
	return blockCiphers, nil
}
