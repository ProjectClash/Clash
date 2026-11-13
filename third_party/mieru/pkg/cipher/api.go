// Copyright (C) 2021  mieru authors
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
	"bytes"
	"crypto/sha256"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/metrics"
)

const (
	DefaultNonceSize = 24
	DefaultOverhead  = 16
	DefaultKeyLen    = 32

	NoncePrefixLenForUserHint = 16
	NonceSuffixLenForUserHint = 4

	ClientDecryptionMetricGroupName = "cipher - client"
	ServerDecryptionMetricGroupName = "cipher - server"
)

var (
	ClientDirectDecrypt = metrics.RegisterMetric(ClientDecryptionMetricGroupName, "DirectDecrypt", metrics.COUNTER)

	ClientFailedDirectDecrypt = metrics.RegisterMetric(ClientDecryptionMetricGroupName, "FailedDirectDecrypt", metrics.COUNTER)

	ServerDirectDecrypt = metrics.RegisterMetric(ServerDecryptionMetricGroupName, "DirectDecrypt", metrics.COUNTER)

	ServerFailedDirectDecrypt = metrics.RegisterMetric(ServerDecryptionMetricGroupName, "FailedDirectDecrypt", metrics.COUNTER)

	ServerIterateDecrypt = metrics.RegisterMetric(ServerDecryptionMetricGroupName, "IterateDecrypt", metrics.COUNTER)

	ServerFailedIterateDecrypt = metrics.RegisterMetric(ServerDecryptionMetricGroupName, "FailedIterateDecrypt", metrics.COUNTER)

	ServerHintMatchDecrypt = metrics.RegisterMetric(ServerDecryptionMetricGroupName, "HintMatchDecrypt", metrics.COUNTER)

	ServerFailedHintMatchDecrypt = metrics.RegisterMetric(ServerDecryptionMetricGroupName, "FailedHintMatchDecrypt", metrics.COUNTER)
)

type BlockCipher interface {
	Encrypt(dst, plaintext []byte) error

	EncryptWithNonce(dst, nonce, plaintext []byte) error

	Decrypt(ciphertext []byte) ([]byte, error)

	DecryptWithNonce(ciphertext, nonce []byte) ([]byte, error)

	DecryptStatelessTo(ciphertext, dst []byte) ([]byte, error)

	NonceSize() int

	Overhead() int

	Clone() BlockCipher

	CloneStatelessFast() BlockCipher

	SetImplicitNonceMode(enable bool)

	IsStateless() bool

	BlockContext() BlockContext

	SetBlockContext(bc BlockContext)

	NoncePattern() *appctlpb.NoncePattern

	SetNoncePattern(pattern *appctlpb.NoncePattern)
}

type BlockContext struct {
	UserName string
}

func HashPassword(rawPassword, uniqueValue []byte) []byte {
	p := append(rawPassword, 0x00)
	p = append(p, uniqueValue...)
	hashed := sha256.Sum256(p)
	return hashed[:]
}

func BlockCipherFromPassword(password []byte, stateless bool) (BlockCipher, error) {
	entry, err := getCachedCiphers(string(password), time.Now())
	if err != nil {
		return nil, err
	}
	block := entry.cipherList[1].CloneStatelessFast()
	if !stateless {
		block.SetImplicitNonceMode(true)
	}
	return block, nil
}

func BlockCipherListFromPassword(password []byte, stateless bool) ([]BlockCipher, error) {
	entry, err := getCachedCiphers(string(password), time.Now())
	if err != nil {
		return nil, err
	}
	blocks := make([]BlockCipher, len(entry.cipherList))
	for i, template := range entry.cipherList {
		blocks[i] = template.CloneStatelessFast()
		if !stateless {
			blocks[i].SetImplicitNonceMode(true)
		}
	}
	return blocks, nil
}

func TryDecrypt(data, password []byte, stateless bool) (BlockCipher, []byte, error) {
	if stateless {
		entry, err := getCachedCiphers(string(password), time.Now())
		if err != nil {
			return nil, nil, fmt.Errorf("getBlockCipherList() failed: %w", err)
		}
		block, plaintext, err := selectDecryptStateless(data, nil, entry.cipherList)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to decrypt from supplied %d cipher blocks", len(entry.cipherList))
		}
		return block.CloneStatelessFast(), plaintext, nil
	}

	blocks, err := getBlockCipherList(string(password), stateless)
	if err != nil {
		return nil, nil, fmt.Errorf("getBlockCipherList() failed: %w", err)
	}
	block, plaintext, err := selectDecrypt(data, blocks)
	if err != nil {
		return nil, nil, err
	}
	return block, plaintext, nil
}

func CheckUserFromHint(user, nonce []byte) bool {
	if len(user) == 0 {
		panic("user is empty")
	}
	if len(user) > constant.MaxUserNameLen {
		panic(fmt.Sprintf("user name length %d exceeds maximum %d", len(user), constant.MaxUserNameLen))
	}
	if len(nonce) < NoncePrefixLenForUserHint+NonceSuffixLenForUserHint {
		panic(fmt.Sprintf("nonce length %d is too short", len(nonce)))
	}
	var input [constant.MaxUserNameLen + NoncePrefixLenForUserHint]byte
	n := copy(input[:], user)
	n += copy(input[n:], nonce[:NoncePrefixLenForUserHint])
	output := sha256.Sum256(input[:n])
	return bytes.Equal(output[:NonceSuffixLenForUserHint], nonce[len(nonce)-NonceSuffixLenForUserHint:])
}

func NewStatelessDecryptor(password []byte) (*StatelessDecryptor, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password is empty")
	}
	return &StatelessDecryptor{password: string(password)}, nil
}

type StatelessDecryptor struct {
	password string
	ciphers  atomic.Pointer[cachedCiphers]
}

func (d *StatelessDecryptor) TryDecrypt(ciphertext, dst []byte) (BlockCipher, []byte, error) {
	return d.tryDecryptAt(ciphertext, dst, time.Now())
}

func (d *StatelessDecryptor) tryDecryptAt(ciphertext, dst []byte, now time.Time) (BlockCipher, []byte, error) {
	if d == nil {
		return nil, nil, fmt.Errorf("stateless decryptor is nil")
	}
	epoch := cipherKeyEpoch(now)
	entry := d.ciphers.Load()
	if entry == nil || entry.epoch != epoch {
		var err error
		entry, err = getCachedCiphers(d.password, now)
		if err != nil {
			return nil, nil, err
		}
		d.ciphers.Store(entry)
	}
	block, plaintext, err := selectDecryptStateless(ciphertext, dst, entry.cipherList)
	if err != nil {
		return nil, nil, err
	}
	return block.CloneStatelessFast(), plaintext, nil
}

func cipherKeyEpoch(t time.Time) int64 {
	return t.Round(KeyRefreshInterval).Unix()
}
