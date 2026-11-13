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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	KeyIter = 64

	KeyRefreshInterval = 2 * time.Minute
)

type pbkdf2Gen struct {
	Salt []byte
	Iter int
}

func (g *pbkdf2Gen) NewKey(password []byte, keyLen int) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password is empty")
	}
	return pbkdf2.Key(password, g.Salt, g.Iter, keyLen, sha256.New), nil
}

func saltFromTime(t time.Time) [][]byte {
	var times []time.Time
	rounded := t.Round(KeyRefreshInterval)
	times = append(times, rounded.Add(-KeyRefreshInterval))
	times = append(times, rounded)
	times = append(times, rounded.Add(KeyRefreshInterval))

	b := make([]byte, 8)
	var salts [][]byte

	for _, t := range times {
		binary.BigEndian.PutUint64(b, uint64(t.Unix()))
		sha := sha256.Sum256(b)
		salts = append(salts, sha[:])
	}

	return salts
}
