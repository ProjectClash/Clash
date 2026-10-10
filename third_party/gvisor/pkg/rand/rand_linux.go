// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rand

import (
	"bufio"
	"crypto/rand"
	"io"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/sync"
)

type reader struct {
	once         sync.Once
	useGetrandom bool
}

func (r *reader) Read(p []byte) (int, error) {
	r.once.Do(func() {
		_, err := unix.Getrandom(p, 0)
		if err != unix.ENOSYS {
			r.useGetrandom = true
		}
	})

	if r.useGetrandom {
		return unix.Getrandom(p, 0)
	}
	return rand.Read(p)
}

type bufferedReader struct {
	mu sync.Mutex
	r  *bufio.Reader
}

func (b *bufferedReader) Read(p []byte) (int, error) {
	const pageSize = 4096
	min := len(p)
	if min > pageSize {
		min = pageSize
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return io.ReadAtLeast(b.r, p, min)
}

var Reader io.Reader = &bufferedReader{r: bufio.NewReader(&reader{})}

func Read(b []byte) (int, error) {
	return io.ReadFull(Reader, b)
}

func Init() error {
	p := make([]byte, 1)
	_, err := Read(p)
	return err
}
