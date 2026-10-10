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

package linewriter

import (
	"bytes"

	"github.com/metacubex/gvisor/pkg/sync"
)

type Writer struct {
	sync.Mutex

	buf bytes.Buffer

	emit func(p []byte)
}

func NewWriter(emitter func(p []byte)) *Writer {
	return &Writer{emit: emitter}
}

func (w *Writer) Write(p []byte) (int, error) {
	w.Lock()
	defer w.Unlock()

	total := 0
	for len(p) > 0 {
		emit := true
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			i = len(p)
			emit = false
		}

		n, err := w.buf.Write(p[:i])
		if err != nil {
			return total, err
		}
		total += n

		p = p[i:]

		if emit {
			p = p[1:]
			total++

			w.emit(w.buf.Bytes())
			w.buf.Reset()
		}
	}

	return total, nil
}
