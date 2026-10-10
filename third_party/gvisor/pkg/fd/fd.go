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

package fd

import (
	"fmt"
	"io"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/atomicbitops"
)

type ReadWriter struct {
	fd atomicbitops.Int64
}

var _ io.ReadWriter = (*ReadWriter)(nil)
var _ io.ReaderAt = (*ReadWriter)(nil)
var _ io.WriterAt = (*ReadWriter)(nil)

func NewReadWriter(fd int) *ReadWriter {
	return &ReadWriter{
		fd: atomicbitops.FromInt64(int64(fd)),
	}
}

func fixCount(n int, err error) (int, error) {
	if n < 0 {
		n = 0
	}
	return n, err
}

func (r *ReadWriter) Read(b []byte) (int, error) {
	c, err := fixCount(unix.Read(r.FD(), b))
	if c == 0 && len(b) > 0 && err == nil {
		return 0, io.EOF
	}
	return c, err
}

func (r *ReadWriter) ReadAt(b []byte, off int64) (c int, err error) {
	for len(b) > 0 {
		var m int
		m, err = fixCount(unix.Pread(r.FD(), b, off))
		if m == 0 && err == nil {
			return c, io.EOF
		}
		if err != nil {
			return c, err
		}
		c += m
		b = b[m:]
		off += int64(m)
	}
	return
}

func (r *ReadWriter) Write(b []byte) (int, error) {
	var err error
	var n, remaining int
	for remaining = len(b); remaining > 0; {
		woff := len(b) - remaining
		n, err = unix.Write(r.FD(), b[woff:])

		if n > 0 {
			remaining -= n
		} else {
			if err == nil {
				panic(fmt.Sprintf("unix.Write returned %d with no error", n))
			}

			if err != unix.EINTR {
				break
			}
		}
	}

	return len(b) - remaining, err
}

func (r *ReadWriter) WriteAt(b []byte, off int64) (c int, err error) {
	for len(b) > 0 {
		var m int
		m, err = fixCount(unix.Pwrite(r.FD(), b, off))
		if err != nil {
			break
		}
		c += m
		b = b[m:]
		off += int64(m)
	}
	return
}

func (r *ReadWriter) FD() int {
	return int(r.fd.Load())
}

func (r *ReadWriter) String() string {
	return fmt.Sprintf("FD: %d", r.FD())
}

type FD struct {
	ReadWriter
}

func New(fd int) *FD {
	if fd < 0 {
		return &FD{
			ReadWriter: ReadWriter{
				fd: atomicbitops.FromInt64(-1),
			},
		}
	}
	f := &FD{
		ReadWriter: ReadWriter{
			fd: atomicbitops.FromInt64(int64(fd)),
		},
	}
	runtime.SetFinalizer(f, (*FD).Close)
	return f
}

func NewFromFile(file *os.File) (*FD, error) {
	fd, err := unix.Dup(int(file.Fd()))
	runtime.KeepAlive(file)
	if err != nil {
		return &FD{
			ReadWriter: ReadWriter{
				fd: atomicbitops.FromInt64(-1),
			},
		}, err
	}
	return New(fd), nil
}

func NewFromFiles(files []*os.File) ([]*FD, error) {
	rv := make([]*FD, 0, len(files))
	for _, f := range files {
		new, err := NewFromFile(f)
		if err != nil {
			for _, fd := range rv {
				fd.Close()
			}
			return nil, err
		}
		rv = append(rv, new)
	}
	return rv, nil
}

func Open(path string, openmode int, perm uint32) (*FD, error) {
	f, err := unix.Open(path, openmode|unix.O_LARGEFILE, perm)
	if err != nil {
		return nil, err
	}
	return New(f), nil
}

func OpenAt(dir *FD, path string, flags int, mode uint32) (*FD, error) {
	f, err := unix.Openat(dir.FD(), path, flags, mode)
	if err != nil {
		return nil, err
	}
	return New(f), nil
}

func (f *FD) Close() error {
	runtime.SetFinalizer(f, nil)
	return unix.Close(int(f.fd.Swap(-1)))
}

func (f *FD) Release() int {
	runtime.SetFinalizer(f, nil)
	return int(f.fd.Swap(-1))
}

func (f *FD) File() (*os.File, error) {
	fd, err := unix.Dup(f.FD())
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), ""), nil
}

func (f *FD) ReleaseToFile(name string) *os.File {
	return os.NewFile(uintptr(f.Release()), name)
}

func ReleaseToFiles(fds []*FD, name string) []*os.File {
	files := make([]*os.File, len(fds))
	for i, fd := range fds {
		files[i] = fd.ReleaseToFile(name)
	}
	return files
}
