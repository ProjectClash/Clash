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

package unet

import (
	"errors"

	"golang.org/x/sys/unix"
	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/eventfd"
	"github.com/metacubex/gvisor/pkg/sync"
)

const backlog = 16

var errClosing = errors.New("Socket is closing")

var errMessageTruncated = errors.New("message truncated")

func socketType(packet bool) int {
	if packet {
		return unix.SOCK_SEQPACKET
	}
	return unix.SOCK_STREAM
}

func socket(packet bool) (int, error) {
	fd, err := unix.Socket(unix.AF_UNIX, socketType(packet), 0)
	if err != nil {
		return 0, err
	}

	return fd, nil
}

type Socket struct {
	gate sync.Gate

	fd atomicbitops.Int32

	efd eventfd.Eventfd

	race *atomicbitops.Int32
}

func NewSocket(fd int) (*Socket, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}

	efd, err := eventfd.Create()
	if err != nil {
		return nil, err
	}

	return &Socket{
		fd:  atomicbitops.FromInt32(int32(fd)),
		efd: efd,
	}, nil
}

func (s *Socket) finish() error {
	if err := s.efd.Notify(); err != nil {
		return err
	}

	s.gate.Close()

	return s.efd.Close()
}

func (s *Socket) Close() error {
	fd := int(s.fd.Swap(-1))
	if fd < 0 {
		return unix.EBADF
	}

	s.shutdown(fd)

	if err := s.finish(); err != nil {
		return err
	}

	return unix.Close(fd)
}

func (s *Socket) Release() (int, error) {
	fd := int(s.fd.Swap(-1))
	if fd < 0 {
		return -1, unix.EBADF
	}

	if err := s.finish(); err != nil {
		return -1, err
	}

	return fd, nil
}

func (s *Socket) FD() int {
	return int(s.fd.Load())
}

func (s *Socket) enterFD() (int, bool) {
	if !s.gate.Enter() {
		return -1, false
	}

	fd := int(s.fd.Load())
	if fd < 0 {
		s.gate.Leave()
		return -1, false
	}

	return fd, true
}

func SocketPair(packet bool) (*Socket, *Socket, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, socketType(packet)|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}

	a, err := NewSocket(fds[0])
	if err != nil {
		unix.Close(fds[0])
		unix.Close(fds[1])
		return nil, nil, err
	}
	var race atomicbitops.Int32
	a.race = &race
	b, err := NewSocket(fds[1])
	if err != nil {
		a.Close()
		unix.Close(fds[1])
		return nil, nil, err
	}
	b.race = &race
	return a, b, nil
}

func Connect(addr string, packet bool) (*Socket, error) {
	fd, err := socket(packet)
	if err != nil {
		return nil, err
	}

	usa := &unix.SockaddrUnix{Name: addr}
	if err := unix.Connect(fd, usa); err != nil {
		unix.Close(fd)
		return nil, err
	}

	return NewSocket(fd)
}

type ControlMessage []byte

func (c *ControlMessage) EnableFDs(count int) {
	*c = make([]byte, unix.CmsgSpace(count*4))
}

func (c *ControlMessage) ExtractFDs() ([]int, error) {
	msgs, err := unix.ParseSocketControlMessage(*c)
	if err != nil {
		return nil, err
	}
	var fds []int
	for _, msg := range msgs {
		thisFds, err := unix.ParseUnixRights(&msg)
		if err != nil {
			return nil, err
		}
		for _, fd := range thisFds {
			if fd >= 0 {
				fds = append(fds, fd)
			}
		}
	}
	return fds, nil
}

func (c *ControlMessage) CloseFDs() {
	fds, _ := c.ExtractFDs()
	for _, fd := range fds {
		if fd >= 0 {
			unix.Close(fd)
		}
	}
}

func (c *ControlMessage) PackFDs(fds ...int) {
	*c = ControlMessage(unix.UnixRights(fds...))
}

func (c *ControlMessage) UnpackFDs() {
	*c = nil
}

type SocketWriter struct {
	socket   *Socket
	to       []byte
	blocking bool
	race     *atomicbitops.Int32

	ControlMessage
}

func (s *Socket) Writer(blocking bool) SocketWriter {
	return SocketWriter{socket: s, blocking: blocking, race: s.race}
}

func (s *Socket) Write(p []byte) (int, error) {
	r := s.Writer(true)
	return r.WriteVec([][]byte{p})
}

func (s *Socket) GetSockOpt(level int, name int, b []byte) (uint32, error) {
	fd, ok := s.enterFD()
	if !ok {
		return 0, unix.EBADF
	}
	defer s.gate.Leave()

	return getsockopt(fd, level, name, b)
}

func (s *Socket) SetSockOpt(level, name int, b []byte) error {
	fd, ok := s.enterFD()
	if !ok {
		return unix.EBADF
	}
	defer s.gate.Leave()

	return setsockopt(fd, level, name, b)
}

func (s *Socket) GetSockName() ([]byte, error) {
	fd, ok := s.enterFD()
	if !ok {
		return nil, unix.EBADF
	}
	defer s.gate.Leave()

	var buf []byte
	l := unix.SizeofSockaddrAny

	for {
		buf = make([]byte, l)
		l, err := getsockname(fd, buf)
		if err != nil {
			return nil, err
		}

		if l <= uint32(len(buf)) {
			return buf[:l], nil
		}
	}
}

func (s *Socket) GetPeerName() ([]byte, error) {
	fd, ok := s.enterFD()
	if !ok {
		return nil, unix.EBADF
	}
	defer s.gate.Leave()

	var buf []byte
	l := unix.SizeofSockaddrAny

	for {
		buf = make([]byte, l)
		l, err := getpeername(fd, buf)
		if err != nil {
			return nil, err
		}

		if l <= uint32(len(buf)) {
			return buf[:l], nil
		}
	}
}

type SocketReader struct {
	socket   *Socket
	source   []byte
	blocking bool
	race     *atomicbitops.Int32

	ControlMessage
}

func (s *Socket) Reader(blocking bool) SocketReader {
	return SocketReader{socket: s, blocking: blocking, race: s.race}
}

func (s *Socket) Read(p []byte) (int, error) {
	r := s.Reader(true)
	return r.ReadVec([][]byte{p})
}

func (s *Socket) shutdown(fd int) error {
	return unix.Shutdown(fd, unix.SHUT_RDWR)
}

func (s *Socket) Shutdown() error {
	fd, ok := s.enterFD()
	if !ok {
		return unix.EBADF
	}
	defer s.gate.Leave()

	return s.shutdown(fd)
}

type ServerSocket struct {
	socket *Socket
}

func NewServerSocket(fd int) (*ServerSocket, error) {
	s, err := NewSocket(fd)
	if err != nil {
		return nil, err
	}
	return &ServerSocket{socket: s}, nil
}

func Bind(addr string, packet bool) (*ServerSocket, error) {
	fd, err := socket(packet)
	if err != nil {
		return nil, err
	}

	usa := &unix.SockaddrUnix{Name: addr}
	if err := unix.Bind(fd, usa); err != nil {
		unix.Close(fd)
		return nil, err
	}

	return NewServerSocket(fd)
}

func BindAndListen(addr string, packet bool) (*ServerSocket, error) {
	s, err := Bind(addr, packet)
	if err != nil {
		return nil, err
	}

	if err := s.Listen(); err != nil {
		s.Close()
		return nil, err
	}

	return s, nil
}

func (s *ServerSocket) Listen() error {
	fd, ok := s.socket.enterFD()
	if !ok {
		return unix.EBADF
	}
	defer s.socket.gate.Leave()

	return unix.Listen(fd, backlog)
}

func (s *ServerSocket) Accept() (*Socket, error) {
	fd, ok := s.socket.enterFD()
	if !ok {
		return nil, unix.EBADF
	}
	defer s.socket.gate.Leave()

	for {
		nfd, _, err := unix.Accept(fd)
		switch err {
		case nil:
			return NewSocket(nfd)
		case unix.EAGAIN:
			err = s.socket.wait(false)
			if err == errClosing {
				err = unix.EBADF
			}
		}
		if err != nil {
			return nil, err
		}
	}
}

func (s *ServerSocket) Close() error {
	return s.socket.Close()
}

func (s *ServerSocket) FD() int {
	return s.socket.FD()
}

func (s *ServerSocket) Release() (int, error) {
	return s.socket.Release()
}
