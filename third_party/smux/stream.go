// MIT License
//
// Copyright (c) 2016-2017 xtaci
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package smux

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Stream struct {
	*stream
}

type stream struct {
	id   uint32
	sess *Session

	buffers [][]byte
	heads   []*[]byte

	bufferLock sync.Mutex
	frameSize  int

	chReaderWakeup chan struct{}
	chWriterWakeup chan struct{}

	die     chan struct{}
	dieOnce sync.Once

	chFinEvent   chan struct{}
	finEventOnce sync.Once

	readDeadline  atomic.Value
	writeDeadline atomic.Value

	numRead    uint32
	numWritten uint32
	incr       uint32

	peerConsumed uint32
	peerWindow   uint32
	chUpdate     chan struct{}
}

func newStream(id uint32, frameSize int, sess *Session) *stream {
	s := new(stream)
	s.id = id
	s.chReaderWakeup = make(chan struct{}, 1)
	s.chWriterWakeup = make(chan struct{}, 1)
	s.chUpdate = make(chan struct{}, 1)
	s.frameSize = frameSize
	s.sess = sess
	s.die = make(chan struct{})
	s.chFinEvent = make(chan struct{})
	s.peerWindow = initialPeerWindow

	return s
}

func (s *stream) ID() uint32 {
	return s.id
}

func (s *stream) Read(b []byte) (n int, err error) {
	for {
		switch s.sess.config.Version {
		case 2:
			n, err = s.tryReadV2(b)
		default:
			n, err = s.tryReadV1(b)
		}

		if err != ErrWouldBlock {
			return n, err
		}

		if ew := s.waitRead(); ew != nil {
			return 0, ew
		}
	}
}

func (s *stream) tryReadV1(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	s.bufferLock.Lock()
	if len(s.buffers) > 0 {
		n = copy(b, s.buffers[0])
		s.buffers[0] = s.buffers[0][n:]

		if len(s.buffers[0]) == 0 {
			s.buffers[0] = nil
			s.buffers = s.buffers[1:]
			defaultAllocator.Put(s.heads[0])
			s.heads = s.heads[1:]
		}
	}
	s.bufferLock.Unlock()

	if n > 0 {
		s.sess.returnTokens(n)
		return n, nil
	}

	select {
	case <-s.die:
		return 0, io.EOF
	default:
		return 0, ErrWouldBlock
	}
}

func (s *stream) tryReadV2(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	var notifyConsumed uint32
	s.bufferLock.Lock()
	if len(s.buffers) > 0 {
		n = copy(b, s.buffers[0])
		s.buffers[0] = s.buffers[0][n:]

		if len(s.buffers[0]) == 0 {
			s.buffers[0] = nil
			s.buffers = s.buffers[1:]
			defaultAllocator.Put(s.heads[0])
			s.heads = s.heads[1:]
		}
	}

	s.numRead += uint32(n)
	s.incr += uint32(n)

	if s.incr >= uint32(s.sess.config.MaxStreamBuffer/2) || s.numRead == uint32(n) {
		notifyConsumed = s.numRead
		s.incr = 0
	}
	s.bufferLock.Unlock()

	if n > 0 {
		s.sess.returnTokens(n)

		if notifyConsumed > 0 {
			return n, s.sendWindowUpdate(notifyConsumed)
		}
		return n, nil
	}

	select {
	case <-s.die:
		return 0, io.EOF
	default:
		return 0, ErrWouldBlock
	}
}

func (s *stream) WriteTo(w io.Writer) (n int64, err error) {
	switch s.sess.config.Version {
	case 2:
		return s.writeToV2(w)
	default:
		return s.writeToV1(w)
	}
}

func (s *stream) writeToV1(w io.Writer) (n int64, err error) {
	for {
		var buf []byte
		var head *[]byte

		s.bufferLock.Lock()
		if len(s.buffers) > 0 {
			buf = s.buffers[0]
			head = s.heads[0]
			s.buffers = s.buffers[1:]
			s.heads = s.heads[1:]
		}
		s.bufferLock.Unlock()

		if buf != nil {
			nw, ew := w.Write(buf)
			s.sess.returnTokens(len(buf))
			defaultAllocator.Put(head)
			if nw > 0 {
				n += int64(nw)
			}

			if ew != nil {
				return n, ew
			}
		} else if ew := s.waitRead(); ew != nil {
			return n, ew
		}
	}
}

func (s *stream) writeToV2(w io.Writer) (n int64, err error) {
	for {
		var notifyConsumed uint32
		var buf []byte
		var head *[]byte

		s.bufferLock.Lock()
		if len(s.buffers) > 0 {
			buf = s.buffers[0]
			head = s.heads[0]
			s.buffers = s.buffers[1:]
			s.heads = s.heads[1:]
		}

		var bufLen uint32
		if buf != nil {
			bufLen = uint32(len(buf))
		}
		s.numRead += bufLen
		s.incr += bufLen

		if s.incr >= uint32(s.sess.config.MaxStreamBuffer/2) || s.numRead == bufLen {
			notifyConsumed = s.numRead
			s.incr = 0
		}
		s.bufferLock.Unlock()

		if buf != nil {
			nw, ew := w.Write(buf)
			s.sess.returnTokens(len(buf))
			defaultAllocator.Put(head)
			if nw > 0 {
				n += int64(nw)
			}

			if ew != nil {
				return n, ew
			}

			if notifyConsumed > 0 {
				if err := s.sendWindowUpdate(notifyConsumed); err != nil {
					return n, err
				}
			}
		} else if ew := s.waitRead(); ew != nil {
			return n, ew
		}
	}
}

func (s *stream) sendWindowUpdate(consumed uint32) error {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := s.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	frame := newFrame(byte(s.sess.config.Version), cmdUPD, s.id)
	var hdr updHeader
	binary.LittleEndian.PutUint32(hdr[:], consumed)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(s.sess.config.MaxStreamBuffer))
	frame.data = hdr[:]
	_, err := s.sess.writeFrameInternal(frame, deadline, CLSCTRL)
	return err
}

func (s *stream) waitRead() error {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := s.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-s.chReaderWakeup:
		return nil
	case <-s.chFinEvent:
		s.bufferLock.Lock()
		defer s.bufferLock.Unlock()
		if len(s.buffers) > 0 {
			return nil
		}
		return io.EOF
	case <-s.sess.chSocketReadError:
		return s.sess.socketReadError.Load().(error)
	case <-s.sess.chProtoError:
		return s.sess.protoError.Load().(error)
	case <-deadline:
		return ErrTimeout
	case <-s.die:
		return io.ErrClosedPipe
	}

}

func (s *stream) Write(b []byte) (n int, err error) {
	switch s.sess.config.Version {
	case 2:
		return s.writeV2(b)
	default:
		return s.writeV1(b)
	}
}

func (s *stream) writeV1(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	select {
	case <-s.chFinEvent:
		return 0, io.EOF
	case <-s.die:
		return 0, io.ErrClosedPipe
	default:
	}

	var deadline <-chan time.Time
	if d, ok := s.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	sent := 0
	frame := newFrame(byte(s.sess.config.Version), cmdPSH, s.id)
	for len(b) > 0 {
		size := len(b)
		if size > s.frameSize {
			size = s.frameSize
		}

		frame.data = b[:size]
		n, err := s.sess.writeFrameInternal(frame, deadline, CLSDATA)
		atomic.AddUint32(&s.numWritten, uint32(size))
		sent += n
		if err != nil {
			return sent, err
		}

		b = b[size:]
	}

	return sent, nil
}

func (s *stream) writeV2(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	select {
	case <-s.chFinEvent:
		return 0, io.EOF
	case <-s.die:
		return 0, io.ErrClosedPipe
	default:
	}

	sent := 0
	frame := newFrame(byte(s.sess.config.Version), cmdPSH, s.id)

	var deadlineTimer *time.Timer
	defer func() {
		stopTimer(deadlineTimer)
	}()

	for {
		deadline := (<-chan time.Time)(nil)
		if d, ok := s.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
			dur := time.Until(d)
			if dur < 0 {
				dur = 0
			}
			if deadlineTimer == nil {
				deadlineTimer = time.NewTimer(dur)
			} else {
				stopTimer(deadlineTimer)
				deadlineTimer.Reset(dur)
			}
			deadline = deadlineTimer.C
		} else if deadlineTimer != nil {
			stopTimer(deadlineTimer)
			deadlineTimer = nil
		}

		inflight := int32(atomic.LoadUint32(&s.numWritten) - atomic.LoadUint32(&s.peerConsumed))
		if inflight < 0 {
			return 0, ErrConsumed
		}

		win := int32(atomic.LoadUint32(&s.peerWindow)) - inflight

		if win > 0 {
			n := len(b)
			if n > int(win) {
				n = int(win)
			}

			bts := b[:n]
			for len(bts) > 0 {
				size := len(bts)
				if size > s.frameSize {
					size = s.frameSize
				}
				frame.data = bts[:size]

				nw, err := s.sess.writeFrameInternal(frame, deadline, CLSDATA)
				atomic.AddUint32(&s.numWritten, uint32(size))
				sent += nw
				if err != nil {
					return sent, err
				}

				bts = bts[size:]
			}

			b = b[n:]
		}

		if len(b) <= 0 {
			return sent, nil
		}

		select {
		case <-s.chWriterWakeup:
		case <-s.chFinEvent:
			return 0, io.EOF
		case <-s.die:
			return sent, io.ErrClosedPipe
		case <-deadline:
			return sent, ErrTimeout
		case <-s.sess.chSocketWriteError:
			return sent, s.sess.socketWriteError.Load().(error)
		case <-s.chUpdate:
			continue
		}
	}
}

func (s *stream) Close() error {
	var once bool
	s.dieOnce.Do(func() {
		close(s.die)
		once = true
	})

	if !once {
		return io.ErrClosedPipe
	}

	f := newFrame(byte(s.sess.config.Version), cmdFIN, s.id)

	timer := time.NewTimer(openCloseTimeout)
	defer timer.Stop()

	_, err := s.sess.writeFrameInternal(f, timer.C, CLSDATA)
	s.sess.streamClosed(s.id)
	return err
}

func (s *stream) GetDieCh() <-chan struct{} {
	return s.die
}

func (s *stream) SetReadDeadline(t time.Time) error {
	s.readDeadline.Store(t)
	s.wakeupReader()
	return nil
}

func (s *stream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Store(t)
	s.wakeupWriter()
	return nil
}

func (s *stream) SetDeadline(t time.Time) error {
	if err := s.SetReadDeadline(t); err != nil {
		return err
	}
	if err := s.SetWriteDeadline(t); err != nil {
		return err
	}
	return nil
}

func (s *stream) sessionClose() { s.dieOnce.Do(func() { close(s.die) }) }

func (s *stream) LocalAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		LocalAddr() net.Addr
	}); ok {
		return ts.LocalAddr()
	}
	return nil
}

func (s *stream) RemoteAddr() net.Addr {
	if ts, ok := s.sess.conn.(interface {
		RemoteAddr() net.Addr
	}); ok {
		return ts.RemoteAddr()
	}
	return nil
}

func (s *stream) pushBytes(pbuf *[]byte) {
	s.bufferLock.Lock()
	defer s.bufferLock.Unlock()

	s.buffers = append(s.buffers, *pbuf)
	s.heads = append(s.heads, pbuf)
}

func (s *stream) recycleTokens() (n int) {
	s.bufferLock.Lock()
	defer s.bufferLock.Unlock()

	for k := range s.buffers {
		n += len(s.buffers[k])
		defaultAllocator.Put(s.heads[k])
	}
	s.buffers = nil
	s.heads = nil
	return
}

func (s *stream) wakeupReader() {
	select {
	case s.chReaderWakeup <- struct{}{}:
	default:
	}
}

func (s *stream) wakeupWriter() {
	select {
	case s.chWriterWakeup <- struct{}{}:
	default:
	}
}

func (s *stream) update(consumed uint32, window uint32) {
	atomic.StoreUint32(&s.peerConsumed, consumed)
	atomic.StoreUint32(&s.peerWindow, window)

	select {
	case s.chUpdate <- struct{}{}:
	default:
	}
}

func (s *stream) fin() {
	s.finEventOnce.Do(func() {
		close(s.chFinEvent)
	})
}

func stopTimer(t *time.Timer) {
	if t == nil {
		return
	}
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}
