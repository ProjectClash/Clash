//go:build with_low_memory

package net

import (
	"errors"
	"io"
	"syscall"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	N "github.com/metacubex/sing/common/network"
)

const lowMemoryRelayMTU = 2 * 1024

func relayCopy(destination io.Writer, source io.Reader) (n int64, err error) {
	if source == nil {
		return 0, E.New("nil reader")
	}
	if destination == nil {
		return 0, E.New("nil writer")
	}

	originSource := source
	var readCounters, writeCounters []N.CountFunc
	possiblyReplaceable := bufio.MaxCopyExtendedOnceTimes
	for {
		if buffered, ok := source.(*BufferedConn); ok && buffered.r != nil && buffered.r.Buffered() == 0 {
			buffered.r = nil
		}
		source, readCounters = N.UnwrapCountReader(source, readCounters)
		destination, writeCounters = N.UnwrapCountWriter(destination, writeCounters)

		if cachedSource, isCached := source.(N.CachedReader); isCached {
			cachedBuffer := cachedSource.ReadCached()
			if cachedBuffer != nil {
				dataLen := cachedBuffer.Len()
				_, err = destination.Write(cachedBuffer.Bytes())
				cachedBuffer.Release()
				if err != nil {
					return
				}
				countRelayBytes(readCounters, int64(dataLen))
				countRelayBytes(writeCounters, int64(dataLen))
				continue
			}
		}

		replaceableReader, readerPossiblyReplaceable := source.(N.ReaderPossiblyReplaceable)
		replaceableWriter, writerPossiblyReplaceable := destination.(N.WriterPossiblyReplaceable)
		if possiblyReplaceable != 0 && ((readerPossiblyReplaceable && replaceableReader.ReaderPossiblyReplaceable()) ||
			(writerPossiblyReplaceable && replaceableWriter.WriterPossiblyReplaceable())) {
			possiblyReplaceable--
			var copied int64
			streamReader := &boundedRelayReader{Reader: source}
			copied, err = bufio.CopyExtendedOnce(newBoundedRelayWriter(destination), streamReader, readCounters, writeCounters)
			n += copied
			if err != nil {
				if n == copied {
					err = N.ReportHandshakeFailure(originSource, err)
				}
				if errors.Is(err, io.EOF) {
					err = nil
				}
				return
			}
			if streamReader.pendingError != nil {
				if !errors.Is(streamReader.pendingError, io.EOF) {
					err = streamReader.pendingError
				}
				return
			}
			continue
		}
		break
	}

	destinationWriter := newBoundedRelayWriter(destination)
	var copied int64
	copied, err = bufio.CopyWithCounters(
		destinationWriter,
		newBoundedRelayReader(source),
		originSource,
		readCounters,
		writeCounters,
	)
	n += copied
	return
}

type boundedRelayReader struct {
	io.Reader
	pendingError error
}

func (r *boundedRelayReader) ReadBuffer(buffer *buf.Buffer) error {
	if r.pendingError != nil {
		return r.pendingError
	}
	n, err := r.Reader.Read(buffer.FreeBytes())
	buffer.Truncate(buffer.Len() + n)
	if n > 0 {
		r.pendingError = err
		return nil
	}
	return err
}

func (r *boundedRelayReader) UpstreamReader() any { return r.Reader }

func (r *boundedRelayReader) CreateReadWaiter() (N.ReadWaiter, bool) {
	return bufio.CreateReadWaiter(r.Reader)
}

type boundedRelaySyscallReader struct {
	*boundedRelayReader
	syscall.Conn
}

func newBoundedRelayReader(source io.Reader) N.ExtendedReader {
	reader := &boundedRelayReader{Reader: source}
	if conn, ok := source.(syscall.Conn); ok {
		return &boundedRelaySyscallReader{boundedRelayReader: reader, Conn: conn}
	}
	return reader
}

func newBoundedRelayWriter(destination io.Writer) *boundedRelayWriter {
	return &boundedRelayWriter{
		ExtendedWriter: bufio.NewExtendedWriter(destination),
		upstream:       destination,
	}
}

func countRelayBytes(counters []N.CountFunc, size int64) {
	for _, counter := range counters {
		counter(size)
	}
}

type boundedRelayWriter struct {
	N.ExtendedWriter
	upstream io.Writer
}

func (*boundedRelayWriter) WriterMTU() int {
	return lowMemoryRelayMTU
}

func (w *boundedRelayWriter) UpstreamWriter() any {
	return w.ExtendedWriter
}

func (w *boundedRelayWriter) SyscallConn() (syscall.RawConn, error) {
	if syscallConn, ok := w.upstream.(syscall.Conn); ok {
		return syscallConn.SyscallConn()
	}
	return nil, syscall.EINVAL
}
