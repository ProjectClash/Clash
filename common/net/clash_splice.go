package net

import (
	"net"
	"reflect"
	"sync/atomic"

	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/network"
)

type Splicer func(leftConn, rightConn net.Conn) bool

var relaySplicer atomic.Pointer[Splicer]

func SetSplicer(splicer Splicer) {
	if splicer == nil {
		relaySplicer.Store(nil)
		return
	}
	relaySplicer.Store(&splicer)
}

func trySplice(leftConn, rightConn net.Conn) bool {
	splicer := relaySplicer.Load()
	return splicer != nil && (*splicer)(leftConn, rightConn)
}

const spliceEndDepth = 32

type SpliceEnd struct {
	Layer         any
	Counting      []any
	ReadCounters  []network.CountFunc
	WriteCounters []network.CountFunc
	Cached        []SpliceCache
}

type SpliceCache struct {
	Reader       network.CachedReader
	ReadCounters []network.CountFunc
}

func UnwrapSpliceEnd(conn any, bottom func(any) bool) (SpliceEnd, bool) {
	var end SpliceEnd
	reader, readable := unwrapSpliceReader(conn, bottom, &end)
	if !readable {
		return SpliceEnd{}, false
	}
	writer, writable := unwrapSpliceWriter(conn, bottom, &end)
	if !writable || !sameLayer(reader, writer) {
		return SpliceEnd{}, false
	}
	end.Layer = reader
	return end, true
}

func unwrapSpliceReader(layer any, bottom func(any) bool, end *SpliceEnd) (any, bool) {
	for depth := 0; depth < spliceEndDepth; depth++ {
		if bottom(layer) {
			return layer, true
		}
		if counter, isCounter := layer.(network.ReadCounter); isCounter {
			upstream, counters := counter.UnwrapReader()
			end.Counting = append(end.Counting, layer)
			end.ReadCounters = append(end.ReadCounters, counters...)
			layer = upstream
			continue
		}
		replaceable, isReplaceable := layer.(network.ReaderWithUpstream)
		if !isReplaceable {
			return nil, false
		}
		if !replaceable.ReaderReplaceable() {
			cached, isCached := layer.(network.CachedReader)
			if !isCached {
				return nil, false
			}
			above := end.ReadCounters[:len(end.ReadCounters):len(end.ReadCounters)]
			end.Cached = append(end.Cached, SpliceCache{Reader: cached, ReadCounters: above})
		}
		if upstream, isSplit := layer.(network.WithUpstreamReader); isSplit {
			layer = upstream.UpstreamReader()
		} else if upstream, hasUpstream := layer.(common.WithUpstream); hasUpstream {
			layer = upstream.Upstream()
		} else {
			return nil, false
		}
	}
	return nil, false
}

func unwrapSpliceWriter(layer any, bottom func(any) bool, end *SpliceEnd) (any, bool) {
	for depth := 0; depth < spliceEndDepth; depth++ {
		if bottom(layer) {
			return layer, true
		}
		if counter, isCounter := layer.(network.WriteCounter); isCounter {
			upstream, counters := counter.UnwrapWriter()
			end.Counting = append(end.Counting, layer)
			end.WriteCounters = append(end.WriteCounters, counters...)
			layer = upstream
			continue
		}
		replaceable, isReplaceable := layer.(network.WriterWithUpstream)
		if !isReplaceable || !replaceable.WriterReplaceable() {
			return nil, false
		}
		if upstream, isSplit := layer.(network.WithUpstreamWriter); isSplit {
			layer = upstream.UpstreamWriter()
		} else if upstream, hasUpstream := layer.(common.WithUpstream); hasUpstream {
			layer = upstream.Upstream()
		} else {
			return nil, false
		}
	}
	return nil, false
}

func sameLayer(reader, writer any) (same bool) {
	if reader == nil || writer == nil || reflect.TypeOf(reader) != reflect.TypeOf(writer) ||
		!reflect.TypeOf(reader).Comparable() {
		return false
	}
	defer func() {
		if recover() != nil {
			same = false
		}
	}()
	return reader == writer
}
