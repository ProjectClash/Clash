package clash

import (
	"io"
	"net"
	"sync"
	"syscall"

	clashnet "github.com/ProjectClash/Clash/common/net"

	N "github.com/metacubex/sing/common/network"

	gotun "github.com/sagernet/sing-tun"
	goN "github.com/sagernet/sing/common/network"
)

func init() {
	clashnet.SetSplicer(spliceGoStack)
}

type spliceTracker interface {
	AttachSplice(splice io.Closer) bool
	DetachSplice()
}

func spliceRemoteWithReadAhead(caches []clashnet.SpliceCache, rightConn net.Conn) (right clashnet.SpliceEnd, ok, drained bool) {
	if right, ok = spliceRemote(rightConn); ok || len(caches) == 0 {
		return right, ok, false
	}
	if !drainSpliceCaches(caches, rightConn) {
		return clashnet.SpliceEnd{}, false, true
	}
	right, ok = spliceRemote(rightConn)
	return right, ok, true
}

func drainSpliceCaches(caches []clashnet.SpliceCache, to io.Writer) bool {
	for _, cache := range caches {
		for {
			buffer := cache.Reader.ReadCached()
			if buffer == nil {
				break
			}
			n, err := to.Write(buffer.Bytes())
			buffer.Release()
			for _, counter := range cache.ReadCounters {
				counter(int64(n))
			}
			if err != nil {
				return false
			}
		}
	}
	return true
}

func spliceGoStack(leftConn, rightConn net.Conn) bool {
	tracker, isTracker := rightConn.(spliceTracker)
	if !isTracker {
		return false
	}
	left, isGoStack := goStackSource(leftConn)
	if !isGoStack {
		return false
	}
	right, isBare, drained := spliceRemoteWithReadAhead(left.Cached, rightConn)
	if !isBare {
		return false
	}
	if !drained && !drainSpliceCaches(left.Cached, rightConn) {
		return false
	}
	if len(left.Cached) > 0 {
		if left, isGoStack = goStackSource(leftConn); !isGoStack || len(left.Cached) > 0 {
			return false
		}
	}
	owner := &goSpliceOwner{
		socket:  right.Layer.(*net.TCPConn),
		tracker: tracker,
		ended:   make(chan struct{}),
	}
	conn := left.Layer.(*goStreamConn).Conn.(*gotun.GoConn)
	reads, writes := goSpliceCounters(left, right)
	spliced := conn.Splice(owner, gotun.SpliceOptions{
		ReadCounters:  reads,
		WriteCounters: writes,
		OnClose:       func(error) { owner.end() },
	})
	if !spliced {
		return false
	}
	<-owner.ended
	return true
}

func spliceRemote(rightConn net.Conn) (clashnet.SpliceEnd, bool) {
	right, isBare := clashnet.UnwrapSpliceEnd(rightConn, isBareTCPConn)
	if !isBare || len(right.Cached) > 0 {
		return clashnet.SpliceEnd{}, false
	}
	for _, layer := range right.Counting {
		if _, isTracker := layer.(spliceTracker); isTracker && layer != any(rightConn) {
			return clashnet.SpliceEnd{}, false
		}
	}
	return right, true
}

func goStackSource(conn net.Conn) (clashnet.SpliceEnd, bool) {
	return clashnet.UnwrapSpliceEnd(conn, isGoStackConn)
}

func isGoStackConn(layer any) bool {
	stream, isStream := layer.(*goStreamConn)
	if !isStream {
		return false
	}
	_, isGoConn := stream.Conn.(*gotun.GoConn)
	return isGoConn
}

func isBareTCPConn(layer any) bool {
	_, isTCP := layer.(*net.TCPConn)
	return isTCP
}

type goSpliceOwner struct {
	socket  *net.TCPConn
	tracker spliceTracker
	ended   chan struct{}
	once    sync.Once
}

var _ gotun.SpliceSocket = (*goSpliceOwner)(nil)

func (o *goSpliceOwner) SyscallConn() (syscall.RawConn, error) {
	return o.socket.SyscallConn()
}

func (o *goSpliceOwner) Attach(splice io.Closer) (io.Closer, bool) {
	if !o.tracker.AttachSplice(splice) {
		return nil, false
	}
	return o.socket, true
}

func (o *goSpliceOwner) Detach() {
	o.tracker.DetachSplice()
}

func (o *goSpliceOwner) Close() error {
	o.end()
	return nil
}

func (o *goSpliceOwner) end() {
	o.once.Do(func() { close(o.ended) })
}

func goSpliceCounters(left, right clashnet.SpliceEnd) (reads, writes []goN.CountFunc) {
	return goCountFuncs(left.ReadCounters, right.WriteCounters), goCountFuncs(left.WriteCounters, right.ReadCounters)
}

func goCountFuncs(groups ...[]N.CountFunc) []goN.CountFunc {
	var converted []goN.CountFunc
	for _, counters := range groups {
		for _, counter := range counters {
			converted = append(converted, goN.CountFunc(counter))
		}
	}
	return converted
}
