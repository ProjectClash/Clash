package clash

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/outbound"
	clashnet "github.com/ProjectClash/Clash/common/net"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/tunnel/statistic"

	tun "github.com/metacubex/sing-tun"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	gotun "github.com/sagernet/sing-tun"
	gobuf "github.com/sagernet/sing/common/buf"
	goM "github.com/sagernet/sing/common/metadata"
	goN "github.com/sagernet/sing/common/network"
	"golang.org/x/sys/unix"
)

type fakeGoPacketConn struct {
	read        []byte
	from        goM.Socksaddr
	written     []byte
	writtenTo   goM.Socksaddr
	headroomGot int
}

func (c *fakeGoPacketConn) ReadPacket(buffer *gobuf.Buffer) (goM.Socksaddr, error) {
	if c.read == nil {
		return goM.Socksaddr{}, io.EOF
	}
	_, err := buffer.Write(c.read)
	c.read = nil
	return c.from, err
}

func (c *fakeGoPacketConn) WritePacket(buffer *gobuf.Buffer, destination goM.Socksaddr) error {
	defer buffer.Release()
	c.written = append([]byte(nil), buffer.Bytes()...)
	c.writtenTo = destination
	c.headroomGot = buffer.Start()
	return nil
}

func (c *fakeGoPacketConn) FrontHeadroom() int               { return 28 }
func (c *fakeGoPacketConn) Close() error                     { return nil }
func (c *fakeGoPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *fakeGoPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeGoPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeGoPacketConn) SetWriteDeadline(time.Time) error { return nil }

var _ goN.PacketConn = (*fakeGoPacketConn)(nil)

func TestAGoStackDatagramCrossesBetweenTheTwoBufferTypes(t *testing.T) {
	peer := netip.MustParseAddrPort("203.0.113.7:443")
	fake := &fakeGoPacketConn{read: []byte("question"), from: goM.SocksaddrFromNetIP(peer)}
	conn := &goPacketConn{PacketConn: fake}

	buffer := buf.NewPacket()
	defer buffer.Release()
	from, err := conn.ReadPacket(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer.Bytes()) != "question" || from.AddrPort() != peer {
		t.Fatalf("read %q from %v", buffer.Bytes(), from)
	}

	reply := buf.NewPacket()
	_, _ = reply.Write([]byte("answer"))
	if err := conn.WritePacket(reply, M.SocksaddrFromNetIP(peer)); err != nil {
		t.Fatal(err)
	}
	if string(fake.written) != "answer" || fake.writtenTo.AddrPort() != peer {
		t.Fatalf("wrote %q to %v", fake.written, fake.writtenTo)
	}
	if fake.headroomGot < 28 {
		t.Fatalf("the go stack's writer asked for 28 bytes of headroom and got %d", fake.headroomGot)
	}
}

type fakeStream struct {
	net.Conn
	data     chan []byte
	pending  []byte
	readable bool

	pendingHandshake bool
	failedWith       error
	readClosed       bool
	writeClosed      bool
}

func (s *fakeStream) WaitReadable() error {
	data, ok := <-s.data
	if !ok {
		return io.EOF
	}
	s.pending = data
	s.readable = true
	return nil
}

func (s *fakeStream) NeedHandshakeForRead() bool { return s.pendingHandshake }
func (s *fakeStream) HandshakeSuccess() error    { s.pendingHandshake = false; return nil }
func (s *fakeStream) HandshakeFailure(err error) error {
	s.failedWith = err
	return nil
}
func (s *fakeStream) CloseRead() error  { s.readClosed = true; return nil }
func (s *fakeStream) CloseWrite() error { s.writeClosed = true; return nil }

func (s *fakeStream) Read(p []byte) (int, error) {
	if !s.readable {
		return 0, errors.New("read before the connection was readable")
	}
	n := copy(p, s.pending)
	s.readable = false
	return n, nil
}

func TestTheReadWaiterTakesItsBlockOnlyOnceThereIsData(t *testing.T) {
	stream := &fakeStream{data: make(chan []byte, 1)}
	conn := &goStreamConn{Conn: stream, side: stream}
	var waiter N.ReadWaiter = conn
	waiter.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: 16, MTU: 16 * 1024})

	stream.data <- []byte("upload")
	buffer, err := waiter.WaitReadBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buffer.Release()
	if string(buffer.Bytes()) != "upload" {
		t.Fatalf("read %q", buffer.Bytes())
	}
	if buffer.Start() < 16 {
		t.Fatalf("the relay asked for 16 bytes of headroom and got %d", buffer.Start())
	}

	close(stream.data)
	if _, err := waiter.WaitReadBuffer(); err != io.EOF {
		t.Fatalf("a connection that ended read %v", err)
	}
}

func TestTheStreamWrapperPassesOnHandshakeHalfCloseAndAddresses(t *testing.T) {
	stream := &fakeStream{pendingHandshake: true}
	app := &net.TCPAddr{IP: net.IPv4(198, 18, 0, 1), Port: 54321}
	server := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 443}
	conn := &goStreamConn{Conn: stream, side: stream, local: server, remote: app}

	if !clashnet.HandshakePending(conn) {
		t.Fatal("a pending go stack handshake does not show as pending, so the tunnel's speculative read answers the app early")
	}
	if err := clashnet.ReportDeferredHandshake(conn, nil); err != nil || clashnet.HandshakePending(conn) {
		t.Fatalf("reporting the dial's success left the handshake pending (%v)", err)
	}
	refused := errors.New("connection refused")
	failing := &fakeStream{pendingHandshake: true}
	_ = clashnet.ReportDeferredHandshake(&goStreamConn{Conn: failing, side: failing}, refused)
	if failing.failedWith != refused {
		t.Fatalf("the dial's failure reached the go stack as %v", failing.failedWith)
	}

	closer, ok := any(conn).(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("the wrapper hides CloseWrite, so the relay closes the whole connection")
	}
	_ = closer.CloseWrite()
	if !stream.writeClosed || stream.readClosed {
		t.Fatalf("CloseWrite closed write %v, read %v", stream.writeClosed, stream.readClosed)
	}
	if conn.LocalAddr().String() != server.String() || conn.RemoteAddr().String() != app.String() {
		t.Fatalf("local %v remote %v, want local %v (the destination) and remote %v", conn.LocalAddr(), conn.RemoteAddr(), server, app)
	}
}

type fakeDoor struct {
	refuse error
	asked  []string
}

func (d *fakeDoor) PrepareConnection(network string, source M.Socksaddr, destination M.Socksaddr, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	d.asked = append(d.asked, network)
	return nil, d.refuse
}

func (d *fakeDoor) DeferHandshake(string, M.Socksaddr, M.Socksaddr) bool { return true }

func TestANewGoStackFlowAsksTheDoorFirst(t *testing.T) {
	source := netip.MustParseAddrPort("198.18.0.1:54321")
	destination := netip.MustParseAddrPort("[2001:db8::1]:443")
	open := &fakeDoor{}
	if verdict := (goStackHandler{door: open}).JudgeFlow(unix.IPPROTO_TCP, source, destination, nil); verdict.Action != gotun.ActionAccept {
		t.Fatalf("an open door refused the flow: %+v", verdict)
	}
	shut := &fakeDoor{refuse: errors.New("no IPv6 on this path")}
	for _, protocol := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
		if verdict := (goStackHandler{door: shut}).JudgeFlow(protocol, source, destination, nil); verdict.Action != gotun.ActionReject {
			t.Fatalf("protocol %d: a refusal at the door let the flow in: %+v", protocol, verdict)
		}
	}
	if strings.Join(shut.asked, ",") != "tcp,udp" {
		t.Fatalf("the door was asked %v", shut.asked)
	}
}

func TestTheRelayReadsAGoStackConnectionInWholeBlocks(t *testing.T) {
	t.Cleanup(func() { pressureShedLayerGauge.Store(0) })
	stream := &fakeStream{data: make(chan []byte, 1)}
	conn := &goStreamConn{Conn: stream, side: stream}
	offered := goStreamBlock / 4
	whole := goStreamBlock - 2*1024
	conn.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: 16, RearHeadroom: 8, MTU: offered})
	read := func(size int) *buf.Buffer {
		t.Helper()
		stream.data <- make([]byte, size)
		buffer, err := conn.WaitReadBuffer()
		if err != nil {
			t.Fatal(err)
		}
		return buffer
	}
	buffer := read(whole)
	if buffer.Len() != whole || buffer.Start() < 16 || buffer.Cap() < goStreamBlock {
		t.Fatalf("read %d bytes at %d of %d, want %d after the 16-byte headroom of a %d-byte block",
			buffer.Len(), buffer.Start(), buffer.Cap(), whole, goStreamBlock)
	}
	buffer.Release()

	pressureShedLayerGauge.Store(1)
	buffer = read(whole)
	if buffer.Len() != offered || buffer.Cap() >= goStreamBlock {
		t.Fatalf("shedding memory, read %d bytes of a %d-byte block, want the %d offered", buffer.Len(), buffer.Cap(), offered)
	}
	buffer.Release()
	pressureShedLayerGauge.Store(0)

	conn.InitializeReadWaiter(N.ReadWaitOptions{MTU: 64 * 1024})
	buffer = read(60 * 1024)
	if buffer.Len() != 60*1024 {
		t.Fatalf("a 64 KiB offer read %d bytes", buffer.Len())
	}
	buffer.Release()
}

func newMemoryGoStack(t *testing.T, failure func(error)) (*goStack, *gotun.MemoryTun) {
	t.Helper()
	device := gotun.NewMemoryTun(gotun.MemoryTunOptions{MTU: 1500, Outbound: func([]*gobuf.Buffer) {}})
	logger := &goStackLogger{ContextLogger: log.SingLogger}
	stack, err := gotun.NewGo(gotun.StackOptions{
		Context:    context.Background(),
		Tun:        device,
		TunOptions: gotun.Options{MTU: 1500, Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}},
		UDPTimeout: time.Minute,
		Handler:    goStackHandler{},
		Logger:     logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &goStack{stack: stack, tun: device, logger: logger, failure: failure}, device
}

type detachingDevice struct{ detached int }

func (d *detachingDevice) DetachFromRuntimePoller() error { d.detached++; return nil }

func TestAStartedGoStackTakesTheDeviceOffTheRuntimePoller(t *testing.T) {
	stack, _ := newMemoryGoStack(t, nil)
	listenerDevice := &detachingDevice{}
	stack.device = listenerDevice
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if listenerDevice.detached != 1 {
		t.Fatalf("a started go stack detached the device %d times", listenerDevice.detached)
	}
}

func TestAGoStackWhoseDeviceGoesAwayTellsItsOwner(t *testing.T) {
	failed := make(chan error, 1)
	stack, device := newMemoryGoStack(t, func(err error) { failed <- err })
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	_ = device.Close()
	select {
	case err := <-failed:
		if err == nil {
			t.Fatal("the failure carried no reason")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stack stopped reading its device and nobody was told")
	}
}

func TestClosingAGoStackIsNotAFailure(t *testing.T) {
	failed := make(chan error, 1)
	stack, _ := newMemoryGoStack(t, func(err error) { failed <- err })
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	if err := stack.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-failed:
		t.Fatalf("closing the stack reported a failure: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestTheGoStackLoggerKeepsTheLastError(t *testing.T) {
	logger := &goStackLogger{ContextLogger: log.SingLogger}
	logger.Error("go: engine read: ", errors.New("bad file descriptor"))
	if last := logger.lastError.Load(); last == nil || *last != "go: engine read: bad file descriptor" {
		t.Fatalf("last error %v", last)
	}
}

func TestTheSplicerDeclinesWhatItCannotSplice(t *testing.T) {
	left, leftPeer := net.Pipe()
	right, rightPeer := net.Pipe()
	defer left.Close()
	defer leftPeer.Close()
	defer right.Close()
	defer rightPeer.Close()
	if spliceGoStack(left, right) {
		t.Fatal("a pipe was spliced")
	}
	stream := &fakeStream{data: make(chan []byte, 1)}
	if spliceGoStack(&goStreamConn{Conn: stream, side: stream}, right) {
		t.Fatal("a go stream that is not the go stack's own connection was spliced")
	}
	if _, ok := goStackSource(clashnet.NewBufferedConn(left)); ok {
		t.Fatal("a buffered pipe passed for a go stack connection")
	}
	client, _ := tcpPairForSplice(t)
	tracker := statistic.NewTCPTracker(outbound.NewConn(client, outbound.NewDirect()), statistic.DefaultManager, &C.Metadata{}, nil, 0, 0, false)
	defer tracker.Close()
	if spliceGoStack(left, tracker) {
		t.Fatal("a pipe on the app's side was spliced onto a tracker")
	}
}

func TestTheRemoteSideIsSplicedOnlyUnderItsOwnTracker(t *testing.T) {
	client, _ := tcpPairForSplice(t)
	inner := statistic.NewTCPTracker(outbound.NewConn(client, outbound.NewDirect()), statistic.DefaultManager, &C.Metadata{}, nil, 0, 0, false)
	defer inner.Close()
	if right, ok := spliceRemote(inner); !ok || right.Layer != any(client) {
		t.Fatalf("a tracker over a bare socket was not spliceable (%v)", ok)
	}
	outer := statistic.NewTCPTracker(outbound.NewConn(inner, outbound.NewDirect()), statistic.DefaultManager, &C.Metadata{}, nil, 0, 0, false)
	defer outer.Close()
	if _, ok := clashnet.UnwrapSpliceEnd(outer, isBareTCPConn); !ok {
		t.Fatal("the nested chain does not reach the socket; the test proves nothing")
	}
	if _, ok := spliceRemote(outer); ok {
		t.Fatal("a chain with a second tracker under its own was spliceable")
	}
}

func TestTheSpliceCountersCountEachDirection(t *testing.T) {
	client, _ := tcpPairForSplice(t)
	tracker := statistic.NewTCPTracker(outbound.NewConn(client, outbound.NewDirect()), statistic.DefaultManager, &C.Metadata{}, nil, 0, 0, false)
	defer tracker.Close()
	right, ok := clashnet.UnwrapSpliceEnd(tracker, isBareTCPConn)
	if !ok || right.Layer != any(client) {
		t.Fatalf("the tracker's socket was not found under it (%v)", ok)
	}
	var leftRead, leftWritten int64
	left := clashnet.SpliceEnd{
		ReadCounters:  []N.CountFunc{func(n int64) { leftRead += n }},
		WriteCounters: []N.CountFunc{func(n int64) { leftWritten += n }},
	}
	reads, writes := goSpliceCounters(left, right)
	for _, count := range reads {
		count(3)
	}
	for _, count := range writes {
		count(5)
	}
	info := tracker.Info()
	if leftRead != 3 || leftWritten != 5 || info.UploadTotal.Load() != 3 || info.DownloadTotal.Load() != 5 {
		t.Fatalf("app side read %d written %d, tracker up %d down %d; want 3 5 3 5",
			leftRead, leftWritten, info.UploadTotal.Load(), info.DownloadTotal.Load())
	}
}

func TestEndingASpliceOnlyWakesTheRelay(t *testing.T) {
	client, _ := tcpPairForSplice(t)
	tracker := &recordingTracker{}
	owner := &goSpliceOwner{socket: client, tracker: tracker, ended: make(chan struct{})}
	if original, attached := owner.Attach(io.NopCloser(nil)); !attached || original != io.Closer(client) {
		t.Fatalf("Attach = %v, %v; want the bare socket", original, attached)
	}
	_ = owner.Close()
	owner.end()
	_ = owner.Close()
	select {
	case <-owner.ended:
	default:
		t.Fatal("ending the splice did not wake the relay")
	}
	owner.Detach()
	if tracker.attached != 1 || tracker.detached != 1 {
		t.Fatalf("attached %d, detached %d", tracker.attached, tracker.detached)
	}
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatalf("ending the splice closed the socket: %v", err)
	}
	tracker.refuse = true
	if _, attached := owner.Attach(io.NopCloser(nil)); attached {
		t.Fatal("a splice the tracker refused was attached")
	}
}

type recordingTracker struct {
	attached, detached int
	refuse             bool
}

func (r *recordingTracker) AttachSplice(io.Closer) bool {
	if r.refuse {
		return false
	}
	r.attached++
	return true
}

func (r *recordingTracker) DetachSplice() { r.detached++ }

func tcpPairForSplice(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client.(*net.TCPConn), server.(*net.TCPConn)
}
