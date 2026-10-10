package mipstack

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

var congestionAPITestName atomic.Uint64

func nextCongestionAPITestName() string {
	return fmt.Sprintf("mipstack-test-%d", congestionAPITestName.Add(1))
}

type congestionAPIRecorder struct {
	events        []CongestionEventType
	rateSample    CongestionRateSample
	ackNumber     uint32
	recovery      []CongestionRecoveryStage
	recoveries    []CongestionRecovery
	phases        []CongestionPhase
	fixedRate     uint64
	windowGrowth  uint32
	undoWindow    uint32
	undoThreshold uint32
}

type congestionAPILifecycle struct {
	events      []CongestionEventType
	maximumRate uint64
	previousMSS int
	currentMSS  int
}

type congestionAPILossRecorder struct {
	events        []CongestionEventType
	lostState     uint64
	lostBytes     int
	totalLost     uint64
	tailRecovered bool
	nextState     uint64
}

type congestionFactoryProbe struct {
	mu          sync.Mutex
	contexts    []CongestionControlContext
	controllers []*congestionFactoryController
}

type congestionFactoryController struct {
	mu     sync.Mutex
	events []CongestionEventType
}

func (p *congestionFactoryProbe) New(context CongestionControlContext) CongestionController {
	controller := &congestionFactoryController{}
	p.mu.Lock()
	p.contexts = append(p.contexts, context)
	p.controllers = append(p.controllers, controller)
	p.mu.Unlock()
	return controller
}

func (p *congestionFactoryProbe) snapshot() ([]CongestionControlContext, []*congestionFactoryController) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]CongestionControlContext(nil), p.contexts...), append([]*congestionFactoryController(nil), p.controllers...)
}

func (c *congestionFactoryController) HandleCongestionEvent(event *CongestionEvent) {
	c.mu.Lock()
	c.events = append(c.events, event.Type)
	c.mu.Unlock()
	if event.Type == CongestionEventRelease {
		event.State.CongestionWindow = 1
		event.State.SlowStartThreshold = 1
		event.State.UsePacingRate = true
		event.State.PacingRate = 1
	}
}

func (c *congestionFactoryController) eventCount(eventType CongestionEventType) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	count := 0
	for _, current := range c.events {
		if current == eventType {
			count++
		}
	}
	return count
}

func (c *congestionAPILossRecorder) HandleCongestionEvent(event *CongestionEvent) {
	c.events = append(c.events, event.Type)
	switch event.Type {
	case CongestionEventPacketSent, CongestionEventPacketRetransmitted:
		c.nextState++
		event.PacketState = c.nextState
	case CongestionEventPacketLost:
		c.lostState = event.PacketState
		c.lostBytes = event.PacketBytes
		c.totalLost = event.State.LostBytes
	case CongestionEventTailLossProbeRecovered:
		c.tailRecovered = true
	}
}

func (c *congestionAPILifecycle) HandleCongestionEvent(event *CongestionEvent) {
	c.events = append(c.events, event.Type)
	switch event.Type {
	case CongestionEventInitialize:
		c.maximumRate = event.State.MaximumPacingRate
		event.State.CongestionWindow = 12_000
		event.State.SlowStartThreshold = 24_000
	case CongestionEventMTUChanged:
		c.previousMSS = event.PreviousMaximumSegmentSize
		c.currentMSS = event.State.MaximumSegmentSize
	}
}

func (c *congestionAPIRecorder) HandleCongestionEvent(event *CongestionEvent) {
	c.events = append(c.events, event.Type)
	switch event.Type {
	case CongestionEventACK:
		if event.RateSample != nil {
			c.rateSample = *event.RateSample
		}
		c.ackNumber = event.AcknowledgementNumber
		event.State.CongestionWindow += c.windowGrowth
		if c.fixedRate != 0 {
			event.State.UsePacingRate = true
			event.State.PacingRate = c.fixedRate
		}
	case CongestionEventRecovery:
		if event.Recovery.Stage == CongestionRecoverySelectFlight {
			event.Recovery.Flight = event.Recovery.OrdinaryFlight
		}
		if event.Recovery.Stage == CongestionRecoveryUndo && c.undoWindow != 0 {
			event.State.CongestionWindow = c.undoWindow
			event.State.SlowStartThreshold = c.undoThreshold
		}
		c.recovery = append(c.recovery, event.Recovery.Stage)
		c.recoveries = append(c.recoveries, event.Recovery)
	case CongestionEventStateChanged:
		c.phases = append(c.phases, event.State.Phase)
	}
}

func TestCongestionControlRegistry(t *testing.T) {
	controls := AvailableCongestionControls()
	if !sort.SliceIsSorted(controls, func(i, j int) bool { return controls[i] < controls[j] }) {
		t.Fatalf("available congestion controls are not sorted: %v", controls)
	}
	for _, builtin := range []string{CongestionControlBBR, CongestionControlBBR3, CongestionControlCUBIC, CongestionControlReno} {
		index := sort.Search(len(controls), func(index int) bool { return controls[index] >= builtin })
		if index == len(controls) || controls[index] != builtin {
			t.Fatalf("built-in congestion control %q is unavailable: %v", builtin, controls)
		}
	}

	if _, err := NewCongestionControlFactory(CongestionControlDefinition{New: func(CongestionControlContext) CongestionController { return &congestionAPIRecorder{} }}); err == nil {
		t.Fatal("empty congestion-control name was accepted")
	}
	if _, err := NewCongestionControlFactory(CongestionControlDefinition{Name: nextCongestionAPITestName()}); err == nil {
		t.Fatal("nil congestion-control factory was accepted")
	}
	if _, err := NewCongestionControlFactory(CongestionControlDefinition{
		Name:     nextCongestionAPITestName(),
		New:      func(CongestionControlContext) CongestionController { return &congestionAPIRecorder{} },
		Features: CongestionControlFeatures(1 << 31),
	}); err == nil {
		t.Fatal("unknown congestion-control feature was accepted")
	}
	if _, err := NewCongestionControlFactory(CongestionControlDefinition{
		Name:     nextCongestionAPITestName(),
		New:      func(CongestionControlContext) CongestionController { return &congestionAPIRecorder{} },
		Features: CongestionControlFeatureCustomPacing,
	}); err == nil {
		t.Fatal("custom pacing without transmission events was accepted")
	}
	if _, err := NewCongestionControlFactory(CongestionControlDefinition{
		Name:     nextCongestionAPITestName(),
		New:      func(CongestionControlContext) CongestionController { return &congestionAPIRecorder{} },
		Features: CongestionControlFeatureLossEvents,
	}); err == nil {
		t.Fatal("loss events without transmission events were accepted")
	}
	if _, err := NewCongestionControlFactory(CongestionControlDefinition{
		Name:     nextCongestionAPITestName(),
		New:      func(CongestionControlContext) CongestionController { return &congestionAPIRecorder{} },
		Features: CongestionControlFeatureCustomWindowValidation,
	}); err == nil {
		t.Fatal("custom window validation without transmission events was accepted")
	}
	if err := RegisterCongestionControl(nil); err == nil {
		t.Fatal("nil congestion-control factory was registered")
	}

	name := nextCongestionAPITestName()
	factory, err := NewCongestionControlFactory(CongestionControlDefinition{
		Name: name,
		New:  func(CongestionControlContext) CongestionController { return &congestionAPIRecorder{} },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = RegisterCongestionControl(factory); err != nil {
		t.Fatal(err)
	}
	if err = RegisterCongestionControl(factory); err == nil {
		t.Fatal("duplicate congestion-control registration was accepted")
	}
	if _, err := normalizeTCPSocketDefaults(TCPSocketDefaults{CongestionControl: name}); err != nil {
		t.Fatalf("registered congestion control was rejected by socket defaults: %v", err)
	}
}

func TestLocalCongestionControlFactoryValidation(t *testing.T) {
	name := nextCongestionAPITestName()
	probe := &congestionFactoryProbe{}
	factory, err := NewCongestionControlFactory(CongestionControlDefinition{
		Name: name, New: probe.New, Features: CongestionControlFeatureDeliveryRate,
		SendBufferMultiplier: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if factory.Name() != name {
		t.Fatalf("local factory name = %q, want %q", factory.Name(), name)
	}
	definition := CongestionControlDefinition{Name: "changed", New: func(CongestionControlContext) CongestionController { return nil }}
	copied, err := NewCongestionControlFactory(definition)
	if err != nil {
		t.Fatal(err)
	}
	definition.Name = "changed-again"
	definition.New = nil
	if copied.Name() != "changed" || !copied.valid() {
		t.Fatal("factory changed with its caller-owned definition")
	}
	for _, available := range AvailableCongestionControls() {
		if available == name {
			t.Fatalf("local factory %q appeared in the process registry", name)
		}
	}
	defaults, err := normalizeTCPSocketDefaults(TCPSocketDefaults{CongestionControlFactory: factory})
	if err != nil {
		t.Fatal(err)
	}
	if defaults.CongestionControl != "" || defaults.CongestionControlFactory != factory {
		t.Fatalf("normalized local factory = name %q factory %p", defaults.CongestionControl, defaults.CongestionControlFactory)
	}
	if repeated, repeatErr := normalizeTCPSocketDefaults(defaults); repeatErr != nil || repeated.CongestionControlFactory != factory {
		t.Fatalf("re-normalized local factory = %p, %v", repeated.CongestionControlFactory, repeatErr)
	}
	registered, err := normalizeTCPSocketDefaults(TCPSocketDefaults{CongestionControl: CongestionControlReno})
	if err != nil {
		t.Fatal(err)
	}
	if registered.CongestionControl != "" || registered.CongestionControlFactory.Name() != CongestionControlReno {
		t.Fatalf("normalized registered factory = name %q factory %q", registered.CongestionControl, registered.CongestionControlFactory.Name())
	}
	if repeated, repeatErr := normalizeTCPSocketDefaults(registered); repeatErr != nil || repeated.CongestionControl != "" || repeated.CongestionControlFactory != registered.CongestionControlFactory {
		t.Fatalf("re-normalized registered factory = name %q factory %p, %v", repeated.CongestionControl, repeated.CongestionControlFactory, repeatErr)
	}
	if _, err = normalizeTCPSocketDefaults(TCPSocketDefaults{
		CongestionControl: CongestionControlCUBIC, CongestionControlFactory: factory,
	}); err == nil {
		t.Fatal("simultaneous congestion-control name and local factory were accepted")
	}
	if _, err = NewCongestionControlFactory(CongestionControlDefinition{New: probe.New}); err == nil {
		t.Fatal("empty local factory name was accepted")
	}
	if _, err = NewCongestionControlFactory(CongestionControlDefinition{Name: name}); err == nil {
		t.Fatal("local factory without New was accepted")
	}
}

func TestLocalCongestionControlFactoryConnectionContexts(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.182")
	serverAddress := netip.MustParseAddr("192.0.2.183")
	probe := &congestionFactoryProbe{}
	factory, err := NewCongestionControlFactory(CongestionControlDefinition{Name: nextCongestionAPITestName(), New: probe.New})
	if err != nil {
		t.Fatal(err)
	}
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	for _, configured := range []struct {
		stack   *Stack
		address netip.Addr
	}{{client, clientAddress}, {server, serverAddress}} {
		if err = configured.stack.UpdateConfig(Config{
			LocalAddresses: []netip.Prefix{netip.PrefixFrom(configured.address, 32)}, MTU: 1400,
			TCP: TCPSocketDefaults{CongestionControlFactory: factory},
		}); err != nil {
			t.Fatal(err)
		}
	}
	newStackBridge(t, client, server)
	listener, err := server.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			acceptErrors <- acceptErr
			return
		}
		accepted <- connection
	}()
	clientConnection, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, listener.(*TCPListener).local)
	if err != nil {
		t.Fatal(err)
	}
	var serverConnection net.Conn
	select {
	case serverConnection = <-accepted:
	case err = <-acceptErrors:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("timed out accepting local-factory TCP connection")
	}
	waitFor(t, time.Second, func() bool {
		contexts, _ := probe.snapshot()
		return len(contexts) == 2
	})
	contexts, controllers := probe.snapshot()
	if len(controllers) != 2 {
		t.Fatalf("factory created %d controllers, want 2", len(controllers))
	}
	if controllers[0] == controllers[1] {
		t.Fatalf("factory reused controller %p", controllers[0])
	}
	for _, context := range contexts {
		switch {
		case context.LocalAddress.Addr() == clientAddress:
			if context.RemoteAddress != listener.(*TCPListener).local || context.Passive || context.Forwarded {
				t.Fatalf("active factory context = %+v", context)
			}
		case context.LocalAddress == listener.(*TCPListener).local:
			if context.RemoteAddress != clientConnection.(*TCPConn).key.local || !context.Passive || context.Forwarded {
				t.Fatalf("passive factory context = %+v", context)
			}
		default:
			t.Fatalf("unexpected factory context = %+v", context)
		}
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if err = server.Close(); err != nil {
		t.Fatal(err)
	}
	for _, connection := range []*TCPConn{clientConnection.(*TCPConn), serverConnection.(*TCPConn)} {
		select {
		case <-connection.done:
		case <-time.After(time.Second):
			t.Fatal("TCP actor did not release its local congestion controller")
		}
	}
	for _, controller := range controllers {
		if controller.eventCount(CongestionEventInitialize) != 1 || controller.eventCount(CongestionEventRelease) != 1 {
			t.Fatalf("controller initialization/release = %d/%d", controller.eventCount(CongestionEventInitialize), controller.eventCount(CongestionEventRelease))
		}
	}
}

func TestLocalCongestionControlFactorySwitchAndOverride(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.184")
	remote := netip.MustParseAddr("192.0.2.185")
	link, stack := newTestStack(t, local, remote)
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	name := nextCongestionAPITestName()
	newFactory := func(probe *congestionFactoryProbe) *CongestionControlFactory {
		factory, err := NewCongestionControlFactory(CongestionControlDefinition{Name: name, New: probe.New})
		if err != nil {
			t.Fatal(err)
		}
		return factory
	}
	firstProbe, secondProbe, explicitProbe := new(congestionFactoryProbe), new(congestionFactoryProbe), new(congestionFactoryProbe)
	first, second, explicit := newFactory(firstProbe), newFactory(secondProbe), newFactory(explicitProbe)
	if err := stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400,
		TCP: TCPSocketDefaults{CongestionControlFactory: first},
	}); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 443))
	if err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	waitFor(t, time.Second, func() bool { _, controllers := firstProbe.snapshot(); return len(controllers) == 1 })
	if err = stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400,
		TCP: TCPSocketDefaults{CongestionControlFactory: second},
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		_, firstControllers := firstProbe.snapshot()
		_, secondControllers := secondProbe.snapshot()
		return len(secondControllers) == 1 && firstControllers[0].eventCount(CongestionEventRelease) == 1
	})
	if info := tcpConnection.Info(); info.CongestionControl != name || info.CongestionWindow <= 1 || info.SlowStartThreshold <= 1 {
		t.Fatalf("same-name factory switch diagnostics = %+v", info)
	}
	if err = tcpConnection.SetCongestionControlFactory(nil); err == nil {
		t.Fatal("nil per-connection congestion factory was accepted")
	}
	if err = tcpConnection.SetCongestionControlFactory(explicit); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		_, secondControllers := secondProbe.snapshot()
		_, explicitControllers := explicitProbe.snapshot()
		return len(explicitControllers) == 1 && secondControllers[0].eventCount(CongestionEventRelease) == 1
	})
	if err = stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400,
		TCP: TCPSocketDefaults{CongestionControlFactory: first},
	}); err != nil {
		t.Fatal(err)
	}
	if options := tcpConnection.socketOptions(); options.congestionFactory != explicit {
		t.Fatalf("explicit local factory was replaced by stack default: %p", options.congestionFactory)
	}
	if err = stack.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-tcpConnection.done:
	case <-time.After(time.Second):
		t.Fatal("TCP actor did not terminate after local factory test")
	}
	_, explicitControllers := explicitProbe.snapshot()
	if explicitControllers[0].eventCount(CongestionEventInitialize) != 1 || explicitControllers[0].eventCount(CongestionEventRelease) != 1 {
		t.Fatalf("explicit controller initialization/release = %d/%d", explicitControllers[0].eventCount(CongestionEventInitialize), explicitControllers[0].eventCount(CongestionEventRelease))
	}
}

func TestLocalCongestionControlFactoryConcurrentSwitchAndClose(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.188")
	remote := netip.MustParseAddr("192.0.2.189")
	link, stack := newTestStack(t, local, remote)
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	probes := []*congestionFactoryProbe{{}, {}, {}}
	factories := make([]*CongestionControlFactory, len(probes))
	for index, probe := range probes {
		factory, err := NewCongestionControlFactory(CongestionControlDefinition{Name: nextCongestionAPITestName(), New: probe.New})
		if err != nil {
			t.Fatal(err)
		}
		factories[index] = factory
	}
	if err := stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400,
		TCP: TCPSocketDefaults{CongestionControlFactory: factories[0]},
	}); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 443))
	if err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	waitFor(t, time.Second, func() bool { _, controllers := probes[0].snapshot(); return len(controllers) == 1 })
	start := make(chan struct{})
	var setters sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		setters.Add(1)
		go func(worker int) {
			defer setters.Done()
			<-start
			for update := 0; update < 64; update++ {
				_ = tcpConnection.SetCongestionControlFactory(factories[(worker+update)%len(factories)])
			}
		}(worker)
	}
	close(start)
	if err = stack.Close(); err != nil {
		t.Fatal(err)
	}
	setters.Wait()
	select {
	case <-tcpConnection.done:
	case <-time.After(time.Second):
		t.Fatal("TCP actor did not terminate after concurrent factory switches")
	}
	for _, probe := range probes {
		_, controllers := probe.snapshot()
		for _, controller := range controllers {
			if controller.eventCount(CongestionEventInitialize) != 1 || controller.eventCount(CongestionEventRelease) != 1 {
				t.Fatalf("concurrent controller initialization/release = %d/%d", controller.eventCount(CongestionEventInitialize), controller.eventCount(CongestionEventRelease))
			}
		}
	}
}

func TestLocalCongestionControlFactoryForwardedContext(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.186")
	serverAddress := netip.MustParseAddr("192.0.2.187")
	intercepted := netip.MustParseAddrPort("198.51.100.187:8080")
	client := newForwarderTestStack(t, clientAddress, false)
	server := newForwarderTestStack(t, serverAddress, true)
	probe := &congestionFactoryProbe{}
	factory, err := NewCongestionControlFactory(CongestionControlDefinition{Name: nextCongestionAPITestName(), New: probe.New})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(serverAddress, 32)},
		Promiscuous:    true, MTU: 1400,
		TCP: TCPSocketDefaults{CongestionControlFactory: factory},
	}); err != nil {
		t.Fatal(err)
	}
	newStackBridge(t, client, server)
	accepted := make(chan *TCPConn, 1)
	acceptErrors := make(chan error, 1)
	forwarder, err := NewTCPForwarder(server, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
		connection, acceptErr := request.Accept(context.Background())
		if acceptErr != nil {
			acceptErrors <- acceptErr
			return
		}
		accepted <- connection
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	clientConnection, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, intercepted)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()
	var serverConnection *TCPConn
	select {
	case serverConnection = <-accepted:
		defer serverConnection.Close()
	case err = <-acceptErrors:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("timed out accepting forwarded local-factory connection")
	}
	waitFor(t, time.Second, func() bool { contexts, _ := probe.snapshot(); return len(contexts) == 1 })
	contexts, _ := probe.snapshot()
	context := contexts[0]
	if context.LocalAddress != intercepted || context.RemoteAddress != clientConnection.(*TCPConn).key.local || !context.Passive || !context.Forwarded {
		t.Fatalf("forwarded congestion factory context = %+v", context)
	}
}

func TestCongestionPacketStateFollowsTransmissionGeneration(t *testing.T) {
	recorder := &congestionAPILossRecorder{}
	controller := newTCPCongestionControllerFromDefinition(CongestionControlDefinition{
		Name: "loss-events",
		New:  func(CongestionControlContext) CongestionController { return recorder },
		Features: CongestionControlFeatureTransmissionEvents |
			CongestionControlFeatureLossEvents,
	})
	now := time.Unix(100, 0)
	controller.initialize(now, 10*time.Millisecond, 20*time.Millisecond, 20_000, 40_000, 1000, 1)
	_, _ = controller.onDataSend(1000, 1000, now, 2, 0, 20_000, 0, 20*time.Millisecond, 40_000)
	segment := sentTCPSegment{sequence: 1, end: 1001, congestionPacketState: controller.transmissionState()}
	if segment.congestionPacketState != 1 {
		t.Fatalf("original packet state = %d, want 1", segment.congestionPacketState)
	}
	controller.notePacketLoss(&segment, 1000, false, now.Add(time.Millisecond), 20_000, 40_000, 1000, 1000, 20*time.Millisecond)
	if recorder.lostState != 1 || recorder.lostBytes != 1000 || recorder.totalLost != 1000 {
		t.Fatalf("first loss = state %d bytes %d total %d", recorder.lostState, recorder.lostBytes, recorder.totalLost)
	}
	segment.congestionPacketState = 0
	segment.delivery = controller.onRetransmit(1000, 1000, now.Add(time.Millisecond), 3, 20_000, 1000, 1000, 20*time.Millisecond, 40_000)
	segment.congestionPacketState = controller.transmissionState()
	if segment.congestionPacketState != 2 {
		t.Fatalf("retransmission packet state = %d, want 2", segment.congestionPacketState)
	}
	controller.notePacketLoss(&segment, 1000, true, now.Add(2*time.Millisecond), 20_000, 40_000, 1000, 1000, 20*time.Millisecond)
	if recorder.lostState != 2 || recorder.totalLost != 2000 {
		t.Fatalf("retransmission loss = state %d total %d", recorder.lostState, recorder.totalLost)
	}
	controller.onTailLossProbeRecovered(now.Add(3*time.Millisecond), 1000, segment.congestionPacketState, 20_000, 40_000, 1000, 1000, 20*time.Millisecond)
	if !recorder.tailRecovered {
		t.Fatal("tail-loss-probe recovery event was not delivered")
	}
}

func TestSentTCPSegmentLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("64-bit layout assertion")
	}
	if size := unsafe.Sizeof(packetQueueTicket{}); size != 16 {
		t.Fatalf("packet queue ticket size = %d, want 16", size)
	}
	if size := unsafe.Sizeof(sentTCPSegment{}); size != 64 {
		t.Fatalf("sent TCP segment size = %d, want 64", size)
	}
	segment := sentTCPSegment{}
	if offset := unsafe.Offsetof(segment.state); offset != 12 {
		t.Fatalf("range state offset = %d, want 12", offset)
	}
	if offset := unsafe.Offsetof(segment.firstSent); offset != 16 {
		t.Fatalf("first-send timestamp offset = %d, want 16", offset)
	}
	if offset := unsafe.Offsetof(segment.hostQueue); offset != 24 {
		t.Fatalf("host queue ticket offset = %d, want 24", offset)
	}
	if offset := unsafe.Offsetof(segment.delivery); offset != 48 {
		t.Fatalf("delivery snapshot offset = %d, want 48", offset)
	}
	if offset := unsafe.Offsetof(segment.congestionPacketState); offset != 40 {
		t.Fatalf("congestion packet state offset = %d, want 40", offset)
	}
	if offset := unsafe.Offsetof(segment.transmissionOrder); offset != 60 {
		t.Fatalf("transmission order offset = %d, want 60", offset)
	}
}

func TestCongestionControlRegistryConcurrentDuplicate(t *testing.T) {
	name := nextCongestionAPITestName()
	factory, err := NewCongestionControlFactory(CongestionControlDefinition{
		Name: name,
		New:  func(CongestionControlContext) CongestionController { return &congestionAPIRecorder{} },
	})
	if err != nil {
		t.Fatal(err)
	}
	const contenders = 32
	var successes atomic.Int32
	var wait sync.WaitGroup
	wait.Add(contenders)
	for contender := 0; contender < contenders; contender++ {
		go func() {
			defer wait.Done()
			if RegisterCongestionControl(factory) == nil {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("concurrent registration successes = %d, want 1", successes.Load())
	}
}

func TestCongestionControlFactoryCreatesIndependentControllers(t *testing.T) {
	name := nextCongestionAPITestName()
	definition := CongestionControlDefinition{
		Name:                 name,
		New:                  func(CongestionControlContext) CongestionController { return &congestionAPIRecorder{windowGrowth: 7} },
		Features:             CongestionControlFeatureDeliveryRate,
		SendBufferMultiplier: 5,
	}
	factory, err := NewCongestionControlFactory(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err = RegisterCongestionControl(factory); err != nil {
		t.Fatal(err)
	}
	first := newTCPCongestionController(name)
	second := newTCPCongestionController(name)
	if first.algorithm == second.algorithm {
		t.Fatal("factory reused one controller across connections")
	}
	if !first.usesDeliveryRate() || first.customPacing() || first.sendBufferMultiplier() != 5 {
		t.Fatalf("definition was not preserved: features %#x multiplier %d", first.features, first.sendBufferMultiplier())
	}

	first.initialize(time.Unix(100, 0), 10*time.Millisecond, 20*time.Millisecond, 10_000, 20_000, 1000, 1)
	sample := tcpDeliveryRateSample{
		priorDelivered: 2, priorDeliveredTotal: 2, delivered: 1000, acked: 1000, losses: 25,
		priorInFlight: 5000, inFlight: 4000, interval: 10 * time.Millisecond,
		rtt: 9 * time.Millisecond, smoothedRTT: 20 * time.Millisecond,
		ackTime: time.Unix(100, 0), valid: true,
	}
	window, _ := first.onDeliveryRateSample(10_000, 20_000, 1000, 12345, &sample)
	recorder := first.algorithm.(*congestionAPIRecorder)
	if window != 10_007 || len(recorder.events) != 2 || recorder.events[0] != CongestionEventInitialize || recorder.events[1] != CongestionEventACK {
		t.Fatalf("custom controller events/window = %v/%d", recorder.events, window)
	}
	if sample := &recorder.rateSample; !sample.Valid() || sample.DeliveredBytes() != 1000 || sample.LostBytes() != 25 || sample.PriorBytesInFlight() != 5000 || sample.BytesInFlight() != 4000 {
		t.Fatalf("public delivery-rate sample = %+v", sample)
	}
	if recorder.ackNumber != 12345 {
		t.Fatalf("public ACK number = %d, want 12345", recorder.ackNumber)
	}
}

func TestRegisteredCongestionControllerRunsOnTCPConnection(t *testing.T) {
	name := nextCongestionAPITestName()
	factory, err := NewCongestionControlFactory(CongestionControlDefinition{
		Name:                 name,
		New:                  func(CongestionControlContext) CongestionController { return &congestionAPIRecorder{windowGrowth: 1000} },
		SendBufferMultiplier: 128,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = RegisterCongestionControl(factory); err != nil {
		t.Fatal(err)
	}
	local := netip.MustParseAddr("192.0.2.180")
	remote := netip.MustParseAddr("192.0.2.181")
	link, stack := newTestStack(t, local, remote)
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	if err := stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		TCP: TCPSocketDefaults{
			CongestionControl: name,
			SendBuffer:        4096,
			MaximumSendBuffer: 1024 * 1024,
		},
	}); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 8180))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	writeAndReadTCPEcho(t, connection, make([]byte, 1000))
	if got := connection.(*TCPConn).Info().CongestionControl; got != name {
		t.Fatalf("active congestion control = %q, want %q", got, name)
	}
	if capacity := connection.(*TCPConn).Info().SendBufferCapacity; capacity <= 4096 {
		t.Fatalf("controller send-buffer multiplier did not grow capacity: %d", capacity)
	}
}

func TestCongestionControllerIgnoresUnknownEvents(t *testing.T) {
	for _, name := range []string{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		controller := newTCPCongestionController(name)
		before := controller.algorithm
		state := CongestionState{CongestionWindow: 12345, DeliveredBytes: 6789}
		event := CongestionEvent{Type: CongestionEventType(255), State: &state}
		controller.algorithm.HandleCongestionEvent(&event)
		if controller.algorithm != before || event.State.CongestionWindow != 12345 {
			t.Fatalf("%s mutated an unknown event", name)
		}
	}
}

func TestCongestionControllerCanUseCommonPacerAtExplicitRate(t *testing.T) {
	const (
		mss  = 1000
		rate = 100_000
	)
	recorder := &congestionAPIRecorder{fixedRate: rate}
	controller := newTCPCongestionControllerFromDefinition(CongestionControlDefinition{
		Name: "fixed-rate",
		New:  func(CongestionControlContext) CongestionController { return recorder },
	})
	start := time.Unix(100, 0)
	window := controller.onACK(10*mss, mss, mss, start, 20*time.Millisecond, 10*time.Millisecond, 10*mss, false)
	controller.pacingSegments = tcpPacingInitialBurst - 1
	controller.pacingNext = start
	_, _ = controller.onDataSend(mss, mss, start, 1, 10*mss, window, 10*mss, 20*time.Millisecond, 10*mss)
	if interval := controller.pacingNext.Sub(start); interval != 10*time.Millisecond {
		t.Fatalf("explicit common-pacer interval = %v, want 10ms", interval)
	}
}

func TestCongestionControllerLifecycleAndMutableInitialState(t *testing.T) {
	lifecycle := &congestionAPILifecycle{}
	controller := newTCPCongestionControllerFromDefinition(CongestionControlDefinition{
		Name:     "lifecycle",
		New:      func(CongestionControlContext) CongestionController { return lifecycle },
		Features: CongestionControlFeatureCustomPacing | CongestionControlFeatureTransmissionEvents,
	})
	if !controller.setMaximumPacingRate(500_000) {
		t.Fatal("initial pacing policy was not recorded")
	}
	if len(lifecycle.events) != 0 {
		t.Fatalf("controller received %v before initialization", lifecycle.events)
	}
	window, threshold := controller.initialize(time.Unix(100, 0), 10*time.Millisecond, 20*time.Millisecond, 10_000, 20_000, 1000, 1)
	if window != 12_000 || threshold != 24_000 || lifecycle.maximumRate != 500_000 {
		t.Fatalf("initialized state = window %d threshold %d max rate %d", window, threshold, lifecycle.maximumRate)
	}
	controller.onMTUChange(window, threshold, 1200)
	if lifecycle.previousMSS != 1000 || lifecycle.currentMSS != 1200 {
		t.Fatalf("MTU event MSS = %d -> %d", lifecycle.previousMSS, lifecycle.currentMSS)
	}
	if len(lifecycle.events) != 2 || lifecycle.events[0] != CongestionEventInitialize || lifecycle.events[1] != CongestionEventMTUChanged {
		t.Fatalf("lifecycle events = %v", lifecycle.events)
	}
}

func TestCongestionRecoveryUsesStableEventStages(t *testing.T) {
	recorder := &congestionAPIRecorder{undoWindow: 16_000, undoThreshold: 18_000}
	controller := newTCPCongestionControllerFromDefinition(CongestionControlDefinition{
		Name: "recovery-events",
		New:  func(CongestionControlContext) CongestionController { return recorder }, Features: CongestionControlFeatureCustomRecovery,
	})
	_, _ = controller.initialize(time.Unix(99, 0), 10*time.Millisecond, 20*time.Millisecond, 20_000, 10_000, 1000, 1)
	controller.checkpointRecovery(time.Unix(100, 0), 20_000, 10_000, 15_000, 1000)
	if flight := controller.recoveryFlight(time.Unix(100, 0), 15_000, 12_000); flight != 15_000 {
		t.Fatalf("custom recovery flight = %d, want 15000", flight)
	}
	_ = controller.recoveryWindow(time.Unix(100, 0), 20_000, 15_000, 10_000, 1000, true)
	_ = controller.applyPRRWindow(time.Unix(100, 0), 9000, 8000, 7000)
	_ = controller.exitRecoveryWindow(time.Unix(100, 0), 9000, 10_000, 7000, true)
	_ = controller.partialACKWindow(time.Unix(100, 0), 9000, 1000, 7000, 1000)
	_ = controller.duplicateACKWindow(time.Unix(100, 0), 9000, 7000, 1000)
	window, threshold := controller.undoRecovery(time.Unix(101, 0), 9000, 10_000, 10_000, 8000, 1000, CongestionPhaseOpen)
	if window != recorder.undoWindow || threshold != recorder.undoThreshold {
		t.Fatalf("custom recovery undo = window %d threshold %d, want %d %d", window, threshold, recorder.undoWindow, recorder.undoThreshold)
	}
	want := []CongestionRecoveryStage{
		CongestionRecoveryCheckpoint, CongestionRecoverySelectFlight, CongestionRecoveryEnter,
		CongestionRecoveryPRR, CongestionRecoveryExit, CongestionRecoveryPartialACK,
		CongestionRecoveryDuplicateACK, CongestionRecoveryUndo,
	}
	if len(recorder.recovery) != len(want) {
		t.Fatalf("recovery stages = %v, want %v", recorder.recovery, want)
	}
	for index := range want {
		if recorder.recovery[index] != want[index] {
			t.Fatalf("recovery stages = %v, want %v", recorder.recovery, want)
		}
	}
	checks := []struct {
		index          int
		previousWindow uint32
		flight         uint32
		proposed       uint32
		sack           bool
	}{
		{index: 1, flight: 15_000},
		{index: 2, previousWindow: 20_000, flight: 15_000, proposed: 10_000, sack: true},
		{index: 3, previousWindow: 9000, flight: 7000, proposed: 8000, sack: true},
		{index: 4, previousWindow: 9000, flight: 7000, proposed: 10_000, sack: true},
		{index: 5, previousWindow: 9000, flight: 7000, proposed: 9000},
		{index: 6, previousWindow: 9000, flight: 7000, proposed: 10_000},
		{index: 7, previousWindow: 9000, flight: 8000, proposed: 10_000},
	}
	for _, check := range checks {
		recovery := recorder.recoveries[check.index]
		if recovery.PreviousWindow != check.previousWindow || recovery.Flight != check.flight || recovery.ProposedWindow != check.proposed || recovery.SACK != check.sack {
			t.Fatalf("recovery stage %v payload = %+v", recovery.Stage, recovery)
		}
	}
	if len(recorder.phases) != 2 || recorder.phases[0] != CongestionPhaseRecovery || recorder.phases[1] != CongestionPhaseOpen {
		t.Fatalf("recovery phases = %v, want [Recovery Open]", recorder.phases)
	}
}

func TestCongestionControllerSkipsOptionalEventFamilies(t *testing.T) {
	recorder := &congestionAPIRecorder{undoWindow: 16_000, undoThreshold: 18_000}
	controller := newTCPCongestionControllerFromDefinition(CongestionControlDefinition{
		Name: "default-events",
		New:  func(CongestionControlContext) CongestionController { return recorder },
	})
	start := time.Unix(100, 0)
	controller.initialize(start, 10*time.Millisecond, 20*time.Millisecond, 20_000, 10_000, 1000, 1)
	_, _ = controller.onDataSend(1000, 1000, start, 2, 0, 20_000, 0, 20*time.Millisecond, 10_000)
	_ = controller.onRetransmit(1000, 1000, start, 3, 20_000, 1000, 1000, 20*time.Millisecond, 10_000)
	controller.checkpointRecovery(start, 20_000, 10_000, 10_000, 1000)
	if flight := controller.recoveryFlight(start, 10_000, 8000); flight != 8000 {
		t.Fatalf("default recovery flight = %d, want 8000", flight)
	}
	_ = controller.recoveryWindow(start, 20_000, 8000, 10_000, 1000, true)
	_ = controller.applyPRRWindow(start, 9000, 8000, 7000)
	_ = controller.exitRecoveryWindow(start, 9000, 10_000, 7000, true)
	_ = controller.partialACKWindow(start, 9000, 1000, 7000, 1000)
	_ = controller.duplicateACKWindow(start, 9000, 7000, 1000)
	window, threshold := controller.undoRecovery(start.Add(time.Second), 9000, 10_000, 10_000, 8000, 1000, CongestionPhaseOpen)
	if window != 10_000 || threshold != 10_000 || controller.state.CongestionWindow != window || controller.state.SlowStartThreshold != threshold {
		t.Fatalf("default recovery accepted undo override: returned %d/%d state %d/%d", window, threshold, controller.state.CongestionWindow, controller.state.SlowStartThreshold)
	}

	for _, eventType := range recorder.events {
		if eventType == CongestionEventPacketSent || eventType == CongestionEventPacketRetransmitted {
			t.Fatalf("controller without transmission feature received %v", eventType)
		}
	}
	wantRecovery := []CongestionRecoveryStage{CongestionRecoveryCheckpoint, CongestionRecoveryUndo}
	if len(recorder.recovery) != len(wantRecovery) || recorder.recovery[0] != wantRecovery[0] || recorder.recovery[1] != wantRecovery[1] {
		t.Fatalf("default recovery events = %v, want %v", recorder.recovery, wantRecovery)
	}
}
