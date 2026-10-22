package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type bbr3TailProbeRecorder struct {
	algorithm *bbr3CongestionControl
	seen      atomic.Bool
	acks      atomic.Uint64
	recovery  atomic.Uint64
}

type bbr3RenegingRecorder struct {
	algorithm    *bbr3CongestionControl
	validLoss    atomic.Uint64
	staleLoss    atomic.Uint64
	lostBytes    atomic.Uint64
	onPacketSent func()
}

type bbr3Retransmission struct {
	flight   uint32
	snapshot uint32
	bytes    int
	phase    CongestionPhase
}

type bbr3RetransmissionRecorder struct {
	algorithm *bbr3CongestionControl
	published chan bbr3Retransmission
}

func (r *bbr3RetransmissionRecorder) HandleCongestionEvent(event *CongestionEvent) {
	r.algorithm.HandleCongestionEvent(event)
	if event.Type == CongestionEventPacketRetransmitted {
		r.published <- bbr3Retransmission{flight: event.State.BytesInFlight, snapshot: bbr3DecodePacketState(event.PacketState).inflight, bytes: event.PacketBytes, phase: event.State.Phase}
	}
}

type bbr3RTOAcknowledgment struct {
	before, after, snapshot, acknowledged uint32
	losses                                uint64
	valid                                 bool
}

type bbr3RTORecorder struct {
	algorithm *bbr3CongestionControl
	published chan bbr3Retransmission
	sent      chan bbr3Retransmission
	acked     chan bbr3RTOAcknowledgment
}

func (r *bbr3RTORecorder) HandleCongestionEvent(event *CongestionEvent) {
	before := r.algorithm.inflightHigh
	r.algorithm.HandleCongestionEvent(event)
	switch event.Type {
	case CongestionEventInitialize:
		r.algorithm.mode, r.algorithm.probePhase = bbrProbeBandwidth, bbr3ProbeCruise
		r.algorithm.fullBandwidthReached = true
		r.algorithm.inflightHigh = uint32(4 * event.State.MaximumSegmentSize)
		r.algorithm.bandwidthHigh[1] = 1_000_000
		r.algorithm.probeStarted = event.Time
	case CongestionEventPacketRetransmitted:
		r.published <- bbr3Retransmission{flight: event.State.BytesInFlight, snapshot: bbr3DecodePacketState(event.PacketState).inflight, bytes: event.PacketBytes, phase: event.State.Phase}
	case CongestionEventPacketSent:
		if r.sent != nil {
			r.sent <- bbr3Retransmission{flight: event.State.BytesInFlight, snapshot: bbr3DecodePacketState(event.PacketState).inflight, bytes: event.PacketBytes, phase: event.State.Phase}
		}
	case CongestionEventACK:
		if sample := event.RateSample; sample != nil {
			r.acked <- bbr3RTOAcknowledgment{
				before: before, after: r.algorithm.inflightHigh,
				snapshot:     bbr3DecodePacketState(sample.PacketState()).inflight,
				acknowledged: sample.AcknowledgedBytes(), losses: sample.LostBytes(), valid: sample.Valid(),
			}
		}
	}
}

func (r *bbr3RenegingRecorder) HandleCongestionEvent(event *CongestionEvent) {
	if event.Type == CongestionEventPacketLost {
		if event.PacketLossEvidenceValid {
			r.validLoss.Add(1)
		} else {
			r.staleLoss.Add(1)
		}
		r.lostBytes.Add(uint64(event.PacketBytes))
	}
	r.algorithm.HandleCongestionEvent(event)
	if event.Type == CongestionEventPacketSent && r.onPacketSent != nil {
		r.onPacketSent()
	}
}

func (r *bbr3TailProbeRecorder) HandleCongestionEvent(event *CongestionEvent) {
	if event.Type == CongestionEventACK && event.RateSample != nil {
		r.acks.Add(1)
		if event.RateSample.TailLossProbeACK() {
			r.seen.Store(true)
		}
	}
	if event.Type == CongestionEventTailLossProbeRecovered {
		r.recovery.Add(1)
	}
	r.algorithm.HandleCongestionEvent(event)
}

func bbr3RateSample(now time.Time, delivered, acked, flight uint32, interval time.Duration) *tcpDeliveryRateSample {
	remaining := uint32(0)
	if acked < flight {
		remaining = flight - acked
	}
	return &tcpDeliveryRateSample{
		priorDelivered: 1,
		delivered:      delivered,
		acked:          acked,
		priorInFlight:  flight,
		inFlight:       remaining,
		interval:       interval,
		rtt:            interval,
		smoothedRTT:    interval,
		ackTime:        now,
		valid:          interval > 0,
	}
}

func TestBBR3PacketStatePreservesLossInputs(t *testing.T) {
	state := CongestionState{
		BytesInFlight:      20_000,
		LostBytes:          uint64(^uint32(0)) + 123,
		ApplicationLimited: true,
	}
	encoded := bbr3EncodePacketState(&state, 1000)
	decoded := bbr3DecodePacketState(encoded)
	if decoded.inflight != 21_000 || decoded.lost != 122 || !decoded.applicationLimited {
		t.Fatalf("decoded packet state = %+v", decoded)
	}
	state.BytesInFlight = bbr3PacketInflightMask
	decoded = bbr3DecodePacketState(bbr3EncodePacketState(&state, 1000))
	if decoded.inflight != bbr3PacketInflightMask {
		t.Fatalf("saturated tx.in_flight = %d, want %d", decoded.inflight, bbr3PacketInflightMask)
	}
}

func TestBBR3InitialWindowFollowsControllerInitialization(t *testing.T) {
	const mss = 1000
	bbr := newBBR3CongestionControl()
	state := CongestionState{CongestionWindow: 40 * mss, MaximumSegmentSize: mss, SmoothedRTT: time.Millisecond}
	bbr.HandleCongestionEvent(&CongestionEvent{Type: CongestionEventInitialize, Time: time.Unix(100, 0), State: &state})
	if bbr.initialWindowMSS != 40 || bbr.modelWindowForBandwidth(0, 1, mss) != 40*mss {
		t.Fatalf("initial window = %d MSS/%d bytes", bbr.initialWindowMSS, bbr.modelWindowForBandwidth(0, 1, mss))
	}
	if got := bbr3InitialWindowMSS(tcpMaximumScaledWindow, mss); got != 127 {
		t.Fatalf("capped initial window = %d MSS, want 127", got)
	}
}

func TestBBR3StartupWindowIncludesACKAggregation(t *testing.T) {
	const mss = 1000
	bbr := newBBR3CongestionControl()
	bbr.initialWindowMSS = bbrInitialCongestionMSS
	bbr.minimumRTT = 10 * time.Millisecond
	bbr.bandwidthHigh[1] = 1_000_000
	bbr.extraACKed[0] = 10_000
	sample := bbr3RateSample(time.Unix(100, 0), mss, mss, 25*mss, time.Millisecond)
	if window := bbr.setCongestionWindow(25*mss, sample, mss); window != 26*mss {
		t.Fatalf("Startup ACK-aggregation window = %d, want %d", window, 26*mss)
	}
}

func TestBBR3UsesLinuxDefaultGains(t *testing.T) {
	bbr := newBBR3CongestionControl()
	if gain := bbr.pacingGain(); gain != 710.0/256 {
		t.Fatalf("Startup pacing gain = %v", gain)
	}
	bbr.mode = bbrDrain
	if gain := bbr.pacingGain(); gain != 88.0/256 {
		t.Fatalf("Drain pacing gain = %v", gain)
	}
	bbr.mode = bbrProbeBandwidth
	bbr.probePhase = bbr3ProbeDown
	if gain := bbr.pacingGain(); gain != 232.0/256 {
		t.Fatalf("ProbeDOWN pacing gain = %v", gain)
	}
	bbr.probePhase = bbr3ProbeUp
	if gain := bbr.pacingGain(); gain != 1.25 || bbr.congestionWindowGain() != 2.25 {
		t.Fatalf("ProbeUP gains = pacing %v cwnd %v", gain, bbr.congestionWindowGain())
	}
}

func TestBBR3StartupPlateauEntersDrain(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	bbr := newBBR3CongestionControl()
	bbr.minimumRTT = 10 * time.Millisecond
	bbr.bandwidthHigh[1] = 1_000_000
	bbr.fullBandwidth = 1_000_000
	for round := 0; round < bbrFullBandwidthRounds; round++ {
		bbr.roundStart = true
		bbr.checkFullBandwidth(bbr3RateSample(now.Add(time.Duration(round)*time.Millisecond), 1000, 1000, 10_000, time.Millisecond), 1_000_000)
	}
	if !bbr.fullBandwidthReached {
		t.Fatal("three stagnant rounds did not fill the pipe")
	}
	sample := bbr3RateSample(now, 1000, 1000, 1000, time.Millisecond)
	threshold := bbr.checkDrain(sample, mss)
	if bbr.mode != bbrProbeBandwidth || bbr.probePhase != bbr3ProbeDown || threshold == 0 {
		t.Fatalf("post-Startup state = mode %v phase %v threshold %d", bbr.mode, bbr.probePhase, threshold)
	}
}

func TestBBR3ProbeBandwidthCycle(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	bbr := newBBR3CongestionControl()
	bbr.mode = bbrProbeBandwidth
	bbr.minimumRTT = 10 * time.Millisecond
	bbr.bandwidthHigh[1] = 1_000_000
	bbr.fullBandwidthReached = true
	bbr.enterProbePhase(bbr3ProbeDown, now)
	bbr.probeWait = 2 * time.Second
	sample := bbr3RateSample(now, 1000, 1000, 4000, time.Millisecond)
	bbr.updateProbeBandwidth(sample, bbr3PacketSnapshot{}, 1_000_000, 20_000, mss)
	if bbr.probePhase != bbr3ProbeCruise {
		t.Fatalf("drained phase = %s", bbr.probePhase.String())
	}
	sample.ackTime = now.Add(2*time.Second + time.Microsecond)
	bbr.updateProbeBandwidth(sample, bbr3PacketSnapshot{}, 1_000_000, 20_000, mss)
	if bbr.probePhase != bbr3ProbeRefill || bbr.ackPhase != bbr3ACKsRefilling {
		t.Fatalf("scheduled probe = phase %s ACK phase %d", bbr.probePhase.String(), bbr.ackPhase)
	}
	bbr.roundStart = true
	bbr.roundCount++
	bbr.updateProbeBandwidth(sample, bbr3PacketSnapshot{}, 1_000_000, 20_000, mss)
	if bbr.probePhase != bbr3ProbeUp || !bbr.probeSamples {
		t.Fatalf("refill completion = phase %s samples %t", bbr.probePhase.String(), bbr.probeSamples)
	}
}

func TestBBR3BandwidthFilterRotatesAfterProbeFeedback(t *testing.T) {
	bbr := newBBR3CongestionControl()
	bbr.mode = bbrProbeBandwidth
	bbr.fullBandwidthReached = true
	bbr.ackPhase = bbr3ACKsProbeStopping
	bbr.probeSamples = true
	bbr.roundStart = true
	bbr.bandwidthHigh = [2]float64{800_000, 1_000_000}
	sample := bbr3RateSample(time.Unix(100, 0), 1000, 1000, 10_000, time.Millisecond)
	bbr.adaptUpperBounds(sample, bbr3PacketSnapshot{}, 20_000, 1000)
	if bbr.probeSamples || bbr.ackPhase != bbr3ACKsInitial || bbr.bandwidthHigh != [2]float64{1_000_000, 0} {
		t.Fatalf("rotated probe feedback = samples %t phase %d bw %v", bbr.probeSamples, bbr.ackPhase, bbr.bandwidthHigh)
	}
}

func TestBBR3LossBoundsAndProbePrefix(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	bbr := newBBR3CongestionControl()
	bbr.mode = bbrProbeBandwidth
	bbr.probePhase = bbr3ProbeUp
	bbr.probeSamples = true
	bbr.bandwidthHigh[1] = 1_000_000
	bbr.minimumRTT = 10 * time.Millisecond
	state := CongestionState{CongestionWindow: 20_000, MaximumSegmentSize: mss, LostBytes: 500}
	packetState := bbr3EncodePacketState(&CongestionState{BytesInFlight: 19_000}, mss)
	event := CongestionEvent{Type: CongestionEventPacketLost, Time: now, State: &state, PacketBytes: mss, PacketState: packetState, PacketLossEvidenceValid: true}
	bbr.onPacketLost(&event)
	if bbr.inflightHigh == 0 || bbr.inflightHigh >= 20_000 || bbr.probeSamples || bbr.probePhase != bbr3ProbeDown {
		t.Fatalf("probe loss response = inflight_hi %d samples %t phase %s", bbr.inflightHigh, bbr.probeSamples, bbr.probePhase.String())
	}

	bbr.mode = bbrProbeBandwidth
	bbr.probePhase = bbr3ProbeCruise
	bbr.bandwidthLow = 1_000_000
	bbr.inflightLow = 20_000
	bbr.latestBandwidth = 800_000
	bbr.latestInflight = 16_000
	bbr.lossInRound = true
	bbr.lossRoundStart = true
	bbr.updateCongestionSignals(bbr3RateSample(now, 1000, 1000, 10_000, time.Millisecond), 1_000_000, 20_000)
	if bbr.bandwidthLow != 800_000 || bbr.inflightLow != 16_000 {
		t.Fatalf("lower bounds = %v/%d", bbr.bandwidthLow, bbr.inflightLow)
	}
}

func TestBBR3RenegingLossDoesNotUseProbeEvidence(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	bbr := newBBR3CongestionControl()
	bbr.mode, bbr.probePhase = bbrProbeBandwidth, bbr3ProbeUp
	bbr.fullBandwidthReached, bbr.probeSamples = true, true
	bbr.minimumRTT, bbr.minimumRTTStamp = 10*time.Millisecond, now
	bbr.bandwidthHigh[1], bbr.probeStarted = 1_000_000, now
	state := CongestionState{CongestionWindow: 20_000, MaximumSegmentSize: mss, LostBytes: 500}
	event := CongestionEvent{
		Type:                    CongestionEventPacketLost,
		Time:                    now,
		State:                   &state,
		PacketBytes:             mss,
		PacketState:             bbr3EncodePacketState(&CongestionState{BytesInFlight: 19_000}, mss),
		PacketLossEvidenceValid: false,
	}
	bbr.onPacketLost(&event)
	if !bbr.lossInRound || bbr.lost != state.LostBytes || !bbr.probeSamples || bbr.probePhase != bbr3ProbeUp || bbr.inflightHigh != 0 {
		t.Fatalf("reneging loss feedback = lossInRound:%v samples:%v phase:%s inflight_hi:%d", bbr.lossInRound, bbr.probeSamples, bbr.probePhase.String(), bbr.inflightHigh)
	}
}

func TestTCPBBR3SACKRenegingLossEvidence(t *testing.T) {
	local, remote := netip.MustParseAddr("192.0.2.192"), netip.MustParseAddr("198.51.100.192")
	link, stack := newTestStack(t, local, remote)
	defer stack.Close()
	recorder := &bbr3RenegingRecorder{algorithm: newBBR3CongestionControl()}
	builtin, _ := registeredCongestionControlFactory(CongestionControlBBR3)
	definition := builtin.definition
	definition.Name = "BBRv3-reneging"
	definition.New = func(CongestionControlContext) CongestionController { return recorder }
	factory, err := NewCongestionControlFactory(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		TCP: TCPSocketDefaults{CongestionControlFactory: factory}}); err != nil {
		t.Fatal(err)
	}
	link.mu.Lock()
	link.echoTCP, link.sackTCP, link.sackReneging = true, true, true
	link.dropTCPOrdinals = map[int]bool{1: true}
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 8103))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	writeAndReadTCPEcho(t, connection, make([]byte, 16*1024))
	link.mu.Lock()
	renege := !link.sackRenegingAt.IsZero()
	link.mu.Unlock()
	if !renege || recorder.staleLoss.Load() < 2 || recorder.validLoss.Load() == 0 || recorder.lostBytes.Load() == 0 {
		t.Fatalf("reneging:%t stale-loss:%d ordinary-loss:%d bytes:%d", renege, recorder.staleLoss.Load(), recorder.validLoss.Load(), recorder.lostBytes.Load())
	}
	if undos := connection.(*TCPConn).Info().SpuriousRecoveryUndos; undos != 0 {
		t.Fatalf("reneging produced %d spurious undos", undos)
	}
}

func TestTCPBBR3SACKRenegingAfterHostQueueDeparture(t *testing.T) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	defer connection.Close()
	recorder := &bbr3RenegingRecorder{algorithm: newBBR3CongestionControl()}
	builtin, _ := registeredCongestionControlFactory(CongestionControlBBR3)
	definition := builtin.definition
	definition.Name = "BBRv3-host-queue-reneging"
	flightReady, releaseFlight := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseFlight) })
	sent := 0
	recorder.onPacketSent = func() {
		sent++
		if sent == 2 {
			close(flightReady)
			<-releaseFlight
		}
	}
	definition.New = func(CongestionControlContext) CongestionController { return recorder }
	factory, err := NewCongestionControlFactory(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.SetCongestionControlFactory(factory); err != nil {
		t.Fatal(err)
	}
	info := connection.Info()
	if info.CongestionControl != definition.Name {
		t.Fatalf("congestion controller = %q, want %q", info.CongestionControl, definition.Name)
	}

	link.mu.Lock()
	link.dropTCPOrdinals = map[int]bool{1: true}
	link.sackReneging = true
	link.mu.Unlock()

	type queuedData struct {
		raw        []byte
		slot       uint16
		sequence   uint32
		generation uint64
	}
	snapshotData := func() []queuedData {
		scheduler := stack.outbound.scheduler
		if scheduler == nil {
			return nil
		}
		scheduler.mu.Lock()
		defer scheduler.mu.Unlock()
		packets := make([]queuedData, 0, scheduler.queued)
		for slot := range scheduler.nodes {
			entry := scheduler.nodes[slot].entry
			if len(entry.packet) == 0 {
				continue
			}
			packet, parseErr := ParseIPPacket(entry.packet)
			if parseErr != nil || packet.Protocol != ProtocolTCP {
				continue
			}
			segment, parseErr := packet.TCPSegment()
			if parseErr != nil || len(segment.Payload) == 0 {
				continue
			}
			packets = append(packets, queuedData{
				raw: append([]byte(nil), entry.packet...), slot: uint16(slot), sequence: segment.SequenceNumber,
				generation: stack.outbound.slots[slot].Load() >> packetQueueSlotGenerationShift,
			})
		}
		sort.Slice(packets, func(i, j int) bool {
			return tcpSequenceLess(packets[i].sequence, packets[j].sequence)
		})
		return packets
	}

	payload := bytes.Repeat([]byte{0x7a}, 2*info.MaximumSegmentSize)
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("TCP Write = %d, %v", n, err)
	}
	select {
	case <-flightReady:
	case <-time.After(time.Second):
		t.Fatal("initial flight was not published")
	}
	initial := snapshotData()
	if len(initial) != 2 {
		t.Fatalf("initial queued ranges = %d, want 2", len(initial))
	}
	first, second := initial[0], initial[1]
	entry, available := stack.outbound.tryDequeue()
	if !available || entry.slot != first.slot {
		if available {
			stack.outbound.release(entry)
		}
		t.Fatalf("first host-queue departure slot = %d/%t, want %d", entry.slot, available, first.slot)
	}
	firstWire := consumeTestPacket(&stack.outbound, entry)
	firstPacket, err := ParseIPPacket(firstWire)
	if err != nil {
		t.Fatal(err)
	}
	firstSegment, err := firstPacket.TCPSegment()
	if err != nil || firstSegment.SequenceNumber != first.sequence {
		t.Fatalf("departed first segment = %+v, %v", firstSegment, err)
	}
	if err = link.handleOutboundPacket(firstWire); err != nil {
		t.Fatal(err)
	}
	if err = link.handleOutboundPacket(second.raw); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return connection.inbound.len() != 0 })
	releaseOnce.Do(func() { close(releaseFlight) })
	_ = connection.Info()

	var firstRetransmission queuedData
	waitFor(t, time.Second, func() bool {
		for _, packet := range snapshotData() {
			if packet.sequence == first.sequence {
				firstRetransmission = packet
				return true
			}
		}
		return false
	})
	if err = link.handleOutboundPacket(firstRetransmission.raw); err != nil {
		t.Fatal(err)
	}
	_ = connection.Info()

	waitFor(t, 2*info.RetransmissionTimeout+time.Second, func() bool {
		waiters := stack.outbound.departureWaiters.Load()
		if waiters == nil {
			return false
		}
		waiter := waiters.slots[second.slot].Load()
		return waiter != nil && waiter.generation == second.generation && waiter.departedAt.Load() == 0
	})
	if recorder.staleLoss.Load() != 0 {
		t.Fatal("reneging loss was reported before the second original departed")
	}
	entry, available = stack.outbound.tryDequeue()
	if !available || entry.slot != second.slot {
		if available {
			stack.outbound.release(entry)
		}
		t.Fatalf("second host-queue departure slot = %d/%t, want %d", entry.slot, available, second.slot)
	}
	secondWire := consumeTestPacket(&stack.outbound, entry)
	secondPacket, err := ParseIPPacket(secondWire)
	if err != nil {
		t.Fatal(err)
	}
	secondSegment, err := secondPacket.TCPSegment()
	if err != nil || secondSegment.SequenceNumber != second.sequence {
		t.Fatalf("departed second segment = %+v, %v", secondSegment, err)
	}
	waitFor(t, time.Second, func() bool { return recorder.staleLoss.Load() != 0 })
	if recorder.validLoss.Load() == 0 {
		t.Fatal("initial RACK loss did not retain valid evidence")
	}
	var secondRetransmission queuedData
	waitFor(t, time.Second, func() bool {
		for _, packet := range snapshotData() {
			if packet.sequence == second.sequence {
				secondRetransmission = packet
				return true
			}
		}
		return false
	})
	if err = link.handleOutboundPacket(secondRetransmission.raw); err != nil {
		t.Fatal(err)
	}
	link.mu.Lock()
	renege := !link.sackRenegingAt.IsZero()
	link.mu.Unlock()
	if !renege {
		t.Fatal("SACK reneging was not observed")
	}
	_ = connection.Info()
}

func TestBBR3LossThresholdIsStrictlyAboveTwoPercent(t *testing.T) {
	bbr := newBBR3CongestionControl()
	if bbr.inflightTooHigh(1000, 51_200) {
		t.Fatal("exact fixed-point two-percent threshold was treated as excessive")
	}
	if !bbr.inflightTooHigh(1001, 51_200) {
		t.Fatal("loss above the fixed-point two-percent threshold was accepted")
	}
}

func TestBBR3ACKLossRateUsesTransmissionSnapshot(t *testing.T) {
	bbr := newBBR3CongestionControl()
	bbr.mode = bbrProbeBandwidth
	bbr.probePhase = bbr3ProbeUp
	bbr.fullBandwidthReached = true
	bbr.probeSamples = true
	bbr.minimumRTT = 10 * time.Millisecond
	bbr.bandwidthHigh[1] = 1_000_000
	bbr.lost = 5000
	sample := bbr3RateSample(time.Unix(100, 0), 1000, 1000, 20_000, time.Millisecond)
	packet := bbr3PacketSnapshot{inflight: 20_000, lost: 3000}
	if transitioned := bbr.adaptUpperBounds(sample, packet, 20_000, 1000); transitioned {
		t.Fatal("loss response was reported as an independent state transition")
	}
	if bbr.inflightHigh == 0 || bbr.probeSamples || bbr.probePhase != bbr3ProbeDown {
		t.Fatalf("cumulative loss response = inflight_hi %d samples %t phase %s", bbr.inflightHigh, bbr.probeSamples, bbr.probePhase.String())
	}
}

func TestBBR3ACKWithoutDeliveryDoesNotInventProbeLoss(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	for _, hasSnapshot := range []bool{false, true} {
		bbr := newBBR3CongestionControl()
		bbr.mode, bbr.probePhase = bbrProbeBandwidth, bbr3ProbeUp
		bbr.fullBandwidthReached, bbr.probeSamples = true, true
		bbr.minimumRTT, bbr.minimumRTTStamp = 10*time.Millisecond, now
		bbr.bandwidthHigh[1], bbr.probeStarted = 1_000_000, now
		bbr.lost = 1000
		sample := tcpDeliveryRateSample{ackTime: now, priorInFlight: 20_000, inFlight: 20_000, smoothedRTT: 10 * time.Millisecond}
		if hasSnapshot {
			sample.packetState = bbr3EncodePacketState(&CongestionState{BytesInFlight: 19_000}, mss)
		}
		_, _ = bbr.onRateSample(20_000, mss, &sample)
		if hasSnapshot {
			if bbr.probeSamples || bbr.probePhase != bbr3ProbeDown || bbr.inflightHigh == 0 {
				t.Fatalf("real transmission loss was ignored: %+v", bbr)
			}
		} else if !bbr.probeSamples || bbr.probePhase != bbr3ProbeUp || bbr.inflightHigh != 0 {
			t.Fatalf("ACK without a transmission snapshot invented probe loss: %+v", bbr)
		}
	}
}

func TestBBR3SACKDeliveryDoesNotUseStaleProbeSnapshot(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	bbr := newBBR3CongestionControl()
	bbr.mode, bbr.probePhase = bbrProbeBandwidth, bbr3ProbeUp
	bbr.fullBandwidthReached, bbr.probeSamples = true, true
	bbr.minimumRTT, bbr.minimumRTTStamp = 10*time.Millisecond, now
	bbr.bandwidthHigh[1], bbr.probeStarted = 1_000_000, now
	bbr.inflightHigh = 10_000
	bbr.lost = 1000
	sample := tcpDeliveryRateSample{ackTime: now, priorInFlight: 20_000, inFlight: 20_000, smoothedRTT: 10 * time.Millisecond}
	sample.observe(sentTCPSegment{
		state:                 sentTCPSegmentTransmitted | sentTCPSegmentSACKed,
		congestionPacketState: bbr3EncodePacketState(&CongestionState{BytesInFlight: 18_000}, mss),
		hostQueue:             packetQueueTicket{queuedAt: 1},
		delivery:              tcpDeliverySnapshot{firstSent: 1, deliveredStamp: 1},
	})
	if sample.PacketLossEvidenceValid() {
		t.Fatal("SACK-selected transmission retained loss evidence")
	}
	_, _ = bbr.onRateSample(20_000, mss, &sample)
	if !bbr.probeSamples || bbr.probePhase != bbr3ProbeUp || bbr.inflightHigh != 19_000 {
		t.Fatalf("SACK-selected transmission feedback = samples %t phase %s inflight_hi %d, want no loss response and 19000 upper bound", bbr.probeSamples, bbr.probePhase.String(), bbr.inflightHigh)
	}
}

func TestTCPSACKPreservesCongestionTransmissionState(t *testing.T) {
	segment := sentTCPSegment{
		sequence: 100, end: 200,
		state:                 sentTCPSegmentInitialState(false, false, false, false),
		congestionPacketState: 0x1234,
	}
	outstanding, _, _, newInformation, newlySACKed := applyTCPSACK(
		[]sentTCPSegment{segment}, []TCPSACKBlock{{LeftEdge: 100, RightEdge: 200}},
	)
	if !newInformation || len(outstanding) != 1 {
		t.Fatalf("SACK application = information %t ranges %d", newInformation, len(outstanding))
	}
	if !outstanding[0].state.has(sentTCPSegmentSACKed) {
		t.Fatal("SACKed range did not enter the scoreboard")
	}
	if outstanding[0].congestionPacketState != 0x1234 {
		t.Fatalf("SACKed congestion transmission state = %#x, want original", outstanding[0].congestionPacketState)
	}
	if len(newlySACKed) != 1 || newlySACKed[0].congestionPacketState != 0x1234 || !newlySACKed[0].state.has(sentTCPSegmentSACKed) {
		t.Fatalf("SACK delivery sample state = %#v, want original metadata and SACK mark", newlySACKed)
	}

	outstanding[0].state.set(sentTCPSegmentSACKed, false)
	outstanding[0].advanceTransmissionGeneration()
	if !outstanding[0].state.has(sentTCPSegmentTransmitted) || !outstanding[0].state.has(sentTCPSegmentRetransmitted) || outstanding[0].congestionPacketState != 0x1234 {
		t.Fatalf("retransmission generation = state %#x metadata %#x", outstanding[0].state, outstanding[0].congestionPacketState)
	}
	outstanding[0].congestionPacketState = 0x5678
	if outstanding[0].congestionPacketState != 0x5678 {
		t.Fatal("retransmission did not accept fresh controller metadata")
	}
}

func TestBBR3LossRoundAdvancesIndependently(t *testing.T) {
	bbr := newBBR3CongestionControl()
	bbr.lossRoundDelivered = 100
	bbr.delivered = 200
	first := bbr3RateSample(time.Unix(100, 0), 100, 100, 1000, time.Millisecond)
	first.priorDelivered = 100
	bbr.updateLatestDeliverySignals(first, 100_000)
	if !bbr.lossRoundStart || bbr.lossRoundDelivered != 200 {
		t.Fatalf("first loss round = start %t boundary %d", bbr.lossRoundStart, bbr.lossRoundDelivered)
	}
	second := bbr3RateSample(time.Unix(100, 0), 50, 50, 1000, time.Millisecond)
	second.priorDelivered = 150
	bbr.updateLatestDeliverySignals(second, 50_000)
	if bbr.lossRoundStart {
		t.Fatal("an ACK inside the current loss round started another round")
	}
}

func TestBBR3TailLossProbeACKIsSampleScoped(t *testing.T) {
	bbr := newBBR3CongestionControl()
	bbr.lossRoundStart = true
	bbr.latestBandwidth = 900_000
	bbr.latestInflight = 9000
	sample := bbr3RateSample(time.Unix(100, 0), 1000, 1000, 10_000, time.Millisecond)
	sample.tailLossProbeACK = true
	bbr.advanceLatestDeliverySignals(sample, 500_000)
	if bbr.latestBandwidth != 900_000 || bbr.latestInflight != 9000 {
		t.Fatalf("TLP ACK discarded prior delivery signals: %v/%d", bbr.latestBandwidth, bbr.latestInflight)
	}
	sample.tailLossProbeACK = false
	bbr.advanceLatestDeliverySignals(sample, 500_000)
	if bbr.latestBandwidth != 500_000 || bbr.latestInflight != 1000 {
		t.Fatalf("TLP ACK state leaked into the next sample: %v/%d", bbr.latestBandwidth, bbr.latestInflight)
	}
}

func TestBBR3TailLossProbeRecoveryBoundsRiskyProbe(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	bbr := newBBR3CongestionControl()
	bbr.mode = bbrProbeBandwidth
	bbr.probePhase = bbr3ProbeUp
	bbr.probeSamples = true
	bbr.latestInflight = 20_000
	bbr.bandwidthHigh[1] = 1_000_000
	bbr.minimumRTT = 10 * time.Millisecond
	state := CongestionState{
		CongestionWindow: 20_000, MaximumSegmentSize: mss,
		DeliveredBytes: 100_000,
	}
	packetState := bbr3EncodePacketState(&CongestionState{BytesInFlight: 19_000}, mss)
	bbr.HandleCongestionEvent(&CongestionEvent{
		Type: CongestionEventTailLossProbeRecovered, Time: now, State: &state,
		PacketBytes: mss, PacketState: packetState,
	})
	if bbr.lossRoundDelivered != 100_000 {
		t.Fatalf("TLP loss-round boundary = %d, want 100000", bbr.lossRoundDelivered)
	}
	if bbr.inflightHigh == 0 || bbr.probeSamples || bbr.probePhase != bbr3ProbeDown {
		t.Fatalf("TLP probe response = inflight_hi %d samples %t phase %s", bbr.inflightHigh, bbr.probeSamples, bbr.probePhase.String())
	}
}

func TestTCPBBR3ObservesAmbiguousTailLossProbeACK(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.190")
	remote := netip.MustParseAddr("192.0.2.191")
	recorder := &bbr3TailProbeRecorder{algorithm: newBBR3CongestionControl()}
	name := nextCongestionAPITestName()
	factory, err := NewCongestionControlFactory(CongestionControlDefinition{
		Name: name,
		New:  func(CongestionControlContext) CongestionController { return recorder },
		Features: CongestionControlFeatureDeliveryRate |
			CongestionControlFeatureTransmissionEvents |
			CongestionControlFeatureCustomPacing |
			CongestionControlFeatureCustomRecovery |
			CongestionControlFeatureLossEvents,
		SendBufferMultiplier: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = RegisterCongestionControl(factory); err != nil {
		t.Fatal(err)
	}
	link, stack := newTestStack(t, local, remote)
	if err := stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		MTU:            1400,
		TCP:            TCPSocketDefaults{CongestionControl: name},
	}); err != nil {
		t.Fatal(err)
	}
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 8389))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	writeAndReadTCPEcho(t, connection, []byte("warmup"))
	link.mu.Lock()
	link.holdTCPACKs = 2
	link.dropTCPOrdinals = map[int]bool{3: true}
	link.mu.Unlock()
	writeAndReadTCPEcho(t, connection, make([]byte, 2000))
	if !recorder.seen.Load() {
		link.mu.Lock()
		retransmitted := link.tailRetransmission
		link.mu.Unlock()
		info := connection.(*TCPConn).Info()
		t.Fatalf("BBRv3 did not observe the ACK matching a retransmitted tail-loss probe: algorithm=%q RTT=%v ACKs=%d recovery=%d retransmitted=%t probes=%d retransmissions=%d", info.CongestionControl, info.RTT, recorder.acks.Load(), recorder.recovery.Load(), retransmitted, stack.Stats().TCPTailLossProbes, info.Retransmissions)
	}
}

func TestBBR3WindowBoundsFollowMode(t *testing.T) {
	const mss = 1000
	bbr := newBBR3CongestionControl()
	bbr.inflightHigh = 10_000
	bbr.mode = bbrDrain
	if got := bbr.boundWindow(20_000, mss); got != 20_000 {
		t.Fatalf("Drain was capped by inflight_hi: %d", got)
	}
	bbr.mode = bbrProbeBandwidth
	bbr.probePhase = bbr3ProbeDown
	if got := bbr.boundWindow(20_000, mss); got != 10_000 {
		t.Fatalf("ProbeDOWN inflight_hi cap = %d", got)
	}
	bbr.probePhase = bbr3ProbeCruise
	if got := bbr.boundWindow(20_000, mss); got != 8516 {
		t.Fatalf("Cruise headroom cap = %d, want 8516", got)
	}
}

func TestBBR3ProbeLossDoesNotReduceLowerBounds(t *testing.T) {
	bbr := newBBR3CongestionControl()
	bbr.mode = bbrProbeBandwidth
	bbr.probePhase = bbr3ProbeRefill
	bbr.bandwidthLow = 1_000_000
	bbr.inflightLow = 20_000
	bbr.latestBandwidth = 700_000
	bbr.latestInflight = 14_000
	bbr.lossInRound = true
	bbr.lossRoundStart = true
	bbr.updateCongestionSignals(bbr3RateSample(time.Unix(100, 0), 1000, 1000, 10_000, time.Millisecond), 1_000_000, 20_000)
	if bbr.bandwidthLow != 1_000_000 || bbr.inflightLow != 20_000 {
		t.Fatalf("probe loss reduced lower bounds to %v/%d", bbr.bandwidthLow, bbr.inflightLow)
	}
}

func TestBBR3StartupLossExitRequiresRecoveryRound(t *testing.T) {
	const mss = 1000
	bbr := newBBR3CongestionControl()
	bbr.bandwidthHigh[1] = 1_000_000
	bbr.latestInflight = 20_000
	bbr.lossRoundStart = true
	bbr.lossEventsInRound = bbr3FullLossEvents
	sample := bbr3RateSample(time.Unix(100, 0), 1000, 1000, 20_000, time.Millisecond)
	sample.losses = 1000
	bbr.lost = 1000
	packet := bbr3PacketSnapshot{inflight: 20_000}
	bbr.checkStartupLoss(sample, packet, mss)
	if bbr.fullBandwidthReached {
		t.Fatal("Startup exited on loss outside fast recovery")
	}
	bbr.lossEventsInRound = bbr3FullLossEvents
	sample.fastRecovery = true
	bbr.handleRecoveryEvent(&CongestionEvent{
		State:    &CongestionState{CongestionWindow: 24_000},
		Recovery: CongestionRecovery{Stage: CongestionRecoveryCheckpoint},
	})
	bbr.checkStartupLoss(sample, packet, mss)
	if !bbr.fullBandwidthReached || bbr.inflightHigh == 0 || bbr.undoState != bbr3UndoStartup {
		t.Fatal("lossy Startup recovery round did not bound inflight")
	}
	bbr.checkDrain(sample, mss)
	bbr.undoRecovery(sample.ackTime)
	if bbr.fullBandwidthReached || bbr.mode != bbrStartup {
		t.Fatal("undo did not restart loss-terminated Startup")
	}
}

func TestBBR3StartupLossDuringProbeRTT(t *testing.T) {
	for _, undo := range []bool{false, true} {
		name := "retain loss"
		if undo {
			name = "undo loss"
		}
		t.Run(name, func(t *testing.T) {
			const mss = 1000
			now := time.Unix(100, 0)
			bbr := newBBR3CongestionControl()
			bbr.bandwidthHigh[1] = 1_000_000
			bbr.minimumRTT = 5 * time.Millisecond
			bbr.minimumRTTStamp = now.Add(-6 * time.Second)
			bbr.probeRTTMinimum, bbr.probeRTTStamp = bbr.minimumRTT, bbr.minimumRTTStamp
			sample := bbr3RateSample(now, 1000, 1000, 20_000, bbr.minimumRTT)
			window := bbr.updateMinimumRTT(24_000, sample, mss)
			if bbr.mode != bbrProbeRTT || bbr.fullBandwidthReached {
				t.Fatal("ProbeRTT did not suspend unfinished Startup")
			}
			bbr.handleRecoveryEvent(&CongestionEvent{
				Time:     now,
				State:    &CongestionState{CongestionWindow: window, MaximumSegmentSize: mss},
				Recovery: CongestionRecovery{Stage: CongestionRecoveryCheckpoint},
			})
			bbr.latestInflight, bbr.lost = 20_000, 1000
			bbr.lossRoundStart, bbr.lossEventsInRound = true, bbr3FullLossEvents
			sample.losses, sample.fastRecovery = 1000, true
			bbr.checkStartupLoss(sample, bbr3PacketSnapshot{inflight: 20_000}, mss)
			if !bbr.fullBandwidthReached {
				t.Fatal("loss evidence did not end Startup during ProbeRTT")
			}
			if undo {
				bbr.handleRecoveryEvent(&CongestionEvent{
					Time:     now.Add(time.Millisecond),
					State:    &CongestionState{CongestionWindow: window, MaximumSegmentSize: mss},
					Recovery: CongestionRecovery{Stage: CongestionRecoveryUndo},
				})
			}
			if bbr.mode != bbrProbeRTT || bbr.fullBandwidthReached == undo {
				t.Fatal("recovery changed ProbeRTT or retained spurious Startup completion")
			}
			sample.inFlight = 0
			sample.ackTime = now.Add(2 * time.Millisecond)
			window = bbr.updateMinimumRTT(window, sample, mss)
			if bbr.probeDone.IsZero() {
				t.Fatal("ProbeRTT did not start its measurement interval")
			}
			sample.ackTime = now.Add(time.Second)
			bbr.roundStart = true
			bbr.updateMinimumRTT(window, sample, mss)
			wantMode := bbrProbeBandwidth
			if undo {
				wantMode = bbrStartup
			}
			if bbr.mode != wantMode {
				t.Fatalf("ProbeRTT exit resumed %s, want %s", bbr.mode, wantMode)
			}
		})
	}
}

func TestBBR3ProbeRTTUsesIndependentFiveSecondWindow(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	bbr := newBBR3CongestionControl()
	bbr.mode = bbrProbeBandwidth
	bbr.probePhase = bbr3ProbeCruise
	bbr.fullBandwidthReached = true
	bbr.bandwidthHigh[1] = 1_000_000
	bbr.minimumRTT = 10 * time.Millisecond
	bbr.minimumRTTStamp = start
	bbr.probeRTTMinimum = 10 * time.Millisecond
	bbr.probeRTTStamp = start
	sample := bbr3RateSample(start.Add(bbr3ProbeRTTWindow+time.Millisecond), 1000, 1000, 20_000, time.Millisecond)
	window := bbr.updateMinimumRTT(20_000, sample, mss)
	if bbr.mode != bbrProbeRTT || window != 20_000 || !bbr.requestAppLimited {
		t.Fatalf("ProbeRTT entry = mode %v window %d app-limited %t", bbr.mode, window, bbr.requestAppLimited)
	}
	bbr.probeDone = sample.ackTime.Add(-time.Millisecond)
	bbr.probeRound = true
	bbr.priorWindow = 20_000
	bbr.roundStart = true
	window = bbr.updateMinimumRTT(4000, sample, mss)
	if window != 20_000 || bbr.mode != bbrProbeBandwidth || bbr.probePhase != bbr3ProbeCruise {
		t.Fatalf("ProbeRTT exit = window %d mode %v phase %s", window, bbr.mode, bbr.probePhase.String())
	}
}

func TestBBR3ProbeRTTExitClearsLowerBounds(t *testing.T) {
	for _, idle := range []bool{false, true} {
		for _, fullBandwidth := range []bool{false, true} {
			t.Run(fmt.Sprintf("idle-%t/full-bandwidth-%t", idle, fullBandwidth), func(t *testing.T) {
				now := time.Unix(100, 0)
				bbr := newBBR3CongestionControl()
				bbr.mode, bbr.fullBandwidthReached, bbr.applicationLimited = bbrProbeRTT, fullBandwidth, true
				bbr.probeDone = now.Add(-time.Millisecond)
				bbr.priorWindow = 20_000
				bbr.bandwidthHigh[1], bbr.bandwidthLow, bbr.inflightLow, bbr.inflightHigh = 1_000_000, 500_000, 8000, 30_000
				window := uint32(4000)
				if idle {
					window = bbr.onDeliverySend(now, 0, window)
				} else {
					bbr.probeRound, bbr.roundStart = true, true
					bbr.probeRTTStamp, bbr.minimumRTTStamp = now, now
					window = bbr.updateMinimumRTT(window, bbr3RateSample(now, 1000, 1000, 4000, time.Millisecond), 1000)
				}
				wantMode := bbrStartup
				if fullBandwidth {
					wantMode = bbrProbeBandwidth
				}
				if bbr.mode != wantMode || window != 20_000 || bbr.bandwidthLow != 0 || bbr.inflightLow != 0 || bbr.inflightHigh != 30_000 || bbr.maximumBandwidth() != 1_000_000 || bbr.effectiveBandwidth() != 1_000_000 {
					t.Fatalf("ProbeRTT exit = mode %v window %d bandwidth %g bounds %g/%d/%d", bbr.mode, window, bbr.effectiveBandwidth(), bbr.bandwidthLow, bbr.inflightLow, bbr.inflightHigh)
				}
				if fullBandwidth && (bbr.probePhase != bbr3ProbeCruise || bbr.boundWindow(uint64(window), 1000) != uint64(window)) {
					t.Fatalf("ProbeBW restart = phase %v bounded window %d", bbr.probePhase, bbr.boundWindow(uint64(window), 1000))
				}
			})
		}
	}
}

func TestTCPBBR3PublishedRetransmissionFlight(t *testing.T) {
	for _, test := range []struct {
		name     string
		count    int
		pathMTU  bool
		repeated bool
	}{
		{name: "RACK", count: 2},
		{name: "SACK threshold", count: 5},
		{name: "PMTU first replacement", count: 5, pathMTU: true},
		{name: "PMTU repeated replacement", count: 5, pathMTU: true, repeated: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, stack, connection := newManuallyPumpedTCPConnection(t)
			recorder := &bbr3RetransmissionRecorder{algorithm: newBBR3CongestionControl(), published: make(chan bbr3Retransmission, 64)}
			base, _ := registeredCongestionControlFactory(CongestionControlBBR3)
			definition := base.definition
			definition.Name = "test-BBR3-flight"
			definition.New = func(CongestionControlContext) CongestionController { return recorder }
			factory, err := NewCongestionControlFactory(definition)
			if err != nil {
				t.Fatal(err)
			}
			if err = connection.SetCongestionControlFactory(factory); err != nil {
				t.Fatal(err)
			}
			mss := connection.Info().MaximumSegmentSize
			if _, err = connection.Write(bytes.Repeat([]byte{'x'}, test.count*mss)); err != nil {
				t.Fatal(err)
			}
			var segments []TCPSegment
			var firstWire []byte
			for len(segments) < test.count {
				entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
				if !available {
					t.Fatal("original transmission did not depart")
				}
				wire := consumeTestPacket(&stack.outbound, entry)
				packet, parseErr := ParseIPPacket(wire)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				segment, parseErr := packet.TCPSegment()
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				if len(segment.Payload) != 0 {
					if len(segments) == 0 {
						firstWire = wire
					}
					segments = append(segments, segment)
				}
			}
			held := make([]uint16, 0, cap(stack.outbound.free))
			defer func() {
				for _, slot := range held {
					stack.outbound.releaseReserved(slot)
				}
			}()
			holdOutput := func() {
				t.Helper()
				for {
					slot, reserved := stack.outbound.tryReserve()
					if !reserved {
						break
					}
					held = append(held, slot)
				}
				if len(held) != cap(stack.outbound.free) {
					t.Fatalf("reserved output slots = %d, want %d", len(held), cap(stack.outbound.free))
				}
			}
			if test.pathMTU && !test.repeated {
				holdOutput()
			}
			sacked := make(map[uint32][]byte)
			for _, segment := range segments[1:] {
				sacked[segment.SequenceNumber] = segment.Payload
			}
			link.mu.Lock()
			serverNext := link.tcp[connection.key.local.Port()].serverNext
			link.mu.Unlock()
			if err = link.deliverTCP(8080, connection.key.local.Port(), serverNext, segments[0].SequenceNumber, TCPFlagACK, 65535, testSACKOptions(sacked), nil); err != nil {
				t.Fatal(err)
			}
			wantFlight, wantPostFlight, wantBytes := uint32(0), uint32(mss), mss
			if test.pathMTU {
				waitFor(t, time.Second, func() bool { return connection.Info().FastRecovery })
				if test.repeated {
					select {
					case event := <-recorder.published:
						if event.phase != CongestionPhaseRecovery || event.flight != 0 || event.snapshot != uint32(mss) || event.bytes != mss {
							t.Fatalf("first publication = %+v, MSS %d", event, mss)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("no initial retransmission event")
					}
					wire := readOutboundPacket(t, stack)
					packet, parseErr := ParseIPPacket(wire)
					if parseErr != nil {
						t.Fatal(parseErr)
					}
					segment, parseErr := packet.TCPSegment()
					if parseErr != nil || segment.SequenceNumber != segments[0].SequenceNumber || !bytes.Equal(segment.Payload, segments[0].Payload) {
						t.Fatalf("first replacement = %+v, %v", segment, parseErr)
					}
					holdOutput()
					wantFlight = uint32(mss)
				}
				const reducedMTU = 1000
				if err = writeTestPacket(stack, buildTestPacketTooBig(link.remote, link.local, firstWire, reducedMTU)); err != nil {
					t.Fatal(err)
				}
				waitFor(t, time.Second, func() bool { return connection.Info().PathMTU == reducedMTU })
				wantBytes = connection.Info().MaximumSegmentSize
				if !test.repeated {
					wantPostFlight = uint32(wantBytes)
				}
				if info := connection.Info(); !info.FastRecovery || info.RetransmissionRecovery || info.BytesInFlight != wantFlight {
					t.Fatalf("unpublished PMTU flight = %+v, want %d", info, wantFlight)
				}
				last := len(held) - 1
				stack.outbound.releaseReserved(held[last])
				held = held[:last]
			}
			select {
			case event := <-recorder.published:
				if event.phase != CongestionPhaseRecovery || event.flight != wantFlight || event.snapshot != wantFlight+uint32(wantBytes) || event.bytes != wantBytes {
					t.Fatalf("published transmission = %+v, want flight %d bytes %d", event, wantFlight, wantBytes)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("no retransmission event")
			}
			info := connection.Info()
			if info.BytesInFlight != wantPostFlight || !info.FastRecovery || info.RetransmissionRecovery {
				t.Fatalf("post-publication flight = %+v", info)
			}
			entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
			if !available {
				t.Fatal("published retransmission did not depart")
			}
			packet, err := ParseIPPacket(consumeTestPacket(&stack.outbound, entry))
			if err != nil {
				t.Fatal(err)
			}
			segment, err := packet.TCPSegment()
			if err != nil || segment.SequenceNumber != segments[0].SequenceNumber || !bytes.Equal(segment.Payload, segments[0].Payload[:wantBytes]) {
				t.Fatalf("retransmitted range = %+v, %v", segment, err)
			}
		})
	}
}

func TestTCPBBR3RTOFlightDoesNotInflateUpperBound(t *testing.T) {
	link, stack, connection := newManuallyPumpedTCPConnection(t)
	recorder := &bbr3RTORecorder{
		algorithm: newBBR3CongestionControl(),
		published: make(chan bbr3Retransmission, 32),
		acked:     make(chan bbr3RTOAcknowledgment, 32),
	}
	base, _ := registeredCongestionControlFactory(CongestionControlBBR3)
	definition := base.definition
	definition.Name = "test-BBR3-RTO-flight"
	definition.New = func(CongestionControlContext) CongestionController { return recorder }
	factory, err := NewCongestionControlFactory(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.SetCongestionControlFactory(factory); err != nil {
		t.Fatal(err)
	}
	info := connection.Info()
	mss := info.MaximumSegmentSize
	if _, err = connection.Write(bytes.Repeat([]byte{'x'}, 4*mss)); err != nil {
		t.Fatal(err)
	}
	var originals []TCPSegment
	for len(originals) < 4 {
		entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
		if !available {
			t.Fatal("original transmission did not depart")
		}
		packet, parseErr := ParseIPPacket(consumeTestPacket(&stack.outbound, entry))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		segment, parseErr := packet.TCPSegment()
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if len(segment.Payload) != 0 {
			originals = append(originals, segment)
		}
	}
	deadline := time.NewTimer(3*info.RetransmissionTimeout + time.Second)
	defer deadline.Stop()
	var publication bbr3Retransmission
	for publication.phase != CongestionPhaseLoss {
		select {
		case publication = <-recorder.published:
			if publication.phase != CongestionPhaseLoss {
				entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
				if !available {
					t.Fatal("tail-loss probe did not depart")
				}
				consumeTestPacket(&stack.outbound, entry)
			}
		case <-deadline.C:
			t.Fatal("ordinary RTO did not publish")
		}
	}
	if publication.flight != 0 || publication.snapshot != uint32(mss) || publication.bytes != mss {
		t.Fatalf("RTO publication = %+v, want only the new %d-byte copy", publication, mss)
	}
	for {
		entry, available := waitTestPacketEntry(&stack.outbound, time.Second)
		if !available {
			t.Fatal("RTO replacement did not depart")
		}
		packet, parseErr := ParseIPPacket(consumeTestPacket(&stack.outbound, entry))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		segment, parseErr := packet.TCPSegment()
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if segment.SequenceNumber == originals[0].SequenceNumber && len(segment.Payload) != 0 {
			break
		}
	}
	link.mu.Lock()
	serverNext := link.tcp[connection.key.local.Port()].serverNext
	link.mu.Unlock()
	last := originals[len(originals)-1]
	ack := last.SequenceNumber + uint32(len(last.Payload))
	if err = link.deliverTCP(8080, connection.key.local.Port(), serverNext, ack, TCPFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case observation := <-recorder.acked:
		if observation.before != uint32(4*mss) || observation.after != observation.before || observation.snapshot != publication.snapshot || observation.acknowledged != uint32(4*mss) || observation.losses != 0 || !observation.valid {
			t.Fatalf("RTO ACK = %+v, publication %+v", observation, publication)
		}
	case <-time.After(time.Second):
		t.Fatal("ACK did not reach the BBR3 controller")
	}
	if info := connection.Info(); info.SpuriousRecoveryUndos != 0 {
		t.Fatalf("bound was restored by spurious-recovery undo: %+v", info)
	}
}

func TestTCPBBR3FRTOProbeFlight(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.111"), netip.MustParseAddr("192.0.2.112"))
	link.mu.Lock()
	link.echoTCP, link.disableTCPSACK = true, true
	link.mu.Unlock()
	dialed, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8080))
	if err != nil {
		t.Fatal(err)
	}
	connection := dialed.(*TCPConn)
	defer connection.Close()
	recorder := &bbr3RTORecorder{
		algorithm: newBBR3CongestionControl(),
		published: make(chan bbr3Retransmission, 32),
		sent:      make(chan bbr3Retransmission, 64),
		acked:     make(chan bbr3RTOAcknowledgment, 32),
	}
	base, _ := registeredCongestionControlFactory(CongestionControlBBR3)
	definition := base.definition
	definition.Name = "test-BBR3-F-RTO-flight"
	definition.New = func(CongestionControlContext) CongestionController { return recorder }
	factory, err := NewCongestionControlFactory(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.SetCongestionControlFactory(factory); err != nil {
		t.Fatal(err)
	}
	info := connection.Info()
	mss := info.MaximumSegmentSize
	link.mu.Lock()
	link.echoTCP = false
	link.outbound = make(chan []byte, 256)
	link.mu.Unlock()
	if _, err = connection.Write(bytes.Repeat([]byte{'x'}, 32*mss)); err != nil {
		t.Fatal(err)
	}
	var sequence uint32
	haveSequence := false
	deadline := time.NewTimer(3*info.RetransmissionTimeout + time.Second)
	defer deadline.Stop()
	for {
		var wire []byte
		select {
		case wire = <-link.outbound:
		case <-deadline.C:
			t.Fatal("initial flight did not reach RTO")
		}
		packet, parseErr := ParseIPPacket(wire)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		segment, parseErr := packet.TCPSegment()
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if len(segment.Payload) == 0 {
			continue
		}
		if !haveSequence {
			sequence, haveSequence = segment.SequenceNumber, true
		} else if segment.SequenceNumber == sequence && connection.Info().RetransmissionRecovery {
			break
		}
	}
	link.mu.Lock()
	serverNext := link.tcp[connection.key.local.Port()].serverNext
	link.mu.Unlock()
	if err = link.deliverTCP(8080, connection.key.local.Port(), serverNext, sequence+uint32(mss), TCPFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for probes := 0; probes < 2; {
		select {
		case event := <-recorder.sent:
			if event.phase != CongestionPhaseLoss {
				continue
			}
			if event.flight != uint32(probes*mss) || event.snapshot != uint32((probes+1)*mss) || event.bytes != mss {
				t.Fatalf("F-RTO probe %d = %+v", probes, event)
			}
			probes++
		case <-timer.C:
			t.Fatalf("F-RTO did not publish two new-data probes: probes %d info %+v", probes, connection.Info())
		}
	}
}

func TestBBR3SpeculativeSACKRetransmissionFlight(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	state := tcpEstablishedState{
		peerSACK: true, fastRecovery: true, peerMSS: mss,
		outstanding: []sentTCPSegment{
			{sequence: 100, end: 1100, state: sentTCPSegmentTransmitted},
			{sequence: 1100, end: 2100, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
		},
		controller: newTCPCongestionController(CongestionControlBBR3),
	}
	state.controller.initialize(CongestionPhaseRecovery, now, time.Millisecond, time.Millisecond, 10*mss, 10*mss, mss, 1)
	if index := firstUnretriedSACKHole(state.outstanding, 2100); index != 0 || sackSegmentLost(state.outstanding, index, mss) {
		t.Fatal("SACK hole was not eligible for RFC 6675 NextSeg rule 3")
	}
	before := state.congestionFlight()
	state.outstanding[0].advanceTransmissionGeneration()
	state.outstanding[0].state.set(sentTCPSegmentSACKRetried, true)
	after := state.congestionFlight()
	if before != mss || after != 2*mss {
		t.Fatalf("speculative replacement discarded its unproven original: flight %d -> %d", before, after)
	}
	state.controller.onRetransmit(mss, mss, now, 1, 10*mss, after, before, 2*mss, time.Millisecond, 10*mss)
	if eventFlight := state.controller.state.BytesInFlight; eventFlight != before {
		t.Fatalf("speculative event flight = %d, want %d", eventFlight, before)
	}
	if snapshot := bbr3DecodePacketState(state.controller.transmissionState()).inflight; snapshot != after {
		t.Fatalf("speculative transmission snapshot = %d, want %d", snapshot, after)
	}
}

func TestBBR3RecoveryUndoOnlyWidensBounds(t *testing.T) {
	for _, test := range []struct {
		name        string
		saved, live uint32
		want        uint32
	}{
		{name: "tightened", saved: 20_000, live: 12_000, want: 20_000},
		{name: "already wider", saved: 20_000, live: 24_000, want: 24_000},
		{name: "previously unlimited", live: 12_000},
		{name: "currently unlimited", saved: 20_000},
	} {
		t.Run(test.name, func(t *testing.T) {
			bbr := newBBR3CongestionControl()
			bbr.bandwidthLow, bbr.inflightLow, bbr.inflightHigh = float64(test.saved), test.saved, test.saved
			bbr.handleRecoveryEvent(&CongestionEvent{
				State:    &CongestionState{CongestionWindow: 24_000},
				Recovery: CongestionRecovery{Stage: CongestionRecoveryCheckpoint},
			})
			bbr.bandwidthLow, bbr.inflightLow, bbr.inflightHigh = float64(test.live), test.live, test.live
			bbr.undoRecovery(time.Unix(100, 0))
			if bbr.bandwidthLow != float64(test.want) || bbr.inflightLow != test.want || bbr.inflightHigh != test.want {
				t.Fatalf("undo bounds = %v/%d/%d, want %d", bbr.bandwidthLow, bbr.inflightLow, bbr.inflightHigh, test.want)
			}
		})
	}
}

func TestBBR3RecoveryUndoBoundsWindow(t *testing.T) {
	for _, test := range []struct {
		name                              string
		mode                              bbrMode
		phase                             bbr3ProbePhase
		exit                              bbr3UndoState
		savedHigh, liveHigh, wantHigh     uint32
		savedLow, liveLow, wantLow        uint32
		priorWindow, proposed, wantWindow uint32
		wantMode                          bbrMode
		wantPhase                         bbr3ProbePhase
	}{
		{name: "Cruise restored bound", mode: bbrProbeBandwidth, phase: bbr3ProbeCruise,
			savedHigh: 20000, liveHigh: 12000, wantHigh: 20000, priorWindow: 20000, proposed: 4000, wantWindow: 17032, wantMode: bbrProbeBandwidth, wantPhase: bbr3ProbeCruise},
		{name: "Cruise wider live bound", mode: bbrProbeBandwidth, phase: bbr3ProbeCruise,
			savedHigh: 20000, liveHigh: 24000, wantHigh: 24000, priorWindow: 20000, proposed: 4000, wantWindow: 20000, wantMode: bbrProbeBandwidth, wantPhase: bbr3ProbeCruise},
		{name: "Cruise saved unlimited", mode: bbrProbeBandwidth, phase: bbr3ProbeCruise,
			liveHigh: 12000, priorWindow: 20000, proposed: 4000, wantWindow: 20000, wantMode: bbrProbeBandwidth, wantPhase: bbr3ProbeCruise},
		{name: "Cruise live unlimited", mode: bbrProbeBandwidth, phase: bbr3ProbeCruise,
			savedHigh: 20000, priorWindow: 20000, proposed: 4000, wantWindow: 20000, wantMode: bbrProbeBandwidth, wantPhase: bbr3ProbeCruise},
		{name: "Cruise short-term bound", mode: bbrProbeBandwidth, phase: bbr3ProbeCruise,
			savedHigh: 20000, liveHigh: 12000, wantHigh: 20000, savedLow: 10000, liveLow: 6000, wantLow: 10000,
			priorWindow: 20000, proposed: 4000, wantWindow: 10000, wantMode: bbrProbeBandwidth, wantPhase: bbr3ProbeCruise},
		{name: "Cruise minimum cap", mode: bbrProbeBandwidth, phase: bbr3ProbeCruise,
			savedHigh: 2000, liveHigh: 1000, wantHigh: 2000, savedLow: 1000, liveLow: 500, wantLow: 1000,
			priorWindow: 20000, proposed: 4000, wantWindow: 4000, wantMode: bbrProbeBandwidth, wantPhase: bbr3ProbeCruise},
		{name: "Cruise one MSS headroom", mode: bbrProbeBandwidth, phase: bbr3ProbeCruise,
			savedHigh: 6000, liveHigh: 5000, wantHigh: 6000, priorWindow: 6000, proposed: 4000, wantWindow: 5000, wantMode: bbrProbeBandwidth, wantPhase: bbr3ProbeCruise},
		{name: "Cruise smaller restored window", mode: bbrProbeBandwidth, phase: bbr3ProbeCruise,
			savedHigh: 20000, liveHigh: 12000, wantHigh: 20000, priorWindow: 4000, proposed: 6000, wantWindow: 6000, wantMode: bbrProbeBandwidth, wantPhase: bbr3ProbeCruise},
		{name: "Down", mode: bbrProbeBandwidth, phase: bbr3ProbeDown,
			savedHigh: 20000, liveHigh: 12000, wantHigh: 20000, priorWindow: 24000, proposed: 4000, wantWindow: 20000, wantMode: bbrProbeBandwidth, wantPhase: bbr3ProbeDown},
		{name: "Up", mode: bbrProbeBandwidth, phase: bbr3ProbeUp,
			savedHigh: 20000, liveHigh: 12000, wantHigh: 20000, priorWindow: 24000, proposed: 4000, wantWindow: 20000, wantMode: bbrProbeBandwidth, wantPhase: bbr3ProbeUp},
		{name: "Refill after probe undo", mode: bbrProbeBandwidth, phase: bbr3ProbeCruise, exit: bbr3UndoProbeUp,
			savedHigh: 20000, liveHigh: 12000, wantHigh: 20000, savedLow: 10000, liveLow: 6000,
			priorWindow: 24000, proposed: 4000, wantWindow: 20000, wantMode: bbrProbeBandwidth, wantPhase: bbr3ProbeRefill},
		{name: "Startup after loss undo", mode: bbrProbeBandwidth, phase: bbr3ProbeCruise, exit: bbr3UndoStartup,
			savedHigh: 20000, liveHigh: 12000, wantHigh: 20000, priorWindow: 24000, proposed: 4000, wantWindow: 24000, wantMode: bbrStartup, wantPhase: bbr3ProbeCruise},
		{name: "Startup short-term bound", mode: bbrStartup,
			savedHigh: 6000, liveHigh: 5000, wantHigh: 6000, savedLow: 10000, liveLow: 6000, wantLow: 10000,
			priorWindow: 20000, proposed: 4000, wantWindow: 10000, wantMode: bbrStartup},
		{name: "Drain", mode: bbrDrain,
			savedHigh: 6000, liveHigh: 5000, wantHigh: 6000, priorWindow: 20000, proposed: 4000, wantWindow: 20000, wantMode: bbrDrain},
		{name: "ProbeRTT target", mode: bbrProbeRTT, phase: bbr3ProbeCruise, exit: bbr3UndoProbeUp,
			savedHigh: 20000, liveHigh: 12000, wantHigh: 20000, priorWindow: 20000, proposed: 4000, wantWindow: 5000, wantMode: bbrProbeRTT, wantPhase: bbr3ProbeCruise},
		{name: "ProbeRTT model bound", mode: bbrProbeRTT, phase: bbr3ProbeCruise,
			savedHigh: 2000, liveHigh: 1000, wantHigh: 2000, priorWindow: 20000, proposed: 4000, wantWindow: 4000, wantMode: bbrProbeRTT, wantPhase: bbr3ProbeCruise},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Unix(100, 0)
			bbr := newBBR3CongestionControl()
			bbr.inflightHigh, bbr.inflightLow = test.savedHigh, test.savedLow
			bbr.minimumRTT, bbr.bandwidthHigh[1] = 10*time.Millisecond, 1000000
			bbr.fullBandwidthReached = true
			state := CongestionState{CongestionWindow: test.priorWindow, MaximumSegmentSize: 1000, SmoothedRTT: 20 * time.Millisecond}
			event := CongestionEvent{Type: CongestionEventRecovery, State: &state, Time: now, Recovery: CongestionRecovery{Stage: CongestionRecoveryCheckpoint}}
			bbr.HandleCongestionEvent(&event)
			bbr.mode, bbr.probePhase, bbr.undoState = test.mode, test.phase, test.exit
			bbr.inflightHigh, bbr.inflightLow = test.liveHigh, test.liveLow
			state.CongestionWindow = test.proposed
			event.Recovery.Stage = CongestionRecoveryUndo
			bbr.HandleCongestionEvent(&event)
			if state.CongestionWindow != test.wantWindow || bbr.priorWindow != test.priorWindow {
				t.Fatalf("undo window = %d, saved %d; want %d, saved %d", state.CongestionWindow, bbr.priorWindow, test.wantWindow, test.priorWindow)
			}
			if bbr.mode != test.wantMode || bbr.probePhase != test.wantPhase || bbr.inflightHigh != test.wantHigh || bbr.inflightLow != test.wantLow {
				t.Fatalf("undo model = %s/%s high %d low %d; want %s/%s high %d low %d", bbr.mode, bbr.probePhase, bbr.inflightHigh, bbr.inflightLow, test.wantMode, test.wantPhase, test.wantHigh, test.wantLow)
			}
			if bbr.undoBounds || bbr.undoState != bbr3UndoNone {
				t.Fatal("undo retained a consumed checkpoint")
			}
		})
	}
}

func BenchmarkBBR3RecoveryUndo(b *testing.B) {
	for _, test := range []struct {
		name string
		mode bbrMode
		high uint32
		exit bbr3UndoState
	}{
		{name: "Cruise", mode: bbrProbeBandwidth, high: 20000},
		{name: "unlimited", mode: bbrProbeBandwidth},
		{name: "Refill", mode: bbrProbeBandwidth, high: 20000, exit: bbr3UndoProbeUp},
		{name: "ProbeRTT", mode: bbrProbeRTT, high: 20000},
	} {
		b.Run(test.name, func(b *testing.B) {
			model := newBBR3CongestionControl()
			model.minimumRTT, model.bandwidthHigh[1] = 10*time.Millisecond, 1000000
			model.fullBandwidthReached = true
			state := CongestionState{MaximumSegmentSize: 1000, SmoothedRTT: 20 * time.Millisecond}
			event := CongestionEvent{Type: CongestionEventRecovery, State: &state, Time: time.Unix(100, 0)}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				model.mode, model.probePhase, model.inflightHigh = bbrProbeBandwidth, bbr3ProbeDown, test.high
				state.CongestionWindow = 20000
				event.Recovery.Stage = CongestionRecoveryCheckpoint
				model.HandleCongestionEvent(&event)
				model.mode, model.probePhase, model.undoState = test.mode, bbr3ProbeCruise, test.exit
				if test.high != 0 {
					model.inflightHigh = 12000
				}
				state.CongestionWindow = 4000
				event.Recovery.Stage = CongestionRecoveryUndo
				model.HandleCongestionEvent(&event)
			}
			b.StopTimer()
			if model.undoBounds || model.undoState != bbr3UndoNone || model.priorWindow != 20000 || state.CongestionWindow == 0 {
				b.Fatal("benchmark did not complete a valid recovery undo")
			}
		})
	}
}

type bbr3UndoRecorder struct {
	algorithm   *bbr3CongestionControl
	checkpoints int
	losses      []uint64
	flights     []uint32
	missing     bool
	probeExitAt uint64
}

func (r *bbr3UndoRecorder) HandleCongestionEvent(event *CongestionEvent) {
	if event.Type == CongestionEventRecovery && event.Recovery.Stage == CongestionRecoveryCheckpoint {
		r.checkpoints++
	}
	if event.Type == CongestionEventPacketLost {
		r.missing = r.missing || r.checkpoints == 0
		r.losses = append(r.losses, event.State.LostBytes)
		r.flights = append(r.flights, event.State.BytesInFlight)
	}
	probing := r.algorithm.probeSamples
	r.algorithm.HandleCongestionEvent(event)
	if event.Type == CongestionEventPacketLost && probing && !r.algorithm.probeSamples {
		r.probeExitAt = event.State.LostBytes
	}
}

func TestTCPBBR3RecoveryEntryBeforeLossCallbacks(t *testing.T) {
	for _, test := range []struct {
		name        string
		recovery    bool
		replacement int
	}{
		{name: "IsLost before DupThresh", replacement: -1},
		{name: "replacement after first hole", recovery: true, replacement: 1},
		{name: "replacement at first hole", recovery: true, replacement: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			const mss = 1000
			now := time.Unix(100, 0)
			epoch := now.Add(-time.Second)
			connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
			connection.stack = &Stack{timestampEpoch: epoch}
			state := tcpEstablishedState{
				connection: connection, controller: newTCPCongestionController(CongestionControlBBR3),
				peerMSS: mss, peerSACK: true, peerWindow: 40_000,
				sendUnacknowledged: 100, sendNext: 6100,
				congestionWindow: 20_000, slowStartThreshold: 30_000,
				fastRecovery: test.recovery, recoveryPoint: 6100, prrPriorFlight: 6000,
				rackReorderingSeen: true, rtt: newRTTEstimator(time.Second),
				outstanding: make([]sentTCPSegment, 6),
			}
			state.controller.initialize(CongestionPhaseOpen, epoch, time.Millisecond, time.Millisecond, state.congestionWindow, state.slowStartThreshold, mss, 1)
			defer state.controller.release(now, state.congestionWindow, state.slowStartThreshold, state.congestionFlight(), mss, state.rtt.srtt, state.rtt.minimum)
			algorithm := state.controller.algorithm.(*bbr3CongestionControl)
			algorithm.inflightHigh = 20_000
			recorder := &bbr3UndoRecorder{algorithm: algorithm}
			state.controller.algorithm = recorder
			for index := range state.outstanding {
				state.outstanding[index] = sentTCPSegment{
					sequence: uint32(100 + index*mss), end: uint32(100 + (index+1)*mss),
					state:     sentTCPSegmentTransmitted,
					hostQueue: testPacketQueueTicketAt(epoch, now.Add(-100*time.Millisecond)),
					delivery:  tcpDeliverySnapshot{deliveredStamp: 1},
				}
			}
			if test.replacement >= 0 {
				for index := 0; index < 2; index++ {
					state.outstanding[index].hostQueue = testPacketQueueTicketAt(epoch, now.Add(-200*time.Millisecond))
				}
				state.outstanding[test.replacement].advanceTransmissionGeneration()
				state.outstanding[test.replacement].state |= sentTCPSegmentSACKRetried | sentTCPSegmentOriginalLost
				state.controller.setCongestionPhase(CongestionPhaseRecovery, now)
			}
			state.rebaseOutstanding()
			var options [10]byte
			options[0], options[1] = TCPHeaderOptionSACK, 10
			binary.BigEndian.PutUint32(options[2:6], 2100)
			binary.BigEndian.PutUint32(options[6:10], 6100)
			segment := tcpSegment{acknowledgement: 100, flags: TCPFlagACK, window: 40_000}
			segment.setOptions(options[:])
			state.processAcknowledgment(&segment, now, 0)
			if !state.fastRecovery || state.undo == nil || !state.undo.active || recorder.checkpoints != 1 || recorder.missing || len(recorder.losses) != 2 || algorithm.undoInflightHigh != 20_000 {
				t.Fatalf("recovery entry: active %t undo %+v checkpoints %d missing %t losses %v saved bound %d", state.fastRecovery, state.undo, recorder.checkpoints, recorder.missing, recorder.losses, algorithm.undoInflightHigh)
			}
			if !test.recovery && (state.duplicateACKs >= tcpDuplicateACKThreshold || state.haveRACKLoss) {
				t.Fatal("fixture did not enter through IsLost before DupThresh")
			}
			if test.recovery && (state.undo.transport == nil || !state.undo.transport.fastRecovery) {
				t.Fatal("new replacement loss did not checkpoint the previous recovery")
			}
			state.processAcknowledgment(&segment, now, 0)
			if recorder.checkpoints != 1 || len(recorder.losses) != 2 {
				t.Fatal("unchanged loss evidence restarted recovery or reported a generation twice")
			}
		})
	}
}

func TestTCPBBR3UndoRestoresModel(t *testing.T) {
	for _, test := range []struct {
		name    string
		timeout bool
		viaACK  bool
		frto    bool
		lossAt  int
	}{
		{name: "RACK"},
		{name: "RTO", timeout: true},
		{name: "RTO middle probe loss", timeout: true, lossAt: 1},
		{name: "RTO last probe loss", timeout: true, lossAt: 3},
		{name: "RACK DSACK", viaACK: true},
		{name: "RTO DSACK", timeout: true, viaACK: true},
		{name: "RTO F-RTO", timeout: true, viaACK: true, frto: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			timeout := test.timeout
			const mss = 1000
			now := time.Unix(100, 0)
			epoch := now.Add(-2 * time.Second)
			connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
			connection.stack = &Stack{timestampEpoch: epoch}
			state := tcpEstablishedState{
				connection: connection,
				controller: newTCPCongestionController(CongestionControlBBR3),
				peerMSS:    mss, peerSACK: true, peerWindow: 40_000,
				sendUnacknowledged: 100, sendNext: 4100,
				congestionWindow: 20_000, slowStartThreshold: 30_000,
				rtt:         newRTTEstimator(time.Second),
				outstanding: make([]sentTCPSegment, 4),
			}
			state.controller.initialize(CongestionPhaseOpen, epoch, time.Millisecond, time.Millisecond, state.congestionWindow, state.slowStartThreshold, mss, 1)
			algorithm := state.controller.algorithm.(*bbr3CongestionControl)
			algorithm.mode, algorithm.probePhase = bbrProbeBandwidth, bbr3ProbeUp
			algorithm.ackPhase, algorithm.probeSamples = bbr3ACKsProbeFeedback, true
			algorithm.fullBandwidthReached = true
			algorithm.minimumRTT = 5 * time.Millisecond
			algorithm.bandwidthHigh[1] = 1_000_000
			initialHigh := uint32(20_000)
			if test.lossAt != 0 {
				initialHigh = 200_000
			}
			algorithm.bandwidthLow, algorithm.inflightLow, algorithm.inflightHigh = 800_000, 16_000, initialHigh
			packetState := CongestionState{BytesInFlight: uint32(10_000 + test.lossAt*50_000)}
			for i := range state.outstanding {
				state.outstanding[i] = sentTCPSegment{
					sequence: uint32(100 + i*mss), end: uint32(100 + (i+1)*mss),
					state:                 sentTCPSegmentTransmitted,
					hostQueue:             testPacketQueueTicketAt(epoch, now.Add(-time.Second)),
					delivery:              tcpDeliverySnapshot{deliveredStamp: 1},
					congestionPacketState: bbr3EncodePacketState(&packetState, mss),
				}
			}
			recorder := &bbr3UndoRecorder{algorithm: algorithm}
			state.controller.algorithm = recorder
			if !timeout {
				for i := range state.outstanding {
					state.outstanding[i].state |= sentTCPSegmentRACKLost | sentTCPSegmentOriginalLost
				}
				markProvenTCPLosses(state.outstanding, mss, false)
				if state.controller.state.LostBytes != 0 || state.undo != nil {
					t.Fatal("marking loss notified the controller before recovery entry")
				}
			}
			state.prepareRetransmission(0, timeout, !timeout, true, false, 0, now)
			if recorder.missing || recorder.checkpoints != 1 || len(recorder.losses) != 4 {
				t.Fatalf("loss event ordering = missing %t checkpoints %d losses %v", recorder.missing, recorder.checkpoints, recorder.losses)
			}
			for i, lost := range recorder.losses {
				if lost != uint64((i+1)*mss) || recorder.flights[i] != recorder.flights[0] {
					t.Fatalf("per-packet loss/flight = %v/%v", recorder.losses, recorder.flights)
				}
			}
			if algorithm.inflightHigh >= initialHigh || algorithm.probePhase != bbr3ProbeDown || algorithm.undoInflightHigh != initialHigh || recorder.probeExitAt != uint64((test.lossAt+1)*mss) {
				t.Fatalf("loss model: live %d saved %d phase %s, probe exit at loss %d, want %d", algorithm.inflightHigh, algorithm.undoInflightHigh, algorithm.probePhase, recorder.probeExitAt, (test.lossAt+1)*mss)
			}
			algorithm.saveWindow(state.congestionWindow)
			algorithm.nextSend = now.Add(3 * time.Millisecond)
			algorithm.pacingWakeDeadline = algorithm.nextSend
			algorithm.pacingBurstRemaining = mss
			state.pacing, state.pacingDeadline = true, algorithm.nextSend
			if test.viaACK {
				state.undo.recordRetransmission(100, 1100, 10, false)
				state.recordRetransmission(100, 1100)
				state.outstanding[0].advanceTransmissionGeneration()
				state.rebaseOutstanding()
				if !test.frto {
					state.frtoState = tcpFRTOInactive
					first := tcpSegment{acknowledgement: 1100, flags: TCPFlagACK, window: 40_000}
					state.processAcknowledgment(&first, now.Add(time.Millisecond), 0)
					if state.undo.spuriousUndos != 0 {
						t.Fatal("ordinary ACK undid recovery without spurious evidence")
					}
				} else {
					state.frtoState = tcpFRTOProbeSent
				}
				var options [10]byte
				options[0], options[1] = TCPHeaderOptionSACK, 10
				binary.BigEndian.PutUint32(options[2:6], 100)
				binary.BigEndian.PutUint32(options[6:10], 1100)
				segment := tcpSegment{acknowledgement: 4100, flags: TCPFlagACK, window: 40_000}
				if !test.frto {
					segment.setOptions(options[:])
				}
				state.processAcknowledgment(&segment, now.Add(2*time.Millisecond), 0)
				if !test.frto && !state.seenDSACK || !state.deliverySample.valid || state.deliverySample.losses != 0 || state.fastRecovery || state.rtoRecovery {
					t.Fatalf("ACK did not complete recovery through a valid delivery sample: %+v", state.deliverySample)
				}
			} else if !state.restoreSpuriousRecovery(now.Add(time.Millisecond), 0) {
				t.Fatal("transport undo failed")
			}
			if algorithm.inflightHigh < initialHigh || algorithm.mode != bbrProbeBandwidth || algorithm.probePhase != bbr3ProbeRefill && !(test.viaACK && algorithm.probePhase == bbr3ProbeUp) || algorithm.previousProbeTooHigh {
				t.Fatalf("undo model = high %d phase %s previous-high %t samples %t", algorithm.inflightHigh, algorithm.probePhase, algorithm.previousProbeTooHigh, algorithm.probeSamples)
			}
			if algorithm.bandwidthLow != 0 || algorithm.inflightLow != 0 {
				t.Fatal("REFILL did not reset lower bounds")
			}
			if state.controller.state.LostBytes != 4*mss || state.undo.spuriousUndos != 1 {
				t.Fatal("undo changed lifetime loss accounting")
			}
			if state.pacing || !state.pacingDeadline.IsZero() || !algorithm.pacingWakeDeadline.IsZero() || !algorithm.nextSend.Equal(now.Add(3*time.Millisecond)) || algorithm.pacingBurstRemaining != mss {
				t.Fatal("undo retained a stale wake or changed published-transmission pacing credit")
			}
		})
	}
}

func TestBBR3UndoLossInducedExit(t *testing.T) {
	for _, test := range []struct {
		name      string
		mode      bbrMode
		exit      bbr3UndoState
		wantMode  bbrMode
		wantPhase bbr3ProbePhase
		wantFull  bool
	}{
		{name: "Startup loss", mode: bbrDrain, exit: bbr3UndoStartup, wantMode: bbrStartup, wantPhase: bbr3ProbeDown},
		{name: "normal Startup exit", mode: bbrDrain, wantMode: bbrDrain, wantPhase: bbr3ProbeDown, wantFull: true},
		{name: "UP loss", mode: bbrProbeBandwidth, exit: bbr3UndoProbeUp, wantMode: bbrProbeBandwidth, wantPhase: bbr3ProbeRefill, wantFull: true},
		{name: "normal UP exit", mode: bbrProbeBandwidth, wantMode: bbrProbeBandwidth, wantPhase: bbr3ProbeDown, wantFull: true},
		{name: "ProbeRTT after Startup loss", mode: bbrProbeRTT, exit: bbr3UndoStartup, wantMode: bbrProbeRTT, wantPhase: bbr3ProbeDown},
		{name: "ProbeRTT after UP loss", mode: bbrProbeRTT, exit: bbr3UndoProbeUp, wantMode: bbrProbeRTT, wantPhase: bbr3ProbeDown, wantFull: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			bbr := newBBR3CongestionControl()
			bbr.mode, bbr.probePhase, bbr.undoState = test.mode, bbr3ProbeDown, test.exit
			bbr.fullBandwidthReached = true
			bbr.fullBandwidth, bbr.fullRounds = 100_000, 3
			bbr.undoRecovery(time.Unix(100, 0))
			if bbr.mode != test.wantMode || bbr.probePhase != test.wantPhase || bbr.fullBandwidthReached != test.wantFull || bbr.undoState != bbr3UndoNone {
				t.Fatalf("undo phase = %s/%s full %t undo %d", bbr.mode, bbr.probePhase, bbr.fullBandwidthReached, bbr.undoState)
			}
			if bbr.fullBandwidth != 0 || bbr.fullRounds != 0 {
				t.Fatal("full-bandwidth detector was not reset")
			}
		})
	}
}

func TestBBR3UndoClearsProbeLossHistory(t *testing.T) {
	for _, phase := range []string{"ProbeRTT", "new UP"} {
		for _, undo := range []bool{false, true} {
			name := phase
			if undo {
				name += " undo"
			}
			t.Run(name, func(t *testing.T) {
				now := time.Unix(100, 0)
				bbr := newBBR3CongestionControl()
				bbr.mode, bbr.probePhase = bbrProbeBandwidth, bbr3ProbeUp
				bbr.fullBandwidthReached = true
				bbr.bandwidthHigh[1] = 1_000_000
				bbr.minimumRTT = 5 * time.Millisecond
				bbr.inflightHigh = 20_000
				bbr.handleRecoveryEvent(&CongestionEvent{
					State:    &CongestionState{CongestionWindow: 24_000},
					Recovery: CongestionRecovery{Stage: CongestionRecoveryCheckpoint},
				})
				bbr.handleInflightTooHigh(10_000, false, 24_000, 1000, now)
				if !bbr.previousProbeTooHigh || bbr.undoState != bbr3UndoProbeUp || bbr.probePhase != bbr3ProbeDown || bbr.inflightHigh >= 20_000 {
					t.Fatal("loss did not terminate UP and tighten the model")
				}
				if phase == "ProbeRTT" {
					bbr.mode = bbrProbeRTT
				} else {
					bbr.enterProbePhase(bbr3ProbeRefill, now.Add(time.Second))
					bbr.enterProbePhase(bbr3ProbeUp, now.Add(2*time.Second))
					bbr.probeUpACKed = 1000
					bbr.ackPhase = bbr3ACKsProbeStarting
				}
				if undo {
					bbr.undoRecovery(now.Add(3 * time.Second))
					if bbr.inflightHigh != 20_000 || bbr.undoState != bbr3UndoNone {
						t.Fatal("undo did not restore the model and consume its checkpoint")
					}
				}
				if phase == "ProbeRTT" {
					if bbr.mode != bbrProbeRTT {
						t.Fatal("undo interrupted ProbeRTT")
					}
					bbr.exitProbeRTT(now.Add(4 * time.Second))
					bbr.enterProbePhase(bbr3ProbeRefill, now.Add(5*time.Second))
					bbr.enterProbePhase(bbr3ProbeUp, now.Add(6*time.Second))
				} else if bbr.mode != bbrProbeBandwidth || bbr.probePhase != bbr3ProbeUp || bbr.probeUpACKed != 1000 || bbr.ackPhase != bbr3ACKsProbeStarting {
					t.Fatal("undo restarted an already active UP phase")
				}
				sample := &tcpDeliveryRateSample{ackTime: now.Add(7 * time.Second), priorInFlight: 20_000}
				bbr.updateProbeBandwidth(sample, bbr3PacketSnapshot{}, 1_000_000, 24_000, 1000)
				wantPhase := bbr3ProbeDown
				if undo {
					wantPhase = bbr3ProbeUp
				}
				if bbr.probePhase != wantPhase || bbr.stoppedRiskyProbe == undo || bbr.previousProbeTooHigh {
					t.Fatalf("subsequent probe = %s previous-high %t stopped-risky %t, want phase %s undo %t", bbr.probePhase, bbr.previousProbeTooHigh, bbr.stoppedRiskyProbe, wantPhase, undo)
				}
			})
		}
	}
}

func TestTCPBBR3TransfersAndRecoversLoss(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.188")
	remote := netip.MustParseAddr("192.0.2.189")
	link, stack := newTestStack(t, local, remote)
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.sackTCP = true
	link.delayTCPACK = 100 * time.Microsecond
	link.dropTCPOrdinals = map[int]bool{3: true, 7: true}
	link.mu.Unlock()
	if err := stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		TCP:            TCPSocketDefaults{CongestionControl: CongestionControlBBR3},
	}); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 8388))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	writeAndReadTCPEcho(t, connection, make([]byte, 128*1024))
	info := connection.(*TCPConn).Info()
	if info.CongestionControl != CongestionControlBBR3 || info.DeliveryRate == 0 || info.PacingRate == 0 || info.CongestionWindow >= tcpMaximumScaledWindow {
		t.Fatalf("BBRv3 connection info = %+v", info)
	}
	if stack.Stats().TCPSACKRetransmissions < 2 {
		t.Fatalf("BBRv3 SACK retransmissions = %d", stack.Stats().TCPSACKRetransmissions)
	}
}

func TestTCPBBR3ImpairmentMatrix(t *testing.T) {
	tests := []struct {
		name      string
		condition testLinkCondition
	}{
		{name: "high-delay-jitter", condition: testLinkCondition{Latency: 50 * time.Millisecond, Jitter: 15 * time.Millisecond}},
		{name: "random-loss", condition: testLinkCondition{Latency: 2 * time.Millisecond, LossRate: 0.08}},
		{name: "burst-loss", condition: testLinkCondition{Latency: 2 * time.Millisecond, BurstEnterRate: 0.04, BurstExitRate: 0.35}},
		{name: "delay-and-loss", condition: testLinkCondition{Latency: 50 * time.Millisecond, Jitter: 15 * time.Millisecond, LossRate: 0.08, BurstEnterRate: 0.02, BurstExitRate: 0.4}},
		{name: "narrow-queue", condition: testLinkCondition{Latency: 3 * time.Millisecond, Bandwidth: 256 * 1024, QueueBytes: 16 * 1024}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, server, _ := newTestTCPConnectionPair(t, CongestionControlBBR3, testLinkConditions{
				Seed: 9917, ClientToPeer: test.condition, PeerToClient: test.condition,
			})
			transferTestTCPPayload(t, client, server, 96*1024, 20*time.Second)
			if info := client.Info(); info.CongestionWindow == 0 || info.CongestionWindow >= tcpMaximumScaledWindow {
				t.Fatalf("BBRv3 impaired connection info = %+v", info)
			}
		})
	}
}

func TestTCPBBR3IPv6FullDuplexUnderAsymmetricImpairment(t *testing.T) {
	clientAddress := netip.MustParseAddr("2001:db8::301")
	serverAddress := netip.MustParseAddr("2001:db8::302")
	client, server, link := newTestTCPConnectionPairForAddresses(t, CongestionControlBBR3, testLinkConditions{
		Seed: 4811,
		ClientToPeer: testLinkCondition{
			Latency: 30 * time.Millisecond, Jitter: 8 * time.Millisecond, LossRate: 0.06,
			BurstEnterRate: 0.01, BurstExitRate: 0.5, Bandwidth: 1024 * 1024, QueueBytes: 48 * 1024,
		},
		PeerToClient: testLinkCondition{
			Latency: 5 * time.Millisecond, Jitter: 2 * time.Millisecond, LossRate: 0.04,
			DuplicateRate: 0.03, Bandwidth: 2 * 1024 * 1024, QueueBytes: 64 * 1024,
		},
	}, clientAddress, serverAddress)
	results := make(chan error, 2)
	go func() { results <- exchangeTestTCPPayload(client, server, 128*1024, 20*time.Second, 0x33333333) }()
	go func() { results <- exchangeTestTCPPayload(server, client, 128*1024, 20*time.Second, 0x44444444) }()
	for direction := 0; direction < 2; direction++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	clientStats, serverStats := link.Stats(0), link.Stats(1)
	if clientStats.RandomDrops == 0 || serverStats.RandomDrops == 0 {
		t.Fatalf("BBRv3 IPv6 impairment was not exercised: client=%+v server=%+v", clientStats, serverStats)
	}
}
