package mipstack

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

const (
	synCookiePeriod = 64 * time.Second
	synCookieDataBits = 8
	synCookieDataMask = uint32(1<<synCookieDataBits - 1)
)

var synCookieMSSValues = [...]uint16{tcpMinimumPeerMSS, 256, 536, 1200, 1220, 1360, 1440, 8960}

type synCookieOptions struct {
	mss              int
	windowScale      uint8
	localWindowScale uint8
	windowScaling    bool
	sack             bool
	timestamp        bool
	ecn              bool
	timestampNow     uint32
}

func (state *tcpPassiveState) synCookieKey(now time.Time) ([16]byte, uint64, error) {
	state.cookieMu.Lock()
	defer state.cookieMu.Unlock()
	if !state.cookieSet {
		if _, err := rand.Read(state.cookieKey[:]); err != nil {
			return [16]byte{}, 0, err
		}
		state.cookieEpoch = now
		state.cookieSet = true
	}
	period := synCookiePeriodNumber(now, state.cookieEpoch)
	return state.cookieKey, period, nil
}

func (state *tcpPassiveState) noteSYNCookie(period uint64) {
	state.cookieMu.Lock()
	if !state.cookieActive || period > state.cookiePeriod {
		state.cookiePeriod = period
	}
	state.cookieActive = true
	state.cookieMu.Unlock()
}

func (state *tcpPassiveState) recentSYNCookieState(now time.Time) ([16]byte, uint64, bool) {
	state.cookieMu.Lock()
	defer state.cookieMu.Unlock()
	period := synCookiePeriodNumber(now, state.cookieEpoch)
	if !state.cookieSet || !state.cookieActive || period < state.cookiePeriod || period-state.cookiePeriod > 1 {
		return [16]byte{}, 0, false
	}
	return state.cookieKey, period, true
}

func (state *tcpPassiveState) sendSYNCookie(stack *Stack, listener *TCPListener, key tcpKey, syn tcpSegment, now time.Time) error {
	defaults := stack.network.Load().tcpDefaults
	if listener != nil {
		defaults = applyTCPSocketOptions(defaults, listener.options)
	}
	configuredScale := tcpReceiveWindowScaleFor(defaults.MaximumReceiveBuffer)
	secret, period, err := state.synCookieKey(now)
	if err != nil {
		return err
	}
	options, data := encodeSYNCookieOptions(syn, key.remote.Addr())
	authenticatedData := synCookieAuthenticatedData(data, options.timestamp, options.ecn)
	var generation uint64
	if listener != nil {
		generation = listener.cookieGeneration
	}
	sequence := synCookieSequence(secret, key, generation, syn.sequence, period, data, authenticatedData)
	localMSS := tcpMSSForMTU(stack.mtuFor(key.remote.Addr()), key.local.Addr())
	if localMSS < 1 {
		return errors.New("mipstack: MTU is too small for TCP")
	}
	timestamp := stack.tcpTimestamp()
	if options.timestamp {
		timestamp = synCookieTimestamp(timestamp, options.ecn)
	}
	var optionStorage [40]byte
	advertisedScale := configuredScale
	if listener != nil {
		advertisedScale = listener.recordSYNCookieScale(period, configuredScale)
	}
	tcpOptions := tcpPassiveSYNOptions(optionStorage[:0], localMSS, options.sack, options.windowScaling, options.timestamp, advertisedScale, timestamp, options.timestampNow)
	flags := byte(TCPFlagSYN | TCPFlagACK)
	if options.ecn {
		flags |= TCPFlagECE
	}
	receiveWindow := defaults.ReceiveBuffer
	if receiveWindow > 65535 {
		receiveWindow = 65535
	}
	state.noteSYNCookie(period)
	flowLabelSet := listener != nil && listener.options.flowLabel.set
	return stack.tryWriteTCPControl(key.local.Addr(), key.remote.Addr(), key.local.Port(), key.remote.Port(), sequence, syn.sequence+1, flags, uint16(receiveWindow), tcpOptions, nil, stack.mtuFor(key.remote.Addr()), defaults.TrafficClass, 0, defaults.FlowLabel, flowLabelSet, outputFlowKey{})
}

func synCookieTimestamp(raw uint32, ecn bool) uint32 {
	timestamp := raw &^ 1
	if ecn {
		timestamp |= 1
	}
	if tcpSequenceGreater(timestamp, raw) {
		timestamp -= 2
	}
	return timestamp
}

func (state *tcpPassiveState) validateSYNCookie(key tcpKey, ack tcpSegment, now time.Time, listener *TCPListener) (uint32, synCookieOptions, bool, bool) {
	if ack.flags&TCPFlagACK == 0 || ack.flags&(TCPFlagSYN|TCPFlagRST) != 0 {
		return 0, synCookieOptions{}, false, false
	}
	secret, period, active := state.recentSYNCookieState(now)
	if !active {
		return 0, synCookieOptions{}, false, false
	}
	serverSequence := ack.acknowledgement - 1
	clientSequence := ack.sequence - 1
	data := serverSequence & synCookieDataMask
	timestampValue, timestampEcho, timestampPresent := parseTCPTimestamp(ack.optionBytes())
	var candidates [3]struct{ timestamp, ecn bool }
	candidateCount := 1
	if timestampPresent {
		candidates[0] = struct{ timestamp, ecn bool }{timestamp: true, ecn: timestampEcho&1 != 0}
		if timestampEcho == 0 {
			candidates[0] = struct{ timestamp, ecn bool }{timestamp: true, ecn: true}
			candidates[1] = struct{ timestamp, ecn bool }{timestamp: true}
			candidateCount = 2
		}
	} else {
		candidates[0] = struct{ timestamp, ecn bool }{timestamp: true, ecn: true}
		candidates[1] = struct{ timestamp, ecn bool }{timestamp: true}
		candidates[2] = struct{ timestamp, ecn bool }{}
		candidateCount = len(candidates)
	}
	valid := false
	matchedTimestamp, matchedECN := false, false
	matchedPeriod := uint64(0)
	var generation uint64
	if listener != nil {
		generation = listener.cookieGeneration
	}
	for attempt := uint64(0); attempt < 2; attempt++ {
		if attempt > period {
			break
		}
		candidatePeriod := period - attempt
		for candidateIndex := 0; candidateIndex < candidateCount; candidateIndex++ {
			candidate := candidates[candidateIndex]
			authenticatedData := synCookieAuthenticatedData(data, candidate.timestamp, candidate.ecn)
			expected := synCookieSequence(secret, key, generation, clientSequence, candidatePeriod, data, authenticatedData)
			if subtle.ConstantTimeEq(int32(expected), int32(serverSequence)) == 1 {
				valid = true
				matchedTimestamp = candidate.timestamp
				matchedECN = candidate.ecn
				matchedPeriod = candidatePeriod
			}
		}
	}
	if !valid {
		return 0, synCookieOptions{}, false, true
	}
	options, ok := decodeSYNCookieOptions(data)
	if !ok {
		return 0, synCookieOptions{}, false, true
	}
	options.timestamp = timestampPresent && matchedTimestamp
	if options.timestamp {
		options.timestampNow = timestampValue
	}
	options.ecn = timestampPresent && matchedECN
	if listener != nil && options.windowScaling {
		localScale, ok := listener.lookupSYNCookieScale(matchedPeriod)
		if !ok {
			return 0, synCookieOptions{}, false, true
		}
		options.localWindowScale = localScale
	}
	if !timestampPresent {
		options.sack = false
		options.windowScaling = false
		options.windowScale = 0
		options.localWindowScale = 0
	}
	return serverSequence, options, true, true
}

func encodeSYNCookieOptions(syn tcpSegment, remoteAddress netip.Addr) (synCookieOptions, uint32) {
	mss, scale, scaling, sack, timestamp, timestampValue := parseTCPOptions(syn.optionBytes(), defaultTCPPeerMSS(remoteAddress), 65535)
	if !timestamp {
		scale, scaling, sack = 0, false, false
	}
	mssIndex := 0
	for index, value := range synCookieMSSValues {
		if int(value) > mss {
			break
		}
		mssIndex = index
	}
	encodedScale := uint32(15)
	if scaling {
		encodedScale = uint32(scale)
	}
	data := uint32(mssIndex) | encodedScale<<3
	if sack {
		data |= 1 << 7
	}
	ecn := timestamp && syn.flags&(TCPFlagECE|TCPFlagCWR) == TCPFlagECE|TCPFlagCWR
	return synCookieOptions{
		mss: int(synCookieMSSValues[mssIndex]), windowScale: scale, windowScaling: scaling,
		sack: sack, timestamp: timestamp, ecn: ecn, timestampNow: timestampValue,
	}, data
}

func decodeSYNCookieOptions(data uint32) (synCookieOptions, bool) {
	if data & ^synCookieDataMask != 0 {
		return synCookieOptions{}, false
	}
	mssIndex := int(data & 7)
	encodedScale := uint8(data >> 3 & 15)
	options := synCookieOptions{
		mss: int(synCookieMSSValues[mssIndex]), sack: data&(1<<7) != 0,
	}
	if encodedScale != 15 {
		options.windowScaling = true
		options.windowScale = encodedScale
	}
	return options, true
}

func synCookieAuthenticatedData(data uint32, timestamp, ecn bool) uint32 {
	if timestamp {
		data |= 1 << 8
	}
	if ecn {
		data |= 1 << 9
	}
	return data
}

func synCookiePeriodNumber(now, epoch time.Time) uint64 {
	elapsed := now.Sub(epoch)
	if elapsed <= 0 {
		return 0
	}
	return uint64(elapsed / synCookiePeriod)
}

func synCookieSequence(secret [16]byte, key tcpKey, generation uint64, clientSequence uint32, period uint64, data, authenticatedData uint32) uint32 {
	var input [59]byte
	if key.local.Addr().Is6() {
		input[0] = 6
	} else {
		input[0] = 4
	}
	local := key.local.Addr().As16()
	remote := key.remote.Addr().As16()
	copy(input[1:17], local[:])
	copy(input[17:33], remote[:])
	binary.BigEndian.PutUint16(input[33:35], key.local.Port())
	binary.BigEndian.PutUint16(input[35:37], key.remote.Port())
	binary.BigEndian.PutUint64(input[37:45], generation)
	binary.BigEndian.PutUint32(input[45:49], clientSequence)
	binary.BigEndian.PutUint64(input[49:57], period)
	binary.BigEndian.PutUint16(input[57:59], uint16(authenticatedData))
	tag := uint32(sipHash24(secret, input[:])) &^ synCookieDataMask
	return tag | data
}

func (c *TCPConn) runPassiveCookie(listener *TCPListener, finalACK tcpSegment, initialSequence uint32) {
	queued := false
	defer func() {
		if !queued {
			listener.removePending(c)
		}
	}()
	defer c.stack.removeTCP(c)
	defer close(c.done)
	protocolTimer := newOwnedTimer()
	defer protocolTimer.close()
	if len(finalACK.payload) != 0 || finalACK.flags&TCPFlagFIN != 0 {
		c.inbound.prepend(finalACK)
	}
	if !listener.enqueue(c) {
		_ = c.sendAbortReset(initialSequence+1, c.receiveNext, 0)
		c.finish(net.ErrClosed)
		return
	}
	queued = true
	c.finish(c.established(initialSequence+1, protocolTimer, tcpInitialReceive{}))
}
