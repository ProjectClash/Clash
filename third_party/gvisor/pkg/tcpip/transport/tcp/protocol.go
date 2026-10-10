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

package tcp

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/header/parse"
	"github.com/metacubex/gvisor/pkg/tcpip/internal/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/seqnum"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/raw"
	"github.com/metacubex/gvisor/pkg/waiter"
)

const (
	ProtocolNumber = header.TCPProtocolNumber

	MinBufferSize = 4 << 10

	DefaultSendBufferSize = 1 << 20

	DefaultReceiveBufferSize = 1 << 20

	MaxBufferSize = 4 << 20

	DefaultTCPLingerTimeout = 60 * time.Second

	MaxTCPLingerTimeout = 120 * time.Second

	DefaultTCPTimeWaitTimeout = 60 * time.Second

	DefaultSynRetries = 6

	DefaultKeepaliveIdle = 2 * time.Hour

	DefaultKeepaliveInterval = 75 * time.Second

	DefaultKeepaliveCount = 9
)

const (
	ccReno  = "reno"
	ccCubic = "cubic"
)

type protocol struct {
	stack *stack.Stack

	mu                         protocolRWMutex `state:"nosave"`
	sackEnabled                bool
	recovery                   tcpip.TCPRecovery
	delayEnabled               bool
	alwaysUseSynCookies        bool
	sendBufferSize             tcpip.TCPSendBufferSizeRangeOption
	recvBufferSize             tcpip.TCPReceiveBufferSizeRangeOption
	congestionControl          string
	availableCongestionControl []string
	moderateReceiveBuffer      bool
	lingerTimeout              time.Duration
	timeWaitTimeout            time.Duration
	timeWaitReuse              tcpip.TCPTimeWaitReuseOption
	minRTO                     time.Duration
	maxRTO                     time.Duration
	maxRetries                 uint32
	synRetries                 uint8
	dispatcher                 dispatcher

	probe TCPProbeFunc `state:"nosave"`

	seqnumSecret   [16]byte `state:"nosave"`
	tsOffsetSecret [16]byte `state:"nosave"`
}

func (*protocol) Number() tcpip.TransportProtocolNumber {
	return ProtocolNumber
}

func (p *protocol) NewEndpoint(netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	return newEndpoint(p.stack, p, netProto, waiterQueue), nil
}

func (p *protocol) NewRawEndpoint(netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	return raw.NewEndpoint(p.stack, netProto, header.TCPProtocolNumber, waiterQueue)
}

func (*protocol) MinimumPacketSize() int {
	return header.TCPMinimumSize
}

func (*protocol) ParsePorts(v []byte) (src, dst uint16, err tcpip.Error) {
	h := header.TCP(v)
	return h.SourcePort(), h.DestinationPort(), nil
}

func (p *protocol) QueuePacket(ep stack.TransportEndpoint, id stack.TransportEndpointID, pkt *stack.PacketBuffer) {
	p.dispatcher.queuePacket(ep, id, p.stack.Clock(), pkt)
}

func (p *protocol) HandleUnknownDestinationPacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) stack.UnknownDestinationPacketDisposition {
	s, err := newIncomingSegment(id, p.stack.Clock(), pkt)
	if err != nil {
		return stack.UnknownDestinationPacketMalformed
	}
	defer s.DecRef()
	if !s.csumValid {
		return stack.UnknownDestinationPacketMalformed
	}

	if !s.flags.Contains(header.TCPFlagRst) {
		replyWithReset(p.stack, s, stack.DefaultTOS, tcpip.UseDefaultIPv4TTL, tcpip.UseDefaultIPv6HopLimit)
	}

	return stack.UnknownDestinationPacketHandled
}

func (p *protocol) tsOffset(src, dst tcpip.Address) tcp.TSOffset {
	h := sha256.New()

	_, _ = h.Write(p.tsOffsetSecret[:])
	_, _ = h.Write(src.AsSlice())
	_, _ = h.Write(dst.AsSlice())
	return tcp.NewTSOffset(binary.LittleEndian.Uint32(h.Sum(nil)[:4]))
}

func replyWithReset(st *stack.Stack, s *segment, tos, ipv4TTL uint8, ipv6HopLimit int16) tcpip.Error {
	net := s.pkt.Network()
	route, err := st.FindRoute(s.pkt.NICID, net.DestinationAddress(), net.SourceAddress(), s.pkt.NetworkProtocolNumber, false)
	if err != nil {
		return err
	}
	defer route.Release()

	ttl := calculateTTL(route, ipv4TTL, ipv6HopLimit)

	seq := seqnum.Value(0)
	ack := seqnum.Value(0)
	flags := header.TCPFlagRst

	if s.flags.Contains(header.TCPFlagAck) {
		seq = s.ackNumber
	} else {
		flags |= header.TCPFlagAck
		ack = s.sequenceNumber.Add(s.logicalLen())
	}

	var expOptVal uint16
	if s.ep != nil {
		expOptVal = s.ep.getExperimentOptionValue(route)
	}
	hdrSize := header.TCPMinimumSize + int(route.MaxHeaderLength())
	if route.NetProto() == header.IPv6ProtocolNumber && expOptVal != 0 {
		hdrSize += header.IPv6ExperimentHdrLength
	}
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: hdrSize})
	defer p.DecRef()

	return sendTCP(route, tcpFields{
		id:        s.id,
		ttl:       ttl,
		tos:       tos,
		flags:     flags,
		seq:       seq,
		ack:       ack,
		rcvWnd:    0,
		expOptVal: expOptVal,
	}, p, stack.GSO{}, nil)
}

func (p *protocol) SetOption(option tcpip.SettableTransportProtocolOption) tcpip.Error {
	switch v := option.(type) {
	case *tcpip.TCPSACKEnabled:
		p.mu.Lock()
		p.sackEnabled = bool(*v)
		p.mu.Unlock()
		return nil

	case *tcpip.TCPRecovery:
		p.mu.Lock()
		p.recovery = *v
		p.mu.Unlock()
		return nil

	case *tcpip.TCPDelayEnabled:
		p.mu.Lock()
		p.delayEnabled = bool(*v)
		p.mu.Unlock()
		return nil

	case *tcpip.TCPSendBufferSizeRangeOption:
		if v.Min <= 0 || v.Default < v.Min || v.Default > v.Max {
			return &tcpip.ErrInvalidOptionValue{}
		}
		p.mu.Lock()
		p.sendBufferSize = *v
		p.mu.Unlock()
		return nil

	case *tcpip.TCPReceiveBufferSizeRangeOption:
		if v.Min <= 0 || v.Default < v.Min || v.Default > v.Max {
			return &tcpip.ErrInvalidOptionValue{}
		}
		p.mu.Lock()
		p.recvBufferSize = *v
		p.mu.Unlock()
		return nil

	case *tcpip.CongestionControlOption:
		for _, c := range p.availableCongestionControl {
			if string(*v) == c {
				p.mu.Lock()
				p.congestionControl = string(*v)
				p.mu.Unlock()
				return nil
			}
		}
		return &tcpip.ErrNoSuchFile{}

	case *tcpip.TCPModerateReceiveBufferOption:
		p.mu.Lock()
		p.moderateReceiveBuffer = bool(*v)
		p.mu.Unlock()
		return nil

	case *tcpip.TCPLingerTimeoutOption:
		p.mu.Lock()
		if *v < 0 {
			p.lingerTimeout = 0
		} else {
			p.lingerTimeout = time.Duration(*v)
		}
		p.mu.Unlock()
		return nil

	case *tcpip.TCPTimeWaitTimeoutOption:
		p.mu.Lock()
		if *v < 0 {
			p.timeWaitTimeout = 0
		} else {
			p.timeWaitTimeout = time.Duration(*v)
		}
		p.mu.Unlock()
		return nil

	case *tcpip.TCPTimeWaitReuseOption:
		if *v < tcpip.TCPTimeWaitReuseDisabled || *v > tcpip.TCPTimeWaitReuseLoopbackOnly {
			return &tcpip.ErrInvalidOptionValue{}
		}
		p.mu.Lock()
		p.timeWaitReuse = *v
		p.mu.Unlock()
		return nil

	case *tcpip.TCPMinRTOOption:
		p.mu.Lock()
		defer p.mu.Unlock()
		if *v < 0 {
			p.minRTO = MinRTO
		} else if minRTO := time.Duration(*v); minRTO <= p.maxRTO {
			p.minRTO = minRTO
		} else {
			return &tcpip.ErrInvalidOptionValue{}
		}
		return nil

	case *tcpip.TCPMaxRTOOption:
		p.mu.Lock()
		defer p.mu.Unlock()
		if *v < 0 {
			p.maxRTO = MaxRTO
		} else if maxRTO := time.Duration(*v); maxRTO >= p.minRTO {
			p.maxRTO = maxRTO
		} else {
			return &tcpip.ErrInvalidOptionValue{}
		}
		return nil

	case *tcpip.TCPMaxRetriesOption:
		p.mu.Lock()
		p.maxRetries = uint32(*v)
		p.mu.Unlock()
		return nil

	case *tcpip.TCPAlwaysUseSynCookies:
		p.mu.Lock()
		p.alwaysUseSynCookies = bool(*v)
		p.mu.Unlock()
		return nil

	case *tcpip.TCPSynRetriesOption:
		if *v < 1 {
			return &tcpip.ErrInvalidOptionValue{}
		}
		p.mu.Lock()
		p.synRetries = uint8(*v)
		p.mu.Unlock()
		return nil

	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

func (p *protocol) Option(option tcpip.GettableTransportProtocolOption) tcpip.Error {
	switch v := option.(type) {
	case *tcpip.TCPSACKEnabled:
		p.mu.RLock()
		*v = tcpip.TCPSACKEnabled(p.sackEnabled)
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPRecovery:
		p.mu.RLock()
		*v = p.recovery
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPDelayEnabled:
		p.mu.RLock()
		*v = tcpip.TCPDelayEnabled(p.delayEnabled)
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPSendBufferSizeRangeOption:
		p.mu.RLock()
		*v = p.sendBufferSize
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPReceiveBufferSizeRangeOption:
		p.mu.RLock()
		*v = p.recvBufferSize
		p.mu.RUnlock()
		return nil

	case *tcpip.CongestionControlOption:
		p.mu.RLock()
		*v = tcpip.CongestionControlOption(p.congestionControl)
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPAvailableCongestionControlOption:
		p.mu.RLock()
		*v = tcpip.TCPAvailableCongestionControlOption(strings.Join(p.availableCongestionControl, " "))
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPModerateReceiveBufferOption:
		p.mu.RLock()
		*v = tcpip.TCPModerateReceiveBufferOption(p.moderateReceiveBuffer)
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPLingerTimeoutOption:
		p.mu.RLock()
		*v = tcpip.TCPLingerTimeoutOption(p.lingerTimeout)
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPTimeWaitTimeoutOption:
		p.mu.RLock()
		*v = tcpip.TCPTimeWaitTimeoutOption(p.timeWaitTimeout)
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPTimeWaitReuseOption:
		p.mu.RLock()
		*v = p.timeWaitReuse
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPMinRTOOption:
		p.mu.RLock()
		*v = tcpip.TCPMinRTOOption(p.minRTO)
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPMaxRTOOption:
		p.mu.RLock()
		*v = tcpip.TCPMaxRTOOption(p.maxRTO)
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPMaxRetriesOption:
		p.mu.RLock()
		*v = tcpip.TCPMaxRetriesOption(p.maxRetries)
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPAlwaysUseSynCookies:
		p.mu.RLock()
		*v = tcpip.TCPAlwaysUseSynCookies(p.alwaysUseSynCookies)
		p.mu.RUnlock()
		return nil

	case *tcpip.TCPSynRetriesOption:
		p.mu.RLock()
		*v = tcpip.TCPSynRetriesOption(p.synRetries)
		p.mu.RUnlock()
		return nil

	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

func (p *protocol) SendBufferSize() tcpip.TCPSendBufferSizeRangeOption {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.sendBufferSize
}

func (p *protocol) Close() {
	p.dispatcher.close()
}

func (p *protocol) Wait() {
	p.dispatcher.wait()
}

func (p *protocol) Pause() {
	p.dispatcher.pause()
}

func (p *protocol) Resume() {
	p.dispatcher.resume()
}

func (p *protocol) Restore() {
	p.dispatcher.start()
}

func (*protocol) Parse(pkt *stack.PacketBuffer) bool {
	return parse.TCP(pkt)
}

func NewProtocol(s *stack.Stack) stack.TransportProtocol {
	return newProtocol(s, ccReno, nil)
}

func NewProtocolProbe(probe TCPProbeFunc) func(*stack.Stack) stack.TransportProtocol {
	return func(s *stack.Stack) stack.TransportProtocol {
		return newProtocol(s, ccReno, probe)
	}
}

func NewProtocolCUBIC(s *stack.Stack) stack.TransportProtocol {
	return newProtocol(s, ccCubic, nil)
}

func newProtocol(s *stack.Stack, cc string, probe TCPProbeFunc) stack.TransportProtocol {
	rng := s.SecureRNG()
	var seqnumSecret [16]byte
	var tsOffsetSecret [16]byte
	if n, err := rng.Reader.Read(seqnumSecret[:]); err != nil || n != len(seqnumSecret) {
		panic(fmt.Sprintf("Read() failed: %v", err))
	}
	if n, err := rng.Reader.Read(tsOffsetSecret[:]); err != nil || n != len(tsOffsetSecret) {
		panic(fmt.Sprintf("Read() failed: %v", err))
	}
	p := protocol{
		stack: s,
		sendBufferSize: tcpip.TCPSendBufferSizeRangeOption{
			Min:     MinBufferSize,
			Default: DefaultSendBufferSize,
			Max:     MaxBufferSize,
		},
		recvBufferSize: tcpip.TCPReceiveBufferSizeRangeOption{
			Min:     MinBufferSize,
			Default: DefaultReceiveBufferSize,
			Max:     MaxBufferSize,
		},
		sackEnabled:                true,
		congestionControl:          cc,
		availableCongestionControl: []string{ccReno, ccCubic},
		moderateReceiveBuffer:      true,
		lingerTimeout:              DefaultTCPLingerTimeout,
		timeWaitTimeout:            DefaultTCPTimeWaitTimeout,
		timeWaitReuse:              tcpip.TCPTimeWaitReuseLoopbackOnly,
		synRetries:                 DefaultSynRetries,
		minRTO:                     MinRTO,
		maxRTO:                     MaxRTO,
		maxRetries:                 MaxRetries,
		recovery:                   tcpip.TCPRACKLossDetection,
		seqnumSecret:               seqnumSecret,
		tsOffsetSecret:             tsOffsetSecret,
		probe:                      probe,
	}
	p.dispatcher.init(s.InsecureRNG(), runtime.GOMAXPROCS(0))
	return &p
}

func protocolFromStack(s *stack.Stack) *protocol {
	return s.TransportProtocolInstance(ProtocolNumber).(*protocol)
}
