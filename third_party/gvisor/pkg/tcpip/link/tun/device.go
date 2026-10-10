// Copyright 2020 The gVisor Authors.
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

package tun

import (
	"fmt"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/context"
	"github.com/metacubex/gvisor/pkg/errors/linuxerr"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/link/packetsocket"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/waiter"
)

const (
	defaultDevMtu = 1500

	defaultDevOutQueueLen = 1024
)

var zeroMAC [6]byte

type Device struct {
	waiter.Queue

	mu           deviceRWMutex `state:"nosave"`
	endpoint     *tunEndpoint
	notifyHandle *channel.NotificationHandle
	flags        Flags
}

type Flags struct {
	TUN          bool
	TAP          bool
	NoPacketInfo bool
	Exclusive    bool
}

func (d *Device) beforeSave() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.endpoint != nil {
		panic("/dev/net/tun does not support save/restore when a device is associated with it.")
	}
}

func (d *Device) SetPersistent(v bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.endpoint == nil {
		return linuxerr.EBADFD
	}

	d.endpoint.setPersistent(v)

	return nil
}

func (d *Device) Release(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.endpoint != nil {
		d.endpoint.Drain()
		d.endpoint.RemoveNotify(d.notifyHandle)
		d.endpoint.DecRef(ctx)
		d.endpoint = nil
	}
}

func (d *Device) SetIff(ctx context.Context, s *stack.Stack, name string, flags Flags) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.endpoint != nil {
		return linuxerr.EINVAL
	}

	if (flags.TAP && flags.TUN) || (!flags.TAP && !flags.TUN) {
		return linuxerr.EINVAL
	}

	prefix := "tun"
	if flags.TAP {
		prefix = "tap"
	}

	linkCaps := stack.CapabilityNone
	if flags.TAP {
		linkCaps |= stack.CapabilityResolutionRequired
	}

	endpoint, err := attachOrCreateNIC(ctx, s, name, prefix, linkCaps, flags)
	if err != nil {
		return err
	}

	d.endpoint = endpoint
	d.notifyHandle = d.endpoint.AddNotify(d)
	d.flags = flags
	return nil
}

func attachOrCreateNIC(ctx context.Context, s *stack.Stack, name, prefix string, linkCaps stack.LinkEndpointCapabilities, flags Flags) (*tunEndpoint, error) {
	for {
		if name != "" && !flags.Exclusive {
			if linkEP := s.GetLinkEndpointByName(name); linkEP != nil {
				packetEndpoint, ok := linkEP.(*packetsocket.Endpoint)
				if !ok {
					return nil, linuxerr.EOPNOTSUPP
				}
				endpoint, ok := packetEndpoint.Child().(*tunEndpoint)
				if !ok {
					return nil, linuxerr.EOPNOTSUPP
				}
				if !endpoint.TryIncRef() {
					continue
				}
				return endpoint, nil
			}
		}

		id := s.NextNICID()
		endpoint := &tunEndpoint{
			Endpoint: channel.New(defaultDevOutQueueLen, defaultDevMtu, ""),
			stack:    s,
			nicID:    id,
			name:     name,
			isTap:    prefix == "tap",
		}
		endpoint.InitRefs()
		endpoint.Endpoint.LinkEPCapabilities = linkCaps
		if endpoint.name == "" {
			endpoint.name = fmt.Sprintf("%s%d", prefix, id)
		}
		err := s.CreateNICWithOptions(endpoint.nicID, packetsocket.New(endpoint), stack.NICOptions{
			Name: endpoint.name,
		})
		switch err.(type) {
		case nil:
			return endpoint, nil
		case *tcpip.ErrDuplicateNICID:
			endpoint.DecRef(ctx)
			if !flags.Exclusive {
				continue
			}
			return nil, linuxerr.EEXIST
		default:
			endpoint.DecRef(ctx)
			return nil, linuxerr.EINVAL
		}
	}
}

func (d *Device) MTU() (uint32, error) {
	d.mu.RLock()
	endpoint := d.endpoint
	d.mu.RUnlock()
	if endpoint == nil {
		return 0, linuxerr.EBADFD
	}
	if !endpoint.IsAttached() {
		return 0, linuxerr.EIO
	}
	return endpoint.MTU(), nil
}

func (d *Device) Write(data *buffer.View) (int64, error) {
	d.mu.RLock()
	endpoint := d.endpoint
	d.mu.RUnlock()
	if endpoint == nil {
		return 0, linuxerr.EBADFD
	}
	if !endpoint.IsAttached() {
		return 0, linuxerr.EIO
	}

	dataLen := int64(data.Size())

	var pktInfoHdr PacketInfoHeader
	if !d.flags.NoPacketInfo {
		if dataLen < PacketInfoHeaderSize {
			return dataLen, nil
		}
		pktInfoHdrView := data.Clone()
		defer pktInfoHdrView.Release()
		pktInfoHdrView.CapLength(PacketInfoHeaderSize)
		pktInfoHdr = PacketInfoHeader(pktInfoHdrView.AsSlice())
		data.TrimFront(PacketInfoHeaderSize)
	}

	var ethHdr header.Ethernet
	if d.flags.TAP {
		if data.Size() < header.EthernetMinimumSize {
			return dataLen, nil
		}
		ethHdrView := data.Clone()
		defer ethHdrView.Release()
		ethHdrView.CapLength(header.EthernetMinimumSize)
		ethHdr = header.Ethernet(ethHdrView.AsSlice())
		data.TrimFront(header.EthernetMinimumSize)
	}

	var protocol tcpip.NetworkProtocolNumber
	switch {
	case pktInfoHdr != nil:
		protocol = pktInfoHdr.Protocol()
	case ethHdr != nil:
		protocol = ethHdr.Type()
	case d.flags.TUN:
		if data.Size() == 0 {
			return dataLen, nil
		}
		version := data.AsSlice()[0] >> 4
		switch version {
		case 4:
			protocol = header.IPv4ProtocolNumber
		case 6:
			protocol = header.IPv6ProtocolNumber
		}
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: len(ethHdr),
		Payload:            buffer.MakeWithView(data.Clone()),
	})
	defer pkt.DecRef()
	copy(pkt.LinkHeader().Push(len(ethHdr)), ethHdr)
	endpoint.InjectInbound(protocol, pkt)
	return dataLen, nil
}

func (d *Device) Read() (*buffer.View, error) {
	d.mu.RLock()
	endpoint := d.endpoint
	d.mu.RUnlock()
	if endpoint == nil {
		return nil, linuxerr.EBADFD
	}

	pkt := endpoint.Read()
	if pkt == nil {
		return nil, linuxerr.ErrWouldBlock
	}
	v := d.encodePkt(pkt)
	pkt.DecRef()
	return v, nil
}

func (d *Device) encodePkt(pkt *stack.PacketBuffer) *buffer.View {
	var view *buffer.View

	if !d.flags.NoPacketInfo {
		view = buffer.NewView(PacketInfoHeaderSize + pkt.Size())
		view.Grow(PacketInfoHeaderSize)
		hdr := PacketInfoHeader(view.AsSlice())
		hdr.Encode(&PacketInfoFields{
			Protocol: pkt.NetworkProtocolNumber,
		})
		pktView := pkt.ToView()
		view.Write(pktView.AsSlice())
		pktView.Release()
	} else {
		view = pkt.ToView()
	}

	return view
}

func (d *Device) Name() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.endpoint != nil {
		return d.endpoint.name
	}
	return ""
}

func (d *Device) Flags() Flags {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.flags
}

func (d *Device) Readiness(mask waiter.EventMask) waiter.EventMask {
	if mask&waiter.ReadableEvents != 0 {
		d.mu.RLock()
		endpoint := d.endpoint
		d.mu.RUnlock()
		if endpoint != nil && endpoint.NumQueued() == 0 {
			mask &= ^waiter.ReadableEvents
		}
	}
	return mask & (waiter.ReadableEvents | waiter.WritableEvents)
}

func (d *Device) WriteNotify() {
	d.Notify(waiter.ReadableEvents)
}

type tunEndpoint struct {
	tunEndpointRefs
	*channel.Endpoint

	stack *stack.Stack
	nicID tcpip.NICID
	name  string
	isTap bool

	mu            endpointMutex `state:"nosave"`
	onCloseAction func()        `state:"nosave"`
	persistent    bool
	closed        bool
}

func (e *tunEndpoint) setPersistent(v bool) {
	e.mu.Lock()
	if e.persistent == v || e.closed {
		e.mu.Unlock()
		return
	}
	e.persistent = v
	e.mu.Unlock()
	if v {
		e.IncRef()
	} else {
		e.DecRef(context.Background())
	}
}

func (e *tunEndpoint) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	decref := e.persistent
	action := e.onCloseAction
	e.onCloseAction = nil
	e.mu.Unlock()
	if decref {
		e.DecRef(context.Background())
	}
	if action != nil {
		action()
	}
	e.Endpoint.Close()
}

func (e *tunEndpoint) SetOnCloseAction(action func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onCloseAction = action
}

func (e *tunEndpoint) DecRef(ctx context.Context) {
	e.tunEndpointRefs.DecRef(func() {
		e.Close()
	})
}

func (e *tunEndpoint) ARPHardwareType() header.ARPHardwareType {
	if e.isTap {
		return header.ARPHardwareEther
	}
	return header.ARPHardwareNone
}

func (e *tunEndpoint) AddHeader(pkt *stack.PacketBuffer) {
	if !e.isTap {
		return
	}
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{
		SrcAddr: pkt.EgressRoute.LocalLinkAddress,
		DstAddr: pkt.EgressRoute.RemoteLinkAddress,
		Type:    pkt.NetworkProtocolNumber,
	})
}

func (e *tunEndpoint) MaxHeaderLength() uint16 {
	if e.isTap {
		return header.EthernetMinimumSize
	}
	return 0
}
