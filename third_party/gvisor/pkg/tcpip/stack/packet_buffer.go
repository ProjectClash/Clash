// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at //
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack

import (
	"fmt"
	"io"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/sync"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
)

type headerType int

const (
	virtioNetHeader headerType = iota
	linkHeader
	networkHeader
	transportHeader
	numHeaderType
)

var pkPool = sync.Pool{
	New: func() any {
		return &PacketBuffer{}
	},
}

type PacketBufferOptions struct {
	ReserveHeaderBytes int

	Payload buffer.Buffer

	IsForwardedPacket bool

	OnRelease func()

	Mark uint32
}

type PacketBuffer struct {
	_ sync.NoCopy

	packetBufferRefs

	buf      buffer.Buffer
	reserved int
	pushed   int
	consumed int

	headers [numHeaderType]headerInfo

	NetworkProtocolNumber tcpip.NetworkProtocolNumber

	TransportProtocolNumber tcpip.TransportProtocolNumber

	Hash uint32

	Owner tcpip.PacketOwner

	EgressRoute RouteInfo
	GSOOptions  GSO

	snatDone bool

	dnatDone bool

	PktType tcpip.PacketType

	NICID tcpip.NICID

	InputNICID tcpip.NICID

	RXChecksumValidated bool

	NetworkPacketInfo NetworkPacketInfo

	Mark uint32

	tuple *tuple

	onRelease func() `state:"nosave"`
}

func NewPacketBuffer(opts PacketBufferOptions) *PacketBuffer {
	pk := pkPool.Get().(*PacketBuffer)
	pk.reset()
	if opts.ReserveHeaderBytes != 0 {
		v := buffer.NewViewSize(opts.ReserveHeaderBytes)
		pk.buf.Append(v)
		pk.reserved = opts.ReserveHeaderBytes
	}
	if opts.Payload.Size() > 0 {
		pk.buf.Merge(&opts.Payload)
	}
	pk.NetworkPacketInfo.IsForwardedPacket = opts.IsForwardedPacket
	pk.onRelease = opts.OnRelease
	pk.Mark = opts.Mark
	pk.InitRefs()
	return pk
}

func (pk *PacketBuffer) IncRef() *PacketBuffer {
	pk.packetBufferRefs.IncRef()
	return pk
}

func (pk *PacketBuffer) DecRef() {
	pk.packetBufferRefs.DecRef(func() {
		if pk.onRelease != nil {
			pk.onRelease()
		}

		pk.buf.Release()
		pkPool.Put(pk)
	})
}

func (pk *PacketBuffer) reset() {
	*pk = PacketBuffer{}
}

func (pk *PacketBuffer) ReservedHeaderBytes() int {
	return pk.reserved
}

func (pk *PacketBuffer) AvailableHeaderBytes() int {
	return pk.reserved - pk.pushed
}

func (pk *PacketBuffer) VirtioNetHeader() PacketHeader {
	return PacketHeader{
		pk:  pk,
		typ: virtioNetHeader,
	}
}

func (pk *PacketBuffer) LinkHeader() PacketHeader {
	return PacketHeader{
		pk:  pk,
		typ: linkHeader,
	}
}

func (pk *PacketBuffer) NetworkHeader() PacketHeader {
	return PacketHeader{
		pk:  pk,
		typ: networkHeader,
	}
}

func (pk *PacketBuffer) TransportHeader() PacketHeader {
	return PacketHeader{
		pk:  pk,
		typ: transportHeader,
	}
}

func (pk *PacketBuffer) HeaderSize() int {
	return pk.pushed + pk.consumed
}

func (pk *PacketBuffer) Size() int {
	return int(pk.buf.Size()) - pk.headerOffset()
}

func (pk *PacketBuffer) MemSize() int {
	return int(pk.buf.Size()) + PacketBufferStructSize
}

func (pk *PacketBuffer) Data() PacketData {
	return PacketData{pk: pk}
}

func (pk *PacketBuffer) AsSlices() [][]byte {
	vl := pk.buf.AsViewList()
	views := make([][]byte, 0, vl.Len())
	offset := pk.headerOffset()
	pk.buf.SubApply(offset, int(pk.buf.Size())-offset, func(v *buffer.View) {
		views = append(views, v.AsSlice())
	})
	return views
}

func (pk *PacketBuffer) AsViewList() (buffer.ViewList, int) {
	return pk.buf.AsViewList(), pk.headerOffset()
}

func (pk *PacketBuffer) ToBuffer() buffer.Buffer {
	b := pk.buf.Clone()
	b.TrimFront(int64(pk.headerOffset()))
	return b
}

func (pk *PacketBuffer) ToView() *buffer.View {
	p := buffer.NewView(int(pk.buf.Size()))
	offset := pk.headerOffset()
	pk.buf.SubApply(offset, int(pk.buf.Size())-offset, func(v *buffer.View) {
		p.Write(v.AsSlice())
	})
	return p
}

func (pk *PacketBuffer) headerOffset() int {
	return pk.reserved - pk.pushed
}

func (pk *PacketBuffer) headerOffsetOf(typ headerType) int {
	return pk.reserved + pk.headers[typ].offset
}

func (pk *PacketBuffer) dataOffset() int {
	return pk.reserved + pk.consumed
}

func (pk *PacketBuffer) push(typ headerType, size int) []byte {
	h := &pk.headers[typ]
	if h.length > 0 {
		panic(fmt.Sprintf("push(%s, %d) called after previous push", typ, size))
	}
	if pk.pushed+size > pk.reserved {
		panic(fmt.Sprintf("push(%s, %d) overflows; pushed=%d reserved=%d", typ, size, pk.pushed, pk.reserved))
	}
	pk.pushed += size
	h.offset = -pk.pushed
	h.length = size
	view := pk.headerView(typ)
	return view.AsSlice()
}

func (pk *PacketBuffer) consume(typ headerType, size int) (v []byte, consumed bool) {
	h := &pk.headers[typ]
	if h.length > 0 {
		panic(fmt.Sprintf("consume must not be called twice: type %s", typ))
	}
	if pk.reserved+pk.consumed+size > int(pk.buf.Size()) {
		return nil, false
	}
	h.offset = pk.consumed
	h.length = size
	pk.consumed += size
	view := pk.headerView(typ)
	return view.AsSlice(), true
}

func (pk *PacketBuffer) headerView(typ headerType) buffer.View {
	h := &pk.headers[typ]
	if h.length == 0 {
		return buffer.View{}
	}
	v, ok := pk.buf.PullUp(pk.headerOffsetOf(typ), h.length)
	if !ok {
		panic("PullUp failed")
	}
	return v
}

func (pk *PacketBuffer) Clone() *PacketBuffer {
	newPk := pkPool.Get().(*PacketBuffer)
	newPk.reset()
	newPk.buf = pk.buf.Clone()
	newPk.reserved = pk.reserved
	newPk.pushed = pk.pushed
	newPk.consumed = pk.consumed
	newPk.headers = pk.headers
	newPk.Hash = pk.Hash
	newPk.Owner = pk.Owner
	newPk.Mark = pk.Mark
	newPk.GSOOptions = pk.GSOOptions
	newPk.EgressRoute = pk.EgressRoute
	newPk.NetworkProtocolNumber = pk.NetworkProtocolNumber
	newPk.dnatDone = pk.dnatDone
	newPk.snatDone = pk.snatDone
	newPk.TransportProtocolNumber = pk.TransportProtocolNumber
	newPk.PktType = pk.PktType
	newPk.NICID = pk.NICID
	newPk.InputNICID = pk.InputNICID
	newPk.RXChecksumValidated = pk.RXChecksumValidated
	newPk.NetworkPacketInfo = pk.NetworkPacketInfo
	newPk.tuple = pk.tuple
	newPk.InitRefs()
	return newPk
}

func (pk *PacketBuffer) ReserveHeaderBytes(reserved int) {
	if pk.reserved != 0 {
		panic(fmt.Sprintf("ReserveHeaderBytes(...) called on packet with reserved=%d, want reserved=0", pk.reserved))
	}
	pk.reserved = reserved
	pk.buf.Prepend(buffer.NewViewSize(reserved))
}

func (pk *PacketBuffer) Network() header.Network {
	switch netProto := pk.NetworkProtocolNumber; netProto {
	case header.IPv4ProtocolNumber:
		return header.IPv4(pk.NetworkHeader().Slice())
	case header.IPv6ProtocolNumber:
		return header.IPv6(pk.NetworkHeader().Slice())
	default:
		panic(fmt.Sprintf("unknown network protocol number %d", netProto))
	}
}

func (pk *PacketBuffer) CloneToInbound() *PacketBuffer {
	newPk := pkPool.Get().(*PacketBuffer)
	newPk.reset()
	newPk.buf = pk.buf.Clone()
	newPk.InitRefs()
	newPk.reserved = pk.AvailableHeaderBytes()
	newPk.Mark = pk.Mark
	newPk.tuple = pk.tuple
	return newPk
}

func (pk *PacketBuffer) DeepCopyForForwarding(reservedHeaderBytes int) *PacketBuffer {
	payload := BufferSince(pk.NetworkHeader())
	defer payload.Release()
	newPk := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: reservedHeaderBytes,
		Payload:            payload.DeepClone(),
		IsForwardedPacket:  true,
	})

	{
		consumeBytes := len(pk.NetworkHeader().Slice())
		if _, consumed := newPk.NetworkHeader().Consume(consumeBytes); !consumed {
			panic(fmt.Sprintf("expected to consume network header %d bytes from new packet", consumeBytes))
		}
		newPk.NetworkProtocolNumber = pk.NetworkProtocolNumber
	}

	{
		consumeBytes := len(pk.TransportHeader().Slice())
		if _, consumed := newPk.TransportHeader().Consume(consumeBytes); !consumed {
			panic(fmt.Sprintf("expected to consume transport header %d bytes from new packet", consumeBytes))
		}
		newPk.TransportProtocolNumber = pk.TransportProtocolNumber
	}

	newPk.tuple = pk.tuple
	newPk.Mark = pk.Mark
	newPk.InputNICID = pk.InputNICID

	return newPk
}

func (pk *PacketBuffer) IsConnTrackConfigured() bool {
	return pk.tuple != nil && pk.tuple.conn != nil
}

func (pk *PacketBuffer) FillConnTrackInfo(opts ConnTrackInfoOpts, info *ConnTrackInfo) bool {
	t := pk.tuple
	if t == nil || t.conn == nil {
		return false
	}
	return t.conn.FillConnTrackInfo(opts, info)
}

func (pk *PacketBuffer) IsReplyPacket() bool {
	t := pk.tuple
	if t == nil {
		return false
	}
	return t.reply
}

func (pk *PacketBuffer) IsNATConfigured(nt NATType) bool {
	if !pk.IsConnTrackConfigured() {
		return false
	}
	return pk.tuple.conn.IsNATConfigured(nt)
}

func (pk *PacketBuffer) ConfigureNoopNAT(natType NATType) bool {
	if !pk.IsConnTrackConfigured() {
		return false
	}
	return pk.tuple.conn.ConfigureNoopNAT(pk, natType)
}

func (pk *PacketBuffer) ConfigureNAT(portsOrIdents PortOrIdentRange, natAddress tcpip.Address, natType NATType, changePort, changeAddress bool) bool {
	if !pk.IsConnTrackConfigured() {
		return false
	}
	return pk.tuple.conn.ConfigureNAT(portsOrIdents, natAddress, natType, changePort, changeAddress)
}

func (pk *PacketBuffer) ConfigureMasquerade(portsOrIdents PortOrIdentRange, route *Route, stk *Stack, changePort bool) bool {
	if !pk.IsConnTrackConfigured() {
		return false
	}
	return pk.tuple.conn.configureMasquerade(pk, route, stk, portsOrIdents, changePort)
}

func (pk *PacketBuffer) FinalizeConnTrack() bool {
	if pk.tuple == nil || pk.tuple.conn == nil {
		return true
	}
	return pk.tuple.conn.finalize()
}

type headerInfo struct {
	offset int

	length int
}

type PacketHeader struct {
	pk  *PacketBuffer
	typ headerType
}

func (h PacketHeader) View() *buffer.View {
	view := h.pk.headerView(h.typ)
	if view.Size() == 0 {
		return nil
	}
	return view.Clone()
}

func (h PacketHeader) Slice() []byte {
	view := h.pk.headerView(h.typ)
	return view.AsSlice()
}

func (h PacketHeader) Push(size int) []byte {
	return h.pk.push(h.typ, size)
}

func (h PacketHeader) Consume(size int) (v []byte, consumed bool) {
	return h.pk.consume(h.typ, size)
}

type PacketData struct {
	pk *PacketBuffer
}

func (d PacketData) PullUp(size int) (b []byte, ok bool) {
	view, ok := d.pk.buf.PullUp(d.pk.dataOffset(), size)
	return view.AsSlice(), ok
}

func (d PacketData) Consume(size int) ([]byte, bool) {
	v, ok := d.PullUp(size)
	if ok {
		d.pk.consumed += size
	}
	return v, ok
}

func (d PacketData) ReadTo(dst io.Writer, peek bool) (int, error) {
	var (
		err  error
		done int
	)
	offset := d.pk.dataOffset()
	d.pk.buf.SubApply(offset, int(d.pk.buf.Size())-offset, func(v *buffer.View) {
		if err != nil {
			return
		}
		var n int
		n, err = dst.Write(v.AsSlice())
		done += n
		if err != nil {
			return
		}
		if n != v.Size() {
			panic(fmt.Sprintf("io.Writer.Write succeeded with incomplete write: %d != %d", n, v.Size()))
		}
	})
	if !peek {
		d.pk.buf.TrimFront(int64(done))
	}
	return done, err
}

func (d PacketData) CapLength(length int) {
	if length < 0 {
		panic("length < 0")
	}
	d.pk.buf.Truncate(int64(length + d.pk.dataOffset()))
}

func (d PacketData) ToBuffer() buffer.Buffer {
	buf := d.pk.buf.Clone()
	offset := d.pk.dataOffset()
	buf.TrimFront(int64(offset))
	return buf
}

func (d PacketData) AppendView(v *buffer.View) {
	d.pk.buf.Append(v)
}

func (d PacketData) MergeBuffer(b *buffer.Buffer) {
	d.pk.buf.Merge(b)
}

func MergeFragment(dst, frag *PacketBuffer) {
	frag.buf.TrimFront(int64(frag.dataOffset()))
	dst.buf.Merge(&frag.buf)
}

func (d PacketData) ReadFrom(src *buffer.Buffer, count int) int {
	toRead := int64(count)
	if toRead > src.Size() {
		toRead = src.Size()
	}
	clone := src.Clone()
	clone.Truncate(toRead)
	d.pk.buf.Merge(&clone)
	src.TrimFront(toRead)
	return int(toRead)
}

func (d PacketData) ReadFromPacketData(oth PacketData, count int) {
	buf := oth.ToBuffer()
	buf.Truncate(int64(count))
	d.MergeBuffer(&buf)
	oth.TrimFront(count)
	buf.Release()
}

func (d PacketData) Merge(oth PacketData) {
	oth.pk.buf.TrimFront(int64(oth.pk.dataOffset()))
	d.pk.buf.Merge(&oth.pk.buf)
}

func (d PacketData) TrimFront(count int) {
	if count > d.Size() {
		count = d.Size()
	}
	buf := d.pk.Data().ToBuffer()
	buf.TrimFront(int64(count))
	d.pk.buf.Truncate(int64(d.pk.dataOffset()))
	d.pk.buf.Merge(&buf)
}

func (d PacketData) Size() int {
	return int(d.pk.buf.Size()) - d.pk.dataOffset()
}

func (d PacketData) AsRange() Range {
	return Range{
		pk:     d.pk,
		offset: d.pk.dataOffset(),
		length: d.Size(),
	}
}

func (d PacketData) Checksum() uint16 {
	return d.pk.buf.Checksum(d.pk.dataOffset())
}

func (d PacketData) ChecksumAtOffset(offset int) uint16 {
	return d.pk.buf.Checksum(offset)
}

type Range struct {
	pk     *PacketBuffer
	offset int
	length int
}

func (r Range) Size() int {
	return r.length
}

func (r Range) SubRange(off int) Range {
	if off > r.length {
		return Range{pk: r.pk}
	}
	return Range{
		pk:     r.pk,
		offset: r.offset + off,
		length: r.length - off,
	}
}

func (r Range) Capped(max int) Range {
	if r.length <= max {
		return r
	}
	return Range{
		pk:     r.pk,
		offset: r.offset,
		length: max,
	}
}

func (r Range) ToSlice() []byte {
	if r.length == 0 {
		return nil
	}
	all := make([]byte, 0, r.length)
	r.iterate(func(v *buffer.View) {
		all = append(all, v.AsSlice()...)
	})
	return all
}

func (r Range) ToView() *buffer.View {
	if r.length == 0 {
		return nil
	}
	newV := buffer.NewView(r.length)
	r.iterate(func(v *buffer.View) {
		newV.Write(v.AsSlice())
	})
	return newV
}

func (r Range) iterate(fn func(*buffer.View)) {
	r.pk.buf.SubApply(r.offset, r.length, fn)
}

func PayloadSince(h PacketHeader) *buffer.View {
	offset := h.pk.headerOffset()
	for i := headerType(0); i < h.typ; i++ {
		offset += h.pk.headers[i].length
	}
	return Range{
		pk:     h.pk,
		offset: offset,
		length: int(h.pk.buf.Size()) - offset,
	}.ToView()
}

func BufferSince(h PacketHeader) buffer.Buffer {
	offset := h.pk.headerOffset()
	for i := headerType(0); i < h.typ; i++ {
		offset += h.pk.headers[i].length
	}
	clone := h.pk.buf.Clone()
	clone.TrimFront(int64(offset))
	return clone
}

func (pk *PacketBuffer) ExperimentOptionValue() (uint16, bool) {
	switch pk.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		h := header.IPv4(pk.NetworkHeader().Slice())
		opts := h.Options()
		iter := opts.MakeIterator()
		for {
			opt, done, err := iter.Next()
			if err != nil {
				return 0, false
			}
			if done {
				return 0, false
			}
			if opt.Type() == header.IPv4OptionExperimentType {
				return opt.(*header.IPv4OptionExperiment).Value(), true
			}
		}
	case header.IPv6ProtocolNumber:
		h := header.IPv6(pk.NetworkHeader().Slice())
		v := pk.NetworkHeader().View()
		if v != nil {
			v.TrimFront(header.IPv6MinimumSize)
		}
		buf := buffer.MakeWithView(v)
		buf.Append(pk.TransportHeader().View())
		dataBuf := pk.Data().ToBuffer()
		buf.Merge(&dataBuf)
		it := header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(h.NextHeader()), buf)

		for {
			hdr, done, err := it.Next()
			if done || err != nil {
				break
			}
			if h, ok := hdr.(header.IPv6ExperimentExtHdr); ok {
				hdr.Release()
				return h.Value, true
			}
			hdr.Release()
		}
	default:
		panic(fmt.Sprintf("Unexpected network protocol number %d", pk.NetworkProtocolNumber))
	}
	return 0, false
}

func (pk *PacketBuffer) GetEmbeddedNetAndTransHeaders(netHdrLength int, getNetAndTransHdr netAndTransHeadersFunc, transProto tcpip.TransportProtocolNumber) (header.Network, header.ChecksummableTransport, bool) {
	switch transProto {
	case header.TCPProtocolNumber:
		if netAndTransHeader, ok := pk.Data().PullUp(netHdrLength + header.TCPMinimumSize); ok {
			netHeader, transHeaderBytes := getNetAndTransHdr(netAndTransHeader, header.TCPMinimumSize)
			return netHeader, header.TCP(transHeaderBytes), true
		}
	case header.UDPProtocolNumber:
		if netAndTransHeader, ok := pk.Data().PullUp(netHdrLength + header.UDPMinimumSize); ok {
			netHeader, transHeaderBytes := getNetAndTransHdr(netAndTransHeader, header.UDPMinimumSize)
			return netHeader, header.UDP(transHeaderBytes), true
		}
	}
	return nil, nil, false
}

func (pk *PacketBuffer) GetHeaders() (netHdr header.Network, transHdr header.Transport, isICMPError bool, ok bool) {
	switch pk.TransportProtocolNumber {
	case header.TCPProtocolNumber:
		if tcpHeader := header.TCP(pk.TransportHeader().Slice()); len(tcpHeader) >= header.TCPMinimumSize {
			return pk.Network(), tcpHeader, false, true
		}
		return nil, nil, false, false
	case header.UDPProtocolNumber:
		if udpHeader := header.UDP(pk.TransportHeader().Slice()); len(udpHeader) >= header.UDPMinimumSize {
			return pk.Network(), udpHeader, false, true
		}
		return nil, nil, false, false
	case header.ICMPv4ProtocolNumber:
		icmpHeader := header.ICMPv4(pk.TransportHeader().Slice())
		if len(icmpHeader) < header.ICMPv4MinimumSize {
			return nil, nil, false, false
		}

		switch icmpType := icmpHeader.Type(); icmpType {
		case header.ICMPv4Echo, header.ICMPv4EchoReply:
			return pk.Network(), icmpHeader, false, true
		case header.ICMPv4DstUnreachable, header.ICMPv4TimeExceeded, header.ICMPv4ParamProblem:
		default:
			return nil, nil, false, false
		}

		h, ok := pk.Data().PullUp(header.IPv4MinimumSize)
		if !ok {
			return nil, nil, false, false
		}

		hdrLength := int(header.IPv4(h).HeaderLength())
		if hdrLength > header.IPv4MinimumSize {
			h, ok = pk.Data().PullUp(hdrLength)
			if !ok {
				return nil, nil, false, false
			}
		}

		if netHdr, transHdr, ok := pk.GetEmbeddedNetAndTransHeaders(hdrLength, v4NetAndTransHdr, tcpip.TransportProtocolNumber(header.IPv4(h).Protocol())); ok {
			return netHdr, transHdr, true, true
		}
		return nil, nil, false, false
	case header.ICMPv6ProtocolNumber:
		icmpHeader := header.ICMPv6(pk.TransportHeader().Slice())
		if len(icmpHeader) < header.ICMPv6MinimumSize {
			return nil, nil, false, false
		}

		switch icmpType := icmpHeader.Type(); icmpType {
		case header.ICMPv6EchoRequest, header.ICMPv6EchoReply:
			return pk.Network(), icmpHeader, false, true
		case header.ICMPv6DstUnreachable, header.ICMPv6PacketTooBig, header.ICMPv6TimeExceeded, header.ICMPv6ParamProblem:
		default:
			return nil, nil, false, false
		}

		h, ok := pk.Data().PullUp(header.IPv6MinimumSize)
		if !ok {
			return nil, nil, false, false
		}

		transProto, _ := header.IPv6(h).TryParseTransportProtocol()
		if netHdr, transHdr, ok := pk.GetEmbeddedNetAndTransHeaders(header.IPv6MinimumSize, v6NetAndTransHdr, transProto); ok {
			return netHdr, transHdr, true, true
		}
		return nil, nil, false, false
	default:
		return nil, nil, false, false
	}
}

func UpdateHeaders(n header.Network, t header.Transport, updateSRCFields, fullChecksum, updatePseudoHeader bool, newPortOrIdent uint16, newAddr tcpip.Address) {
	switch t := t.(type) {
	case header.ChecksummableTransport:
		if updateSRCFields {
			if fullChecksum {
				t.SetSourcePortWithChecksumUpdate(newPortOrIdent)
			} else {
				t.SetSourcePort(newPortOrIdent)
			}
		} else {
			if fullChecksum {
				t.SetDestinationPortWithChecksumUpdate(newPortOrIdent)
			} else {
				t.SetDestinationPort(newPortOrIdent)
			}
		}

		if updatePseudoHeader {
			var oldAddr tcpip.Address
			if updateSRCFields {
				oldAddr = n.SourceAddress()
			} else {
				oldAddr = n.DestinationAddress()
			}

			t.UpdateChecksumPseudoHeaderAddress(oldAddr, newAddr, fullChecksum)
		}
	case header.ICMPv4:
		switch icmpType := t.Type(); icmpType {
		case header.ICMPv4Echo:
			if updateSRCFields {
				t.SetIdentWithChecksumUpdate(newPortOrIdent)
			}
		case header.ICMPv4EchoReply:
			if !updateSRCFields {
				t.SetIdentWithChecksumUpdate(newPortOrIdent)
			}
		default:
			panic(fmt.Sprintf("unexpected ICMPv4 type = %d", icmpType))
		}
	case header.ICMPv6:
		switch icmpType := t.Type(); icmpType {
		case header.ICMPv6EchoRequest:
			if updateSRCFields {
				t.SetIdentWithChecksumUpdate(newPortOrIdent)
			}
		case header.ICMPv6EchoReply:
			if !updateSRCFields {
				t.SetIdentWithChecksumUpdate(newPortOrIdent)
			}
		default:
			panic(fmt.Sprintf("unexpected ICMPv6 type = %d", icmpType))
		}

		var oldAddr tcpip.Address
		if updateSRCFields {
			oldAddr = n.SourceAddress()
		} else {
			oldAddr = n.DestinationAddress()
		}

		t.UpdateChecksumPseudoHeaderAddress(oldAddr, newAddr)
	default:
		panic(fmt.Sprintf("unhandled transport = %#v", t))
	}

	if checksummableNetHeader, ok := n.(header.ChecksummableNetwork); ok {
		if updateSRCFields {
			checksummableNetHeader.SetSourceAddressWithChecksumUpdate(newAddr)
		} else {
			checksummableNetHeader.SetDestinationAddressWithChecksumUpdate(newAddr)
		}
	} else if updateSRCFields {
		n.SetSourceAddress(newAddr)
	} else {
		n.SetDestinationAddress(newAddr)
	}
}

func (pk *PacketBuffer) CalculateTransportChecksum() {
	netHdr, transHdr, isICMPError, ok := pk.GetHeaders()
	if isICMPError {
		return
	}
	if !ok {
		if pk.NetworkProtocolNumber == 0 {
			return
		}
		netHdr = pk.Network()
		transProto := netHdr.TransportProtocol()

		var headerSize int
		switch transProto {
		case header.TCPProtocolNumber:
			b, ok := pk.Data().PullUp(header.TCPMinimumSize)
			if !ok {
				return
			}
			tcp := header.TCP(b)
			headerSize = int(tcp.DataOffset())
			if headerSize < header.TCPMinimumSize {
				return
			}
		case header.UDPProtocolNumber:
			headerSize = header.UDPMinimumSize
		default:
			return
		}

		if _, ok := pk.TransportHeader().Consume(headerSize); !ok {
			return
		}
		pk.TransportProtocolNumber = transProto

		netHdr, transHdr, isICMPError, ok = pk.GetHeaders()
		if !ok || isICMPError {
			return
		}
	}

	var xsum uint16
	switch t := transHdr.(type) {
	case header.TCP:
		src := netHdr.SourceAddress()
		dst := netHdr.DestinationAddress()
		proto := netHdr.TransportProtocol()
		totalLen := uint16(len(t) + pk.Data().Size())
		xsum = header.PseudoHeaderChecksum(proto, src, dst, totalLen)
		xsum = checksum.Combine(xsum, pk.Data().Checksum())
		t.SetChecksum(0)
		t.SetChecksum(^t.CalculateChecksum(xsum))
	case header.UDP:
		src := netHdr.SourceAddress()
		dst := netHdr.DestinationAddress()
		proto := netHdr.TransportProtocol()
		totalLen := uint16(len(t) + pk.Data().Size())
		xsum = header.PseudoHeaderChecksum(proto, src, dst, totalLen)
		xsum = checksum.Combine(xsum, pk.Data().Checksum())
		t.SetChecksum(0)
		csum := ^t.CalculateChecksum(xsum)
		if csum == 0 {
			csum = 0xFFFF
		}
		t.SetChecksum(csum)
	}
}
