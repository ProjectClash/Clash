package mipstack

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
	"runtime"
	"syscall"
)

const (
	ProtocolICMPv4 = 1
	ProtocolIGMP = 2
	ProtocolTCP = 6
	ProtocolUDP = 17
	ProtocolESP = 50
	ProtocolICMPv6 = 58
	ProtocolNoNextHeader = 59

	IPv4HeaderOptionEnd = 0
	IPv4HeaderOptionNOP = 1
	IPv4HeaderOptionRecordRoute = 7
	IPv4HeaderOptionTimestamp = 68
	IPv4HeaderOptionLooseSourceRoute = 131
	IPv4HeaderOptionStrictSourceRoute = 137
	IPv4HeaderOptionRouterAlert = 148

	IPv6ExtensionHeaderHopByHop = 0
	IPv6ExtensionHeaderRouting = 43
	IPv6ExtensionHeaderFragment = 44
	IPv6ExtensionHeaderAuthentication = 51
	IPv6ExtensionHeaderDestination = 60
	IPv6ExtensionHeaderMobility = 135

	IPv6ExtensionOptionPad1 = 0
	IPv6ExtensionOptionPadN = 1
	IPv6ExtensionOptionRouterAlert = 5
	IPv6ExtensionOptionJumboPayload = 194
	IPv6ExtensionOptionHomeAddress = 201

	ipv6MaximumFlowLabel = 1<<20 - 1
)

type IPPacket struct {
	Source netip.Addr
	Destination netip.Addr
	Protocol int
	HopLimit int
	TrafficClass int
	FlowLabel uint32
	Identification uint16
	DontFragment bool
	MoreFragments bool
	FragmentOffset int
	IPv4Options []byte
	Payload []byte
}

type IPPacketFragmentView struct {
	Protocol int
	Identification uint32
	Offset int
	MoreFragments bool
	Payload []byte
}

func (f IPPacketFragmentView) IsAtomic() bool {
	return f.Offset == 0 && !f.MoreFragments
}

type IPv4HeaderOption struct {
	Type uint8
	Data []byte
}

func ipv4HeaderOptionLength(option []byte) int {
	if len(option) < 2 {
		return 0
	}
	length := int(option[1])
	if uint(length-2) > uint(len(option)-2) {
		return 0
	}
	return length
}

type IPv6ExtensionHeader struct {
	Type uint8
	Data []byte
}

type IPv6ExtensionOption struct {
	Type uint8
	Data []byte
}

func ipv6NextHeaderFieldOffset(previous int) int {
	if previous < 0 {
		return 6
	}
	return 40 + previous
}

func ipv6ExtensionOptionLength(optionType byte, remaining []byte) (length int, valid bool) {
	if optionType == IPv6ExtensionOptionPad1 {
		return 1, true
	}
	if len(remaining) < 2 {
		return 0, false
	}
	length = 2 + int(remaining[1])
	return length, length <= len(remaining)
}

func (p IPPacket) IPv4HeaderOptions() ([]IPv4HeaderOption, error) {
	if !p.Source.Unmap().Is4() || !p.Destination.Unmap().Is4() {
		return nil, syscall.EAFNOSUPPORT
	}
	if len(p.IPv4Options) > 40 {
		return nil, syscall.EMSGSIZE
	}
	var result []IPv4HeaderOption
	for offset := 0; offset < len(p.IPv4Options); {
		optionType := p.IPv4Options[offset]
		if optionType == IPv4HeaderOptionEnd {
			return append(result, IPv4HeaderOption{Type: optionType}), nil
		}
		if optionType == IPv4HeaderOptionNOP {
			result = append(result, IPv4HeaderOption{Type: optionType})
			offset++
			continue
		}
		length := ipv4HeaderOptionLength(p.IPv4Options[offset:])
		if length == 0 {
			return nil, syscall.EINVAL
		}
		result = append(result, IPv4HeaderOption{Type: optionType, Data: p.IPv4Options[offset+2 : offset+length]})
		offset += length
	}
	return result, nil
}

func (p *IPPacket) SetIPv4HeaderOptions(options []IPv4HeaderOption) error {
	if p == nil {
		return syscall.EINVAL
	}
	if !p.Source.Unmap().Is4() || !p.Destination.Unmap().Is4() {
		return syscall.EAFNOSUPPORT
	}
	size := 0
	ended := false
	for _, option := range options {
		if ended {
			return syscall.EINVAL
		}
		switch option.Type {
		case IPv4HeaderOptionEnd, IPv4HeaderOptionNOP:
			if len(option.Data) != 0 {
				return syscall.EINVAL
			}
			size++
			ended = option.Type == IPv4HeaderOptionEnd
		default:
			if len(option.Data) > 253 {
				return syscall.EINVAL
			}
			size += 2 + len(option.Data)
		}
		if size > 40 {
			return syscall.EMSGSIZE
		}
	}
	var encoded []byte
	if size != 0 {
		encoded = make([]byte, 0, size)
	}
	for _, option := range options {
		encoded = append(encoded, option.Type)
		if option.Type == IPv4HeaderOptionEnd || option.Type == IPv4HeaderOptionNOP {
			continue
		}
		encoded = append(encoded, byte(2+len(option.Data)))
		encoded = append(encoded, option.Data...)
	}
	p.IPv4Options = encoded
	return nil
}

func (o IPv4HeaderOption) Copied() bool { return o.Type&0x80 != 0 }

func (o IPv4HeaderOption) Class() uint8 { return o.Type >> 5 & 0x03 }

func (o IPv4HeaderOption) Number() uint8 { return o.Type & 0x1f }

func (o IPv4HeaderOption) RouterAlert() (uint16, bool) {
	if o.Type != IPv4HeaderOptionRouterAlert || len(o.Data) != 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(o.Data), true
}

func (o *IPv4HeaderOption) SetRouterAlert(value uint16) {
	o.Type = IPv4HeaderOptionRouterAlert
	o.Data = make([]byte, 2)
	binary.BigEndian.PutUint16(o.Data, value)
}

func (p IPPacket) IPv6ExtensionHeaders() (headers []IPv6ExtensionHeader, protocol int, payload []byte, err error) {
	if !p.Source.Is6() || p.Source.Is4In6() || !p.Destination.Is6() || p.Destination.Is4In6() {
		return nil, 0, nil, syscall.EAFNOSUPPORT
	}
	if p.Protocol < 0 || p.Protocol > 255 || p.Identification != 0 || p.DontFragment || p.MoreFragments ||
		p.FragmentOffset != 0 || len(p.IPv4Options) != 0 {
		return nil, 0, nil, syscall.EINVAL
	}
	next, offset := byte(p.Protocol), 0
	seenHop, seenFragment := false, false
	for {
		if !isTraversableIPv6ExtensionHeader(next) {
			return headers, int(next), p.Payload[offset:], nil
		}
		if next == IPv6ExtensionHeaderHopByHop && (offset != 0 || seenHop) {
			return nil, 0, nil, syscall.EINVAL
		}
		headerType := next
		length, valid := ipv6ExtensionHeaderLength(headerType, p.Payload[offset:])
		if !valid {
			return nil, 0, nil, syscall.EINVAL
		}
		header := p.Payload[offset : offset+length]
		next, offset = header[0], offset+length
		if headerType == IPv6ExtensionHeaderHopByHop || headerType == IPv6ExtensionHeaderDestination {
			validOptions, _, jumboPayload := inspectIPv6OptionsForCodec(header)
			if !validOptions || jumboPayload {
				return nil, 0, nil, syscall.EINVAL
			}
		}
		descriptor := IPv6ExtensionHeader{Type: headerType, Data: header[1:]}
		headers = append(headers, descriptor)
		if headerType == IPv6ExtensionHeaderHopByHop {
			seenHop = true
		}
		if headerType == IPv6ExtensionHeaderFragment {
			if seenFragment {
				return nil, 0, nil, syscall.EINVAL
			}
			seenFragment = true
			fragmentOffset, more, _, valid := descriptor.Fragment()
			fragmentPayload := p.Payload[offset:]
			if !valid || !validFragmentPayload(fragmentOffset, more, len(fragmentPayload), 65535) {
				return nil, 0, nil, syscall.EINVAL
			}
			if fragmentOffset != 0 || more {
				return headers, int(next), fragmentPayload, nil
			}
		}
	}
}

func (p *IPPacket) SetIPv6ExtensionHeaders(headers []IPv6ExtensionHeader, protocol int, payload []byte) error {
	return p.setIPv6ExtensionHeaders(headers, protocol, payload, true)
}

func (p *IPPacket) SetRawIPv6ExtensionHeaders(headers []IPv6ExtensionHeader, protocol int, payload []byte) error {
	return p.setIPv6ExtensionHeaders(headers, protocol, payload, false)
}

func (p *IPPacket) setIPv6ExtensionHeaders(headers []IPv6ExtensionHeader, protocol int, payload []byte, strict bool) error {
	if p == nil {
		return syscall.EINVAL
	}
	if !p.Source.Is6() || p.Source.Is4In6() || !p.Destination.Is6() || p.Destination.Is4In6() {
		return syscall.EAFNOSUPPORT
	}
	if protocol < 0 || protocol > 255 {
		return syscall.EINVAL
	}
	if len(payload) > 65535 {
		return syscall.EMSGSIZE
	}
	total := len(payload)
	seenHop, seenFragment, nonAtomicFragment := false, false, false
	for index, header := range headers {
		if !isTraversableIPv6ExtensionHeader(header.Type) {
			return syscall.EPROTONOSUPPORT
		}
		if strict {
			if header.Type == IPv6ExtensionHeaderHopByHop {
				if index != 0 || seenHop {
					return syscall.EINVAL
				}
				seenHop = true
			}
			length, valid := ipv6ExtensionHeaderDataLength(header.Type, header.Data)
			if !valid || length != 1+len(header.Data) {
				return syscall.EINVAL
			}
			if header.Type == IPv6ExtensionHeaderHopByHop || header.Type == IPv6ExtensionHeaderDestination {
				validOptions, _, jumboPayload := inspectIPv6OptionBytesForCodec(header.Data[1:])
				if !validOptions || jumboPayload {
					return syscall.EINVAL
				}
			}
			if header.Type == IPv6ExtensionHeaderFragment {
				if seenFragment {
					return syscall.EINVAL
				}
				seenFragment = true
				fragmentOffset, more, _, valid := header.Fragment()
				if !valid {
					return syscall.EINVAL
				}
				nonAtomicFragment = fragmentOffset != 0 || more
				if nonAtomicFragment {
					if index != len(headers)-1 || !validFragmentPayload(fragmentOffset, more, len(payload), 65535) {
						return syscall.EINVAL
					}
				}
			}
		}
		if len(header.Data) >= 65535-total {
			return syscall.EMSGSIZE
		}
		total += 1 + len(header.Data)
	}
	if strict && isTraversableIPv6ExtensionHeader(byte(protocol)) && !nonAtomicFragment {
		return syscall.EINVAL
	}
	encoded := make([]byte, 0, total)
	for index, header := range headers {
		next := byte(protocol)
		if index+1 < len(headers) {
			next = headers[index+1].Type
		}
		encoded = append(encoded, next)
		encoded = append(encoded, header.Data...)
	}
	encoded = append(encoded, payload...)
	if len(headers) == 0 {
		p.Protocol = protocol
	} else {
		p.Protocol = int(headers[0].Type)
	}
	p.Payload = encoded
	return nil
}

func (p IPPacket) Fragment() (IPPacketFragmentView, bool) {
	source, destination := p.Source.Unmap(), p.Destination.Unmap()
	if source.Is4() && destination.Is4() {
		if !p.MoreFragments && p.FragmentOffset == 0 {
			return IPPacketFragmentView{}, false
		}
		return IPPacketFragmentView{
			Protocol: p.Protocol, Identification: uint32(p.Identification),
			Offset: p.FragmentOffset, MoreFragments: p.MoreFragments, Payload: p.Payload,
		}, true
	}
	if !p.Source.Is6() || p.Source.Is4In6() || !p.Destination.Is6() || p.Destination.Is4In6() ||
		p.Protocol < 0 || p.Protocol > 255 {
		return IPPacketFragmentView{}, false
	}
	next, offset := byte(p.Protocol), 0
	for isTraversableIPv6ExtensionHeader(next) {
		headerType := next
		length, valid := ipv6ExtensionHeaderLength(headerType, p.Payload[offset:])
		if !valid {
			return IPPacketFragmentView{}, false
		}
		header := p.Payload[offset : offset+length]
		if headerType == IPv6ExtensionHeaderFragment {
			fragmentOffset, more, identification, valid := (IPv6ExtensionHeader{Type: headerType, Data: header[1:]}).Fragment()
			if !valid {
				return IPPacketFragmentView{}, false
			}
			return IPPacketFragmentView{
				Protocol: int(header[0]), Identification: identification,
				Offset: fragmentOffset, MoreFragments: more, Payload: p.Payload[offset+length:],
			}, true
		}
		next, offset = header[0], offset+length
	}
	return IPPacketFragmentView{}, false
}

func (h IPv6ExtensionHeader) Fragment() (offset int, moreFragments bool, identification uint32, ok bool) {
	if h.Type != IPv6ExtensionHeaderFragment || len(h.Data) != 7 {
		return 0, false, 0, false
	}
	field := binary.BigEndian.Uint16(h.Data[1:3])
	return int(field & 0xfff8), field&1 != 0, binary.BigEndian.Uint32(h.Data[3:7]), true
}

func (h *IPv6ExtensionHeader) SetFragment(offset int, moreFragments bool, identification uint32) error {
	if h == nil || offset < 0 || offset > 65528 || offset&7 != 0 {
		return syscall.EINVAL
	}
	data := make([]byte, 7)
	field := uint16(offset)
	if moreFragments {
		field |= 1
	}
	binary.BigEndian.PutUint16(data[1:3], field)
	binary.BigEndian.PutUint32(data[3:7], identification)
	h.Type, h.Data = IPv6ExtensionHeaderFragment, data
	return nil
}

func (h IPv6ExtensionHeader) Options() ([]IPv6ExtensionOption, error) {
	if h.Type != IPv6ExtensionHeaderHopByHop && h.Type != IPv6ExtensionHeaderDestination {
		return nil, syscall.EPROTONOSUPPORT
	}
	length, valid := ipv6ExtensionHeaderDataLength(h.Type, h.Data)
	if !valid || length != 1+len(h.Data) {
		return nil, syscall.EINVAL
	}
	return parseIPv6ExtensionOptions(h.Data[1:])
}

func (h *IPv6ExtensionHeader) SetOptions(options []IPv6ExtensionOption) error {
	if h == nil {
		return syscall.EINVAL
	}
	if h.Type != IPv6ExtensionHeaderHopByHop && h.Type != IPv6ExtensionHeaderDestination {
		return syscall.EPROTONOSUPPORT
	}
	optionSize := 0
	for _, option := range options {
		if option.Type == IPv6ExtensionOptionPad1 {
			if len(option.Data) != 0 {
				return syscall.EINVAL
			}
			optionSize++
		} else {
			if len(option.Data) > 255 {
				return syscall.EINVAL
			}
			optionSize += 2 + len(option.Data)
		}
		if optionSize > 2046 {
			return syscall.EMSGSIZE
		}
	}
	total := 2 + optionSize
	padding := -total & 7
	total += padding
	if total > 2048 {
		return syscall.EMSGSIZE
	}
	data := make([]byte, total-1)
	data[0] = byte(total/8 - 1)
	offset := 1
	for _, option := range options {
		data[offset] = option.Type
		offset++
		if option.Type == IPv6ExtensionOptionPad1 {
			continue
		}
		data[offset] = byte(len(option.Data))
		offset++
		copy(data[offset:], option.Data)
		offset += len(option.Data)
	}
	if padding == 1 {
		data[offset] = IPv6ExtensionOptionPad1
	} else if padding > 1 {
		data[offset], data[offset+1] = IPv6ExtensionOptionPadN, byte(padding-2)
	}
	h.Data = data
	return nil
}

func (o IPv6ExtensionOption) Action() uint8 { return o.Type >> 6 }

func (o IPv6ExtensionOption) MayChangeInTransit() bool { return o.Type&0x20 != 0 }

func (o IPv6ExtensionOption) RouterAlert() (uint16, bool) {
	if o.Type != IPv6ExtensionOptionRouterAlert || len(o.Data) != 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(o.Data), true
}

func (o *IPv6ExtensionOption) SetRouterAlert(value uint16) {
	o.Type = IPv6ExtensionOptionRouterAlert
	o.Data = make([]byte, 2)
	binary.BigEndian.PutUint16(o.Data, value)
}

func ParseIPPacket(packet []byte) (IPPacket, error) {
	if len(packet) == 0 {
		return IPPacket{}, syscall.EINVAL
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return IPPacket{}, syscall.EINVAL
		}
		headerSize := int(packet[0]&0x0f) * 4
		totalSize := int(binary.BigEndian.Uint16(packet[2:4]))
		fragment := binary.BigEndian.Uint16(packet[6:8])
		fragmentOffset := int(fragment&0x1fff) * 8
		moreFragments := fragment&0x2000 != 0
		if headerSize < 20 || totalSize < headerSize || totalSize > len(packet) || fragment&0x8000 != 0 ||
			fragment&0x3fff != 0 && !validFragmentPayload(fragmentOffset, moreFragments, totalSize-headerSize, 65535-20) ||
			checksum(packet[:headerSize]) != 0 {
			return IPPacket{}, syscall.EINVAL
		}
		options := packet[20:headerSize]
		if !validIPv4OptionsForCodec(options) {
			return IPPacket{}, syscall.EINVAL
		}
		return IPPacket{
			Source: netip.AddrFrom4([4]byte(packet[12:16])), Destination: netip.AddrFrom4([4]byte(packet[16:20])),
			Protocol: int(packet[9]), HopLimit: int(packet[8]), TrafficClass: int(packet[1]),
			Identification: binary.BigEndian.Uint16(packet[4:6]), DontFragment: fragment&0x4000 != 0,
			MoreFragments: moreFragments, FragmentOffset: fragmentOffset,
			IPv4Options: options, Payload: packet[headerSize:totalSize],
		}, nil
	case 6:
		if len(packet) < 40 {
			return IPPacket{}, syscall.EINVAL
		}
		payloadSize := int(binary.BigEndian.Uint16(packet[4:6]))
		end := 40 + payloadSize
		if end > len(packet) {
			return IPPacket{}, syscall.EINVAL
		}
		source, destination := netip.AddrFrom16([16]byte(packet[8:24])), netip.AddrFrom16([16]byte(packet[24:40]))
		if source.Is4In6() || destination.Is4In6() {
			return IPPacket{}, syscall.EINVAL
		}
		result := IPPacket{
			Source: source, Destination: destination,
			Protocol: int(packet[6]), HopLimit: int(packet[7]),
			TrafficClass: int(packet[0]&0x0f)<<4 | int(packet[1]>>4),
			FlowLabel:    uint32(packet[1]&0x0f)<<16 | uint32(binary.BigEndian.Uint16(packet[2:4])),
			Payload:      packet[40:end],
		}
		if _, _, _, _, valid := walkIPv6UpperLayer(byte(result.Protocol), result.Payload); !valid {
			return IPPacket{}, syscall.EINVAL
		}
		return result, nil
	default:
		return IPPacket{}, syscall.EINVAL
	}
}

func (p IPPacket) UpperLayer() (protocol int, payload []byte, err error) {
	protocol, payload, _, err = p.upperLayer()
	return
}

func (p IPPacket) upperLayer() (protocol int, payload []byte, pseudoHeaderSafe bool, err error) {
	source, destination := p.Source.Unmap(), p.Destination.Unmap()
	if !source.IsValid() || !destination.IsValid() || p.Source.Zone() != "" || p.Destination.Zone() != "" ||
		source.Is4() != destination.Is4() || p.Protocol < 0 || p.Protocol > 255 {
		return 0, nil, false, syscall.EINVAL
	}
	if source.Is4() {
		if p.MoreFragments || p.FragmentOffset != 0 || len(p.IPv4Options) > 40 || !validIPv4OptionsForCodec(p.IPv4Options) {
			return 0, nil, false, syscall.EINVAL
		}
		return p.Protocol, p.Payload, !hasActiveIPv4SourceRoute(p.IPv4Options), nil
	}
	if p.Identification != 0 || p.DontFragment || p.MoreFragments || p.FragmentOffset != 0 || len(p.IPv4Options) != 0 {
		return 0, nil, false, syscall.EINVAL
	}
	next, upper, pseudoHeaderUnsafe, nonAtomicFragment, ok := walkIPv6UpperLayer(byte(p.Protocol), p.Payload)
	if !ok || nonAtomicFragment {
		return 0, nil, false, syscall.EINVAL
	}
	return int(next), upper, !pseudoHeaderUnsafe, nil
}

func (p IPPacket) upperLayerForProtocol(protocol byte) ([]byte, bool, error) {
	actual, payload, pseudoHeaderSafe, err := p.upperLayer()
	if err != nil {
		return nil, false, err
	}
	if actual != int(protocol) {
		return nil, false, syscall.EPROTONOSUPPORT
	}
	return payload, pseudoHeaderSafe, nil
}

func (p IPPacket) MarshalBinary() ([]byte, error) { return p.AppendBinary(nil) }

func (p IPPacket) MarshalRawBinary() ([]byte, error) { return p.AppendRawBinary(nil) }

func (p IPPacket) AppendBinary(dst []byte) ([]byte, error) {
	normalized, headerSize, totalSize, err := p.wireLayout(true)
	if err != nil {
		return dst, err
	}
	start := len(dst)
	dst = extendForAppend(dst, totalSize)
	marshalPublicIPPacket(dst[start:], normalized, headerSize, true)
	return dst, nil
}

func (p IPPacket) AppendRawBinary(dst []byte) ([]byte, error) {
	normalized, headerSize, totalSize, err := p.wireLayout(false)
	if err != nil {
		return dst, err
	}
	start := len(dst)
	dst = extendForAppend(dst, totalSize)
	marshalPublicIPPacket(dst[start:], normalized, headerSize, false)
	return dst, nil
}

func (p IPPacket) MarshalFragments(mtu int, ipv6Identification uint32) ([][]byte, error) {
	normalized, headerSize, totalSize, err := p.wireLayout(true)
	if err != nil {
		return nil, err
	}
	if mtu <= 0 {
		return nil, syscall.EMSGSIZE
	}
	if totalSize <= mtu {
		packet := make([]byte, totalSize)
		marshalPublicIPPacket(packet, normalized, headerSize, true)
		return [][]byte{packet}, nil
	}
	if normalized.Source.Is4() {
		if normalized.DontFragment {
			return nil, syscall.EMSGSIZE
		}
		return marshalPublicIPv4Fragments(normalized, mtu)
	}
	if fragment, ok := normalized.Fragment(); ok && !fragment.IsAtomic() {
		return nil, syscall.EMSGSIZE
	}
	return marshalPublicIPv6Fragments(normalized, totalSize, mtu, ipv6Identification)
}

func extendForAppend(dst []byte, size int) []byte {
	if size <= cap(dst)-len(dst) {
		return dst[:len(dst)+size]
	}
	return append(dst, make([]byte, size)...)
}

func (p IPPacket) wireLayout(strict bool) (IPPacket, int, int, error) {
	if p.Source.Zone() != "" || p.Destination.Zone() != "" {
		return IPPacket{}, 0, 0, syscall.EINVAL
	}
	p.Source, p.Destination = p.Source.Unmap(), p.Destination.Unmap()
	if !p.Source.IsValid() || !p.Destination.IsValid() || p.Source.Is4() != p.Destination.Is4() ||
		p.Protocol < 0 || p.Protocol > 255 || p.HopLimit < 0 || p.HopLimit > 255 ||
		p.TrafficClass < 0 || p.TrafficClass > 255 {
		return IPPacket{}, 0, 0, syscall.EINVAL
	}
	if p.Source.Is4() {
		if p.FlowLabel != 0 || len(p.IPv4Options) > 40 || (strict && !validIPv4OptionsForCodec(p.IPv4Options)) {
			return IPPacket{}, 0, 0, syscall.EINVAL
		}
		headerSize := 20 + (len(p.IPv4Options)+3)&^3
		if len(p.Payload) > 65535-headerSize {
			return IPPacket{}, 0, 0, syscall.EMSGSIZE
		}
		if strict {
			if !validFragmentPayload(p.FragmentOffset, p.MoreFragments, len(p.Payload), 65535-20) {
				return IPPacket{}, 0, 0, syscall.EINVAL
			}
		} else if p.FragmentOffset < 0 || p.FragmentOffset > 65528 || p.FragmentOffset&7 != 0 {
			return IPPacket{}, 0, 0, syscall.EINVAL
		}
		return p, headerSize, headerSize + len(p.Payload), nil
	}
	if p.FlowLabel > ipv6MaximumFlowLabel || p.Identification != 0 || p.DontFragment || p.MoreFragments ||
		p.FragmentOffset != 0 || len(p.IPv4Options) != 0 {
		return IPPacket{}, 0, 0, syscall.EINVAL
	}
	if len(p.Payload) > 65535 {
		return IPPacket{}, 0, 0, syscall.EMSGSIZE
	}
	if strict {
		if _, _, _, _, valid := walkIPv6UpperLayer(byte(p.Protocol), p.Payload); !valid {
			return IPPacket{}, 0, 0, syscall.EINVAL
		}
	}
	return p, 40, 40 + len(p.Payload), nil
}

func validFragmentPayload(offset int, more bool, payloadSize, maximum int) bool {
	if offset < 0 || offset > 65528 || offset&7 != 0 || payloadSize < 0 || maximum < 0 {
		return false
	}
	if (offset != 0 || more) && payloadSize == 0 {
		return false
	}
	if more && payloadSize&7 != 0 {
		return false
	}
	return payloadSize <= maximum && offset <= maximum-payloadSize
}

func marshalPublicIPPacket(dst []byte, p IPPacket, headerSize int, normalize bool) {
	if p.Source.Is4() {
		var options [40]byte
		if normalize {
			contentSize, _ := ipv4OptionsContentLength(p.IPv4Options)
			copy(options[:], p.IPv4Options[:contentSize])
		} else {
			copy(options[:], p.IPv4Options)
		}
		copy(dst[headerSize:], p.Payload)
		copy(dst[20:headerSize], options[:len(p.IPv4Options)])
		for index := 20 + len(p.IPv4Options); index < headerSize; index++ {
			dst[index] = 0
		}
		dst[0], dst[1], dst[8], dst[9] = 0x40|byte(headerSize/4), byte(p.TrafficClass), byte(p.HopLimit), byte(p.Protocol)
		binary.BigEndian.PutUint16(dst[2:4], uint16(len(dst)))
		binary.BigEndian.PutUint16(dst[4:6], p.Identification)
		fragment := uint16(p.FragmentOffset / 8)
		if p.DontFragment {
			fragment |= 0x4000
		}
		if p.MoreFragments {
			fragment |= 0x2000
		}
		binary.BigEndian.PutUint16(dst[6:8], fragment)
		source, destination := p.Source.As4(), p.Destination.As4()
		copy(dst[12:16], source[:])
		copy(dst[16:20], destination[:])
		binary.BigEndian.PutUint16(dst[10:12], 0)
		binary.BigEndian.PutUint16(dst[10:12], checksum(dst[:headerSize]))
		return
	}
	copy(dst[headerSize:], p.Payload)
	if normalize {
		normalizeIPv6ExtensionFields(byte(p.Protocol), dst[headerSize:])
	}
	marshalPublicIPv6BaseHeader(dst, p, byte(p.Protocol), len(dst)-40)
}

func marshalPublicIPv6BaseHeader(dst []byte, p IPPacket, protocol byte, payloadSize int) {
	dst[0] = 0x60 | byte(p.TrafficClass)>>4
	dst[1] = byte(p.TrafficClass)<<4 | byte(p.FlowLabel>>16)
	binary.BigEndian.PutUint16(dst[2:4], uint16(p.FlowLabel))
	binary.BigEndian.PutUint16(dst[4:6], uint16(payloadSize))
	dst[6], dst[7] = protocol, byte(p.HopLimit)
	source, destination := p.Source.As16(), p.Destination.As16()
	copy(dst[8:24], source[:])
	copy(dst[24:40], destination[:])
}

func normalizeIPv6ExtensionFields(first byte, payload []byte) {
	next, offset := first, 0
	for {
		switch next {
		case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderDestination:
			length, valid := ipv6ExtensionHeaderLength(next, payload[offset:])
			if !valid {
				return
			}
			header := payload[offset : offset+length]
			next, offset = header[0], offset+length
			options := header[2:]
			for offset := 0; offset < len(options); {
				optionType := options[offset]
				length, valid := ipv6ExtensionOptionLength(optionType, options[offset:])
				if !valid {
					return
				}
				if optionType == IPv6ExtensionOptionPadN {
					for index := offset + 2; index < offset+length; index++ {
						options[index] = 0
					}
				}
				offset += length
			}
		case IPv6ExtensionHeaderRouting, IPv6ExtensionHeaderAuthentication, IPv6ExtensionHeaderMobility:
			length, valid := ipv6ExtensionHeaderLength(next, payload[offset:])
			if !valid {
				return
			}
			next, offset = payload[offset], offset+length
		case IPv6ExtensionHeaderFragment:
			length, valid := ipv6ExtensionHeaderLength(next, payload[offset:])
			if !valid {
				return
			}
			header := payload[offset : offset+length]
			next, offset = header[0], offset+length
			header[1] = 0
			field := binary.BigEndian.Uint16(header[2:4])
			binary.BigEndian.PutUint16(header[2:4], field&^0x0006)
			if field&0xfff9 != 0 {
				return
			}
		default:
			return
		}
	}
}

func InternetChecksum(data []byte) uint16 { return checksum(data) }

func InternetChecksumParts(parts ...[]byte) uint16 {
	if len(parts) == 1 {
		return checksum(parts[0])
	}
	return checksumParts(0, parts)
}

func IPTransportChecksum(source, destination netip.Addr, protocol int, payload []byte) (uint16, error) {
	if source.Zone() != "" || destination.Zone() != "" {
		return 0, syscall.EINVAL
	}
	source, destination = source.Unmap(), destination.Unmap()
	if !source.IsValid() || !destination.IsValid() || source.Is4() != destination.Is4() || protocol < 0 || protocol > 255 {
		return 0, syscall.EINVAL
	}
	if len(payload) > 65535 {
		return 0, syscall.EMSGSIZE
	}
	return transportChecksum(source, destination, byte(protocol), payload), nil
}

func IPTransportChecksumParts(source, destination netip.Addr, protocol int, parts ...[]byte) (uint16, error) {
	if source.Zone() != "" || destination.Zone() != "" {
		return 0, syscall.EINVAL
	}
	source, destination = source.Unmap(), destination.Unmap()
	if !source.IsValid() || !destination.IsValid() || source.Is4() != destination.Is4() || protocol < 0 || protocol > 255 {
		return 0, syscall.EINVAL
	}
	payloadLength := 0
	for _, part := range parts {
		if len(part) > 65535-payloadLength {
			return 0, syscall.EMSGSIZE
		}
		payloadLength += len(part)
	}
	switch len(parts) {
	case 1:
		return transportChecksum(source, destination, byte(protocol), parts[0]), nil
	case 2:
		return transportChecksumParts(source, destination, byte(protocol), payloadLength, parts[0], parts[1]), nil
	}
	var sum uint32
	if source.Is4() {
		sourceBytes, destinationBytes := source.As4(), destination.As4()
		sum += checksumSum(sourceBytes[:])
		sum += checksumSum(destinationBytes[:])
		sum += uint32(protocol)
		sum += uint32(payloadLength)
	} else {
		sourceBytes, destinationBytes := source.As16(), destination.As16()
		sum += checksumSum(sourceBytes[:])
		sum += checksumSum(destinationBytes[:])
		sum += uint32(payloadLength >> 16)
		sum += uint32(payloadLength & 0xffff)
		sum += uint32(protocol)
	}
	return checksumParts(sum, parts), nil
}

type ipPacket struct {
	source, target netip.Addr
	protocol       byte
	protocolOffset int
	parameterError bool
	parameterCode  byte
	parameterAt    uint32
	ecn            byte
	hopLimit       byte
	trafficClass   byte
	flowLabel      uint32
	payload        []byte
	original       []byte
}

type ipPacketOptions struct {
	hopLimit        byte
	trafficClass    byte
	flowLabel       uint32
	hopLimitSet     bool
	trafficClassSet bool
	flowLabelSet    bool
}

func (o ipPacketOptions) withDefaults(defaults ipPacketOptions) ipPacketOptions {
	if !o.hopLimitSet && o.hopLimit == 0 {
		o.hopLimit, o.hopLimitSet = defaults.hopLimit, defaults.hopLimitSet
	}
	if !o.trafficClassSet && o.trafficClass == 0 {
		o.trafficClass, o.trafficClassSet = defaults.trafficClass, defaults.trafficClassSet
	}
	if !o.flowLabelSet {
		o.flowLabel, o.flowLabelSet = defaults.flowLabel, defaults.flowLabelSet
	}
	return o
}

func (o ipPacketOptions) normalized() ipPacketOptions {
	if !o.hopLimitSet && o.hopLimit == 0 {
		o.hopLimit = 64
	}
	o.flowLabel &= ipv6MaximumFlowLabel
	return o
}

func checksum(data []byte) uint16 {
	sum := checksumSum(data)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

const checksumTargetBigEndian = runtime.GOARCH == "armbe" || runtime.GOARCH == "arm64be" ||
	runtime.GOARCH == "mips" || runtime.GOARCH == "mips64" ||
	runtime.GOARCH == "ppc" || runtime.GOARCH == "ppc64" ||
	runtime.GOARCH == "s390" || runtime.GOARCH == "s390x" ||
	runtime.GOARCH == "sparc" || runtime.GOARCH == "sparc64"

func checksumSum(data []byte) uint32 {
	var sum uint64
	for len(data) >= 16 {
		var first, second uint64
		if checksumTargetBigEndian {
			first = binary.BigEndian.Uint64(data[:8])
			second = binary.BigEndian.Uint64(data[8:16])
		} else {
			first = binary.LittleEndian.Uint64(data[:8])
			second = binary.LittleEndian.Uint64(data[8:16])
		}
		sum += first>>32 + first&0xffffffff + second>>32 + second&0xffffffff
		data = data[16:]
	}
	for len(data) >= 2 {
		if checksumTargetBigEndian {
			sum += uint64(binary.BigEndian.Uint16(data[:2]))
		} else {
			sum += uint64(binary.LittleEndian.Uint16(data[:2]))
		}
		data = data[2:]
	}
	if len(data) != 0 {
		if checksumTargetBigEndian {
			sum += uint64(data[0]) << 8
		} else {
			sum += uint64(data[0])
		}
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	if checksumTargetBigEndian {
		return uint32(uint16(sum))
	}
	return uint32(bits.ReverseBytes16(uint16(sum)))
}

func checksumParts(sum uint32, parts [][]byte) uint16 {
	var trailing byte
	odd := false
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		if odd {
			sum += uint32(trailing)<<8 | uint32(part[0])
			part = part[1:]
			odd = false
		}
		even := len(part) &^ 1
		if even != 0 {
			sum += checksumSum(part[:even])
		}
		if even != len(part) {
			trailing = part[even]
			odd = true
		}
		for sum>>16 != 0 {
			sum = sum&0xffff + sum>>16
		}
	}
	if odd {
		sum += uint32(trailing) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func transportChecksum(source, target netip.Addr, protocol byte, payload []byte) uint16 {
	return transportChecksumParts(source, target, protocol, len(payload), payload, nil)
}

func transportChecksumParts(source, target netip.Addr, protocol byte, payloadLength int, first, second []byte) uint16 {
	source, target = source.Unmap(), target.Unmap()
	var sum uint32
	if source.Is4() && target.Is4() {
		sourceBytes, targetBytes := source.As4(), target.As4()
		sum += checksumSum(sourceBytes[:])
		sum += checksumSum(targetBytes[:])
		sum += uint32(protocol)
		sum += uint32(payloadLength)
	} else if source.Is6() && target.Is6() {
		sourceBytes, targetBytes := source.As16(), target.As16()
		sum += checksumSum(sourceBytes[:])
		sum += checksumSum(targetBytes[:])
		sum += uint32(payloadLength >> 16)
		sum += uint32(payloadLength & 0xffff)
		sum += uint32(protocol)
	} else {
		return 0
	}
	sum += checksumSum(first)
	if len(first)&1 != 0 && len(second) != 0 {
		last := uint32(first[len(first)-1]) << 8
		sum -= last
		sum += last | uint32(second[0])
		second = second[1:]
	}
	sum += checksumSum(second)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func packetDestination(packet []byte) (netip.Addr, bool) {
	if len(packet) < 1 {
		return netip.Addr{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(packet[16:20])), true
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(packet[24:40])), true
	default:
		return netip.Addr{}, false
	}
}

func parseIPPacket(packet []byte, skipChecksum bool) (ipPacket, bool) {
	if len(packet) == 0 {
		return ipPacket{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return ipPacket{}, false
		}
		headerSize := int(packet[0]&0x0f) * 4
		totalSize := int(binary.BigEndian.Uint16(packet[2:4]))
		if headerSize < 20 || totalSize < headerSize || totalSize > len(packet) || binary.BigEndian.Uint16(packet[6:8])&0xbfff != 0 {
			return ipPacket{}, false
		}
		if !skipChecksum && checksum(packet[:headerSize]) != 0 {
			return ipPacket{}, false
		}
		source := netip.AddrFrom4([4]byte(packet[12:16]))
		target := netip.AddrFrom4([4]byte(packet[16:20]))
		if headerSize > 20 {
			options := packet[20:headerSize]
			if optionAt, malformed := malformedIPv4Option(options); malformed {
				return ipPacket{
					source: source, target: target, original: packet[:totalSize],
					parameterError: true, parameterCode: 0, parameterAt: uint32(20 + optionAt),
				}, true
			}
			if !validateIPv4Options(options) {
				return ipPacket{}, false
			}
		}
		return ipPacket{
			source: source, target: target,
			protocol: packet[9], protocolOffset: 9, ecn: packet[1] & 3, hopLimit: packet[8], trafficClass: packet[1],
			payload: packet[headerSize:totalSize], original: packet[:totalSize],
		}, true
	case 6:
		if len(packet) < 40 {
			return ipPacket{}, false
		}
		payloadSize := int(binary.BigEndian.Uint16(packet[4:6]))
		end := 40 + payloadSize
		if end > len(packet) {
			return ipPacket{}, false
		}
		source := netip.AddrFrom16([16]byte(packet[8:24]))
		target := netip.AddrFrom16([16]byte(packet[24:40]))
		if source.Is4In6() || target.Is4In6() {
			return ipPacket{}, false
		}
		flowLabel := uint32(packet[1]&0x0f)<<16 | uint32(binary.BigEndian.Uint16(packet[2:4]))
		payload := packet[40:end]
		switch packet[6] {
		case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderDestination,
			IPv6ExtensionHeaderRouting, IPv6ExtensionHeaderFragment:
		default:
			return ipPacket{
				source: source, target: target, protocol: packet[6], protocolOffset: 6,
				ecn: packet[1] >> 4 & 3, hopLimit: packet[7], trafficClass: packet[0]&0x0f<<4 | packet[1]>>4, flowLabel: flowLabel,
				payload: payload, original: packet[:end],
			}, true
		}
		next, offset, previous := packet[6], 0, -1
		seenHop := false
		for {
			switch next {
			case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderDestination:
				headerType, headerOffset := next, offset
				if next == IPv6ExtensionHeaderHopByHop && (offset != 0 || seenHop) {
					return ipPacket{
						source: source, target: target, original: packet[:end], ecn: packet[1] >> 4 & 3,
						hopLimit: packet[7], trafficClass: packet[0]&0x0f<<4 | packet[1]>>4, flowLabel: flowLabel,
						parameterError: true, parameterCode: 1, parameterAt: uint32(ipv6NextHeaderFieldOffset(previous)),
					}, true
				}
				length, valid := ipv6ExtensionHeaderUnit8Length(payload[offset:])
				if !valid {
					return ipPacket{}, false
				}
				header := payload[offset : offset+length]
				next, previous, offset = header[0], offset, offset+length
				valid, action, optionOffset := inspectIPv6Options(header)
				if !valid {
					if action >= 2 && (action == 2 || !target.IsMulticast()) {
						return ipPacket{
							source: source, target: target, original: packet[:end], ecn: packet[1] >> 4 & 3,
							hopLimit: packet[7], trafficClass: packet[0]&0x0f<<4 | packet[1]>>4, flowLabel: flowLabel,
							parameterError: true, parameterCode: 2, parameterAt: uint32(40 + headerOffset + optionOffset),
						}, true
					}
					return ipPacket{}, false
				}
				if headerType == IPv6ExtensionHeaderHopByHop {
					seenHop = true
				}
			case IPv6ExtensionHeaderRouting:
				headerOffset := offset
				length, valid := ipv6ExtensionHeaderUnit8Length(payload[offset:])
				if !valid {
					return ipPacket{}, false
				}
				header := payload[offset : offset+length]
				next, previous, offset = header[0], offset, offset+length
				if header[3] != 0 {
					return ipPacket{
						source: source, target: target, original: packet[:end], ecn: packet[1] >> 4 & 3,
						hopLimit: packet[7], trafficClass: packet[0]&0x0f<<4 | packet[1]>>4, flowLabel: flowLabel,
						parameterError: true, parameterCode: 0, parameterAt: uint32(40 + headerOffset + 2),
					}, true
				}
			case IPv6ExtensionHeaderFragment:
				if len(payload)-offset < 8 {
					return ipPacket{}, false
				}
				header := payload[offset : offset+8]
				next, previous, offset = header[0], offset, offset+8
				if binary.BigEndian.Uint16(header[2:4])&0xfff9 != 0 {
					return ipPacket{}, false
				}
			default:
				return ipPacket{
					source: source, target: target, protocol: next, protocolOffset: ipv6NextHeaderFieldOffset(previous),
					ecn: packet[1] >> 4 & 3, hopLimit: packet[7], trafficClass: packet[0]&0x0f<<4 | packet[1]>>4, flowLabel: flowLabel,
					payload: payload[offset:], original: packet[:end],
				}, true
			}
		}
	}
	return ipPacket{}, false
}

func (p ipPacket) hasRouterAlert() bool {
	if p.source.Is4() {
		if len(p.original) < 20 {
			return false
		}
		headerSize := int(p.original[0]&0x0f) * 4
		return headerSize >= 20 && headerSize <= len(p.original) && ipv4RouterAlert(p.original[20:headerSize])
	}
	if !p.source.Is6() || len(p.original) < 48 || p.original[6] != IPv6ExtensionHeaderHopByHop {
		return false
	}
	length, valid := ipv6ExtensionHeaderUnit8Length(p.original[40:])
	return valid && ipv6RouterAlert(p.original[40:40+length])
}

func walkIPv6UpperLayer(first byte, payload []byte) (protocol byte, upper []byte, pseudoHeaderUnsafe, nonAtomicFragment, ok bool) {
	next, offset := first, 0
	seenHop, seenFragment := false, false
	for {
		if next == ProtocolNoNextHeader {
			return next, nil, pseudoHeaderUnsafe, false, true
		}
		if !isTraversableIPv6ExtensionHeader(next) {
			return next, payload[offset:], pseudoHeaderUnsafe, false, true
		}
		if next == IPv6ExtensionHeaderHopByHop && (offset != 0 || seenHop) {
			return 0, nil, false, false, false
		}
		headerType := next
		length, valid := ipv6ExtensionHeaderLength(headerType, payload[offset:])
		if !valid {
			return 0, nil, false, false, false
		}
		header := payload[offset : offset+length]
		switch headerType {
		case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderDestination:
			validOptions, homeAddress, jumboPayload := inspectIPv6OptionsForCodec(header)
			if !validOptions || jumboPayload {
				return 0, nil, false, false, false
			}
			pseudoHeaderUnsafe = pseudoHeaderUnsafe || homeAddress
		case IPv6ExtensionHeaderRouting:
			pseudoHeaderUnsafe = pseudoHeaderUnsafe || header[3] != 0
		case IPv6ExtensionHeaderFragment:
			if seenFragment {
				return 0, nil, false, false, false
			}
			seenFragment = true
			field := binary.BigEndian.Uint16(header[2:4])
			fragmentOffset, more := int(field&0xfff8), field&1 != 0
			fragmentPayload := payload[offset+length:]
			if !validFragmentPayload(fragmentOffset, more, len(fragmentPayload), 65535) {
				return 0, nil, false, false, false
			}
			if fragmentOffset != 0 || more {
				return header[0], fragmentPayload, pseudoHeaderUnsafe, true, true
			}
		}
		if headerType == IPv6ExtensionHeaderHopByHop {
			seenHop = true
		}
		next, offset = header[0], offset+length
	}
}

func isTraversableIPv6ExtensionHeader(headerType byte) bool {
	switch headerType {
	case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderRouting,
		IPv6ExtensionHeaderFragment, IPv6ExtensionHeaderAuthentication,
		IPv6ExtensionHeaderDestination, IPv6ExtensionHeaderMobility:
		return true
	default:
		return false
	}
}

func ipv6ExtensionHeaderLength(headerType byte, header []byte) (int, bool) {
	if headerType == IPv6ExtensionHeaderFragment {
		return 8, len(header) >= 8
	}
	if len(header) < 2 {
		return 0, false
	}
	length := ipv6ExtensionHeaderLengthField(headerType, header[1])
	return length, length != 0 && length <= len(header)
}

func ipv6ExtensionHeaderUnit8Length(header []byte) (int, bool) {
	if len(header) < 2 {
		return 0, false
	}
	length := ipv6ExtensionHeaderUnit8LengthField(header[1])
	return length, length <= len(header)
}

func ipv6ExtensionHeaderUnit8LengthField(lengthField byte) int {
	return (int(lengthField) + 1) * 8
}

func ipv6AuthenticationHeaderLength(lengthField byte) int {
	if lengthField < 2 || lengthField&1 != 0 {
		return 0
	}
	return (int(lengthField) + 2) * 4
}

func ipv6ExtensionHeaderLengthField(headerType, lengthField byte) int {
	if headerType == IPv6ExtensionHeaderAuthentication {
		return ipv6AuthenticationHeaderLength(lengthField)
	}
	switch headerType {
	case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderRouting,
		IPv6ExtensionHeaderDestination, IPv6ExtensionHeaderMobility:
		return ipv6ExtensionHeaderUnit8LengthField(lengthField)
	default:
		return 0
	}
}

func ipv6ExtensionHeaderDataLength(headerType byte, data []byte) (int, bool) {
	if len(data) < 1 || !isTraversableIPv6ExtensionHeader(headerType) {
		return 0, false
	}
	length := 8
	if headerType != IPv6ExtensionHeaderFragment {
		length = ipv6ExtensionHeaderLengthField(headerType, data[0])
	}
	return length, length != 0 && len(data) >= length-1
}

func parseIPv6ExtensionOptions(options []byte) ([]IPv6ExtensionOption, error) {
	var result []IPv6ExtensionOption
	for offset := 0; offset < len(options); {
		optionType := options[offset]
		length, valid := ipv6ExtensionOptionLength(optionType, options[offset:])
		if !valid {
			return nil, syscall.EINVAL
		}
		option := IPv6ExtensionOption{Type: optionType}
		if length != 1 {
			option.Data = options[offset+2 : offset+length]
		}
		result = append(result, option)
		offset += length
	}
	return result, nil
}

func ipv4OptionsContentLength(options []byte) (int, bool) {
	for offset := 0; offset < len(options); {
		switch options[offset] {
		case IPv4HeaderOptionEnd:
			return offset + 1, true
		case IPv4HeaderOptionNOP:
			offset++
			continue
		}
		if len(options)-offset < 2 {
			return 0, false
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			return 0, false
		}
		offset += length
	}
	return len(options), true
}

func validIPv4OptionsForCodec(options []byte) bool {
	_, valid := ipv4OptionsContentLength(options)
	return valid
}

func hasActiveIPv4SourceRoute(options []byte) bool {
	for offset := 0; offset < len(options); {
		kind := options[offset]
		if kind == IPv4HeaderOptionEnd {
			return false
		}
		if kind == IPv4HeaderOptionNOP {
			offset++
			continue
		}
		length := ipv4HeaderOptionLength(options[offset:])
		if length == 0 {
			return false
		}
		if kind == IPv4HeaderOptionLooseSourceRoute || kind == IPv4HeaderOptionStrictSourceRoute {
			if length < 3 {
				return true
			}
			pointer := int(options[offset+2])
			if pointer < 4 || pointer <= length {
				return true
			}
		}
		offset += length
	}
	return false
}

func inspectIPv6OptionsForCodec(header []byte) (valid, homeAddress, jumboPayload bool) {
	if len(header) < 8 || len(header)%8 != 0 {
		return false, false, false
	}
	return inspectIPv6OptionBytesForCodec(header[2:])
}

func inspectIPv6OptionBytesForCodec(options []byte) (valid, homeAddress, jumboPayload bool) {
	for offset := 0; offset < len(options); {
		optionType := options[offset]
		if optionType == IPv6ExtensionOptionPad1 {
			offset++
			continue
		}
		if len(options)-offset < 2 {
			return false, false, false
		}
		length := int(options[offset+1]) + 2
		if length > len(options)-offset {
			return false, false, false
		}
		homeAddress = homeAddress || optionType == IPv6ExtensionOptionHomeAddress
		jumboPayload = jumboPayload || optionType == IPv6ExtensionOptionJumboPayload
		offset += length
	}
	return true, homeAddress, jumboPayload
}

func ipv4RouterAlert(options []byte) bool {
	found := false
	for offset := 0; offset < len(options); {
		kind := options[offset]
		if kind == IPv4HeaderOptionEnd {
			return found
		}
		if kind == IPv4HeaderOptionNOP {
			offset++
			continue
		}
		length := ipv4HeaderOptionLength(options[offset:])
		if length == 0 {
			return false
		}
		if kind == IPv4HeaderOptionRouterAlert {
			if found || length != 4 || options[offset+2] != 0 || options[offset+3] != 0 {
				return false
			}
			found = true
		}
		offset += length
	}
	return found
}

func ipv6RouterAlert(header []byte) bool {
	if len(header) < 2 {
		return false
	}
	found := false
	options := header[2:]
	for offset := 0; offset < len(options); {
		optionType := options[offset]
		length, valid := ipv6ExtensionOptionLength(optionType, options[offset:])
		if !valid {
			return false
		}
		if optionType == IPv6ExtensionOptionRouterAlert {
			if found || length != 4 || options[offset+2] != 0 || options[offset+3] != 0 {
				return false
			}
			found = true
		}
		offset += length
	}
	return found
}

func malformedIPv4Option(options []byte) (int, bool) {
	var sourceRoute, recordRoute, timestamp, routerAlert bool
	for offset := 0; offset < len(options); {
		kind := options[offset]
		switch kind {
		case IPv4HeaderOptionEnd:
			return 0, false
		case IPv4HeaderOptionNOP:
			offset++
			continue
		}
		length := ipv4HeaderOptionLength(options[offset:])
		if length == 0 {
			return offset, true
		}
		switch kind {
		case IPv4HeaderOptionLooseSourceRoute, IPv4HeaderOptionStrictSourceRoute:
			if length < 3 {
				return offset + 1, true
			}
			if options[offset+2] < 4 {
				return offset + 2, true
			}
			if sourceRoute {
				return offset, true
			}
			sourceRoute = true
		case IPv4HeaderOptionRecordRoute:
			if recordRoute {
				return offset, true
			}
			recordRoute = true
			if length < 3 {
				return offset + 1, true
			}
			pointer := int(options[offset+2])
			if pointer < 4 {
				return offset + 2, true
			}
			if pointer <= length && pointer+3 > length {
				return offset + 2, true
			}
		case IPv4HeaderOptionTimestamp:
			if timestamp {
				return offset, true
			}
			timestamp = true
			if length < 4 {
				return offset + 1, true
			}
			pointer := int(options[offset+2])
			if pointer < 5 {
				return offset + 2, true
			}
			flag := options[offset+3] & 0x0f
			if pointer <= length {
				required := 4
				if flag == 1 || flag == 3 {
					required = 8
				}
				if pointer+required-1 > length {
					return offset + 2, true
				}
			} else if flag != 3 && options[offset+3]>>4 == 15 {
				return offset + 3, true
			}
		case IPv4HeaderOptionRouterAlert:
			if length != 4 {
				return offset + 1, true
			}
			if routerAlert {
				return offset, true
			}
			routerAlert = true
		}
		offset += length
	}
	return 0, false
}

func validateIPv4Options(options []byte) bool {
	for offset := 0; offset < len(options); {
		switch options[offset] {
		case IPv4HeaderOptionEnd:
			return true
		case IPv4HeaderOptionNOP:
			offset++
			continue
		case IPv4HeaderOptionLooseSourceRoute, IPv4HeaderOptionStrictSourceRoute:
			return false
		}
		if len(options)-offset < 2 {
			return false
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			return false
		}
		offset += length
	}
	return true
}

func inspectIPv6Options(header []byte) (bool, byte, int) {
	if len(header) < 8 {
		return false, 0, 0
	}
	for offset := 2; offset < len(header); {
		kind := header[offset]
		length, valid := ipv6ExtensionOptionLength(kind, header[offset:])
		if !valid {
			return false, 0, offset
		}
		if action := kind >> 6; action != 0 {
			return false, action, offset
		}
		offset += length
	}
	return true, 0, 0
}

func setPacketECN(packet []byte, ecn byte) {
	if len(packet) < 1 {
		return
	}
	if packet[0]>>4 == 4 && len(packet) >= 20 {
		headerSize := int(packet[0]&0x0f) * 4
		if headerSize < 20 || headerSize > len(packet) {
			return
		}
		packet[1] = packet[1]&^3 | ecn&3
		packet[10], packet[11] = 0, 0
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:headerSize]))
	} else if packet[0]>>4 == 6 && len(packet) >= 40 {
		packet[1] = packet[1]&0xcf | (ecn&3)<<4
	}
}

func ipHeaderSize(source, target netip.Addr, payloadSize int) int {
	source, target = source.Unmap(), target.Unmap()
	if !source.IsValid() || !target.IsValid() || source.Is4() != target.Is4() {
		return 0
	}
	if source.Is4() {
		if payloadSize < 0 || payloadSize > 65515 {
			return 0
		}
		return 20
	}
	if payloadSize < 0 || payloadSize > 65535 {
		return 0
	}
	return 40
}

func marshalIPHeader(packet []byte, source, target netip.Addr, protocol byte, identification uint16, dontFragment bool, options ipPacketOptions) bool {
	source, target = source.Unmap(), target.Unmap()
	headerSize := 20
	if source.Is6() {
		headerSize = 40
	}
	if len(packet) < headerSize || ipHeaderSize(source, target, len(packet)-headerSize) != headerSize {
		return false
	}
	options = options.normalized()
	if source.Is4() {
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		binary.BigEndian.PutUint16(packet[4:6], identification)
		binary.BigEndian.PutUint16(packet[6:8], 0)
		if dontFragment {
			binary.BigEndian.PutUint16(packet[6:8], 0x4000)
		}
		packet[1], packet[8], packet[9] = options.trafficClass, options.hopLimit, protocol
		sourceBytes, targetBytes := source.As4(), target.As4()
		copy(packet[12:16], sourceBytes[:])
		copy(packet[16:20], targetBytes[:])
		binary.BigEndian.PutUint16(packet[10:12], 0)
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
		return true
	}
	packet[0] = 0x60 | options.trafficClass>>4
	packet[1] = options.trafficClass<<4 | byte(options.flowLabel>>16)
	binary.BigEndian.PutUint16(packet[2:4], uint16(options.flowLabel))
	packet[6], packet[7] = protocol, options.hopLimit
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	sourceBytes, targetBytes := source.As16(), target.As16()
	copy(packet[8:24], sourceBytes[:])
	copy(packet[24:40], targetBytes[:])
	return true
}
