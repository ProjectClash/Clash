package mipstack

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"runtime"
	"syscall"
)

const (
	ICMPCodeNone = 0

	ICMPv4TypeEchoReply = 0
	ICMPv4TypeDestinationUnreachable = 3
	ICMPv4TypeEchoRequest = 8
	ICMPv4TypeTimeExceeded = 11
	ICMPv4TypeParameterProblem = 12

	ICMPv6TypeDestinationUnreachable = 1
	ICMPv6TypePacketTooBig = 2
	ICMPv6TypeTimeExceeded = 3
	ICMPv6TypeParameterProblem = 4
	ICMPv6TypeEchoRequest = 128
	ICMPv6TypeEchoReply = 129

	ICMPv4DestinationUnreachableCodeNetwork = 0
	ICMPv4DestinationUnreachableCodeHost = 1
	ICMPv4DestinationUnreachableCodeProtocol = 2
	ICMPv4DestinationUnreachableCodePort = 3
	ICMPv4DestinationUnreachableCodeFragmentationNeeded = 4
	ICMPv4DestinationUnreachableCodeSourceRouteFailed = 5
	ICMPv4DestinationUnreachableCodeNetworkUnknown = 6
	ICMPv4DestinationUnreachableCodeHostUnknown = 7
	ICMPv4DestinationUnreachableCodeSourceHostIsolated = 8
	ICMPv4DestinationUnreachableCodeNetworkAdministrativelyProhibited = 9
	ICMPv4DestinationUnreachableCodeHostAdministrativelyProhibited = 10
	ICMPv4DestinationUnreachableCodeNetworkUnreachableForTOS = 11
	ICMPv4DestinationUnreachableCodeHostUnreachableForTOS = 12
	ICMPv4DestinationUnreachableCodeCommunicationAdministrativelyProhibited = 13
	ICMPv4DestinationUnreachableCodeHostPrecedenceViolation = 14
	ICMPv4DestinationUnreachableCodePrecedenceCutoff = 15

	ICMPv4TimeExceededCodeTTLInTransit = 0
	ICMPv4TimeExceededCodeFragmentReassembly = 1
	ICMPv4ParameterProblemCodePointer = 0
	ICMPv4ParameterProblemCodeMissingOption = 1
	ICMPv4ParameterProblemCodeBadLength = 2

	ICMPv6DestinationUnreachableCodeNoRoute = 0
	ICMPv6DestinationUnreachableCodeAdministrativelyProhibited = 1
	ICMPv6DestinationUnreachableCodeBeyondSourceScope = 2
	ICMPv6DestinationUnreachableCodeAddress = 3
	ICMPv6DestinationUnreachableCodePort = 4
	ICMPv6DestinationUnreachableCodeSourceAddressPolicy = 5
	ICMPv6DestinationUnreachableCodeRejectRoute = 6
	ICMPv6DestinationUnreachableCodeSourceRoutingHeader = 7
	ICMPv6DestinationUnreachableCodeHeadersTooLong = 8
	ICMPv6DestinationUnreachableCodePRoute = 9

	ICMPv6TimeExceededCodeHopLimitInTransit = 0
	ICMPv6TimeExceededCodeFragmentReassembly = 1
	ICMPv6ParameterProblemCodeErroneousHeaderField = 0
	ICMPv6ParameterProblemCodeUnrecognizedNextHeader = 1
	ICMPv6ParameterProblemCodeUnrecognizedOption = 2
	ICMPv6ParameterProblemCodeIncompleteFirstFragment = 3
	ICMPv6ParameterProblemCodeSRUpperLayerHeader = 4
	ICMPv6ParameterProblemCodeUnrecognizedNextHeaderAtIntermediateNode = 5
	ICMPv6ParameterProblemCodeExtensionHeaderTooBig = 6
	ICMPv6ParameterProblemCodeExtensionHeaderChainTooLong = 7
	ICMPv6ParameterProblemCodeTooManyExtensionHeaders = 8
	ICMPv6ParameterProblemCodeTooManyOptionsInExtensionHeader = 9
	ICMPv6ParameterProblemCodeOptionTooBig = 10

	ICMPExtensionClassExtendedInformation = 4
	ICMPExtensionExtendedInformationTypePointer = 1
)

type ICMPMessage struct {
	Source netip.Addr
	Destination netip.Addr
	Type uint8
	Code uint8
	Body []byte
}

func (p IPPacket) ICMPMessage() (ICMPMessage, error) {
	protocol := byte(ProtocolICMPv4)
	if p.Source.Unmap().Is6() {
		protocol = ProtocolICMPv6
	}
	icmp, pseudoHeaderSafe, err := p.upperLayerForProtocol(protocol)
	if err != nil {
		return ICMPMessage{}, err
	}
	if protocol == ProtocolICMPv6 && !pseudoHeaderSafe {
		return ICMPMessage{}, syscall.EPROTONOSUPPORT
	}
	if len(icmp) < 8 {
		return ICMPMessage{}, syscall.EINVAL
	}
	valid := checksum(icmp) == 0
	if protocol == ProtocolICMPv6 {
		valid = transportChecksum(p.Source, p.Destination, ProtocolICMPv6, icmp) == 0
	}
	if !valid {
		return ICMPMessage{}, syscall.EINVAL
	}
	return ICMPMessage{Source: p.Source.Unmap(), Destination: p.Destination.Unmap(), Type: icmp[0], Code: icmp[1], Body: icmp[4:]}, nil
}

func (m ICMPMessage) IsEchoRequest() bool {
	request, ok := m.echoKind()
	return ok && request
}

func (m ICMPMessage) IsEchoReply() bool {
	request, ok := m.echoKind()
	return ok && !request
}

func (m ICMPMessage) Echo() (identifier, sequence uint16, payload []byte, ok bool) {
	if _, ok = m.echoKind(); !ok {
		return 0, 0, nil, false
	}
	return binary.BigEndian.Uint16(m.Body[:2]), binary.BigEndian.Uint16(m.Body[2:4]), m.Body[4:], true
}

func classifyICMPEcho(protocol, messageType, code byte, bodyLength int) (request, ok bool) {
	if bodyLength < 4 || code != ICMPCodeNone {
		return false, false
	}
	switch protocol {
	case ProtocolICMPv4:
		switch messageType {
		case ICMPv4TypeEchoRequest:
			return true, true
		case ICMPv4TypeEchoReply:
			return false, true
		}
	case ProtocolICMPv6:
		switch messageType {
		case ICMPv6TypeEchoRequest:
			return true, true
		case ICMPv6TypeEchoReply:
			return false, true
		}
	}
	return false, false
}

func icmpEchoMessageType(ipv6, request bool) byte {
	if ipv6 {
		if request {
			return ICMPv6TypeEchoRequest
		}
		return ICMPv6TypeEchoReply
	}
	if request {
		return ICMPv4TypeEchoRequest
	}
	return ICMPv4TypeEchoReply
}

func (m *ICMPMessage) SetEchoRequest(identifier, sequence uint16, payload []byte) error {
	return m.setEcho(true, identifier, sequence, payload)
}

func (m *ICMPMessage) SetEchoReply(identifier, sequence uint16, payload []byte) error {
	return m.setEcho(false, identifier, sequence, payload)
}

func (m ICMPMessage) echoKind() (request, ok bool) {
	_, _, protocol, valid := normalizeICMPAddresses(m.Source, m.Destination)
	if !valid {
		return false, false
	}
	return classifyICMPEcho(protocol, m.Type, m.Code, len(m.Body))
}

func (m *ICMPMessage) setEcho(request bool, identifier, sequence uint16, payload []byte) error {
	if m == nil {
		return syscall.EINVAL
	}
	_, _, protocol, valid := normalizeICMPAddresses(m.Source, m.Destination)
	if !valid {
		return syscall.EINVAL
	}
	if len(payload) > 65535-8 {
		return syscall.EMSGSIZE
	}
	body := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(body[:2], identifier)
	binary.BigEndian.PutUint16(body[2:4], sequence)
	copy(body[4:], payload)
	messageType := icmpEchoMessageType(protocol == ProtocolICMPv6, request)
	m.Type, m.Code, m.Body = messageType, ICMPCodeNone, body
	return nil
}

func (m ICMPMessage) EchoReply(source netip.Addr) (ICMPMessage, error) {
	normalized, _, err := m.wireLayout()
	if err != nil {
		return ICMPMessage{}, err
	}
	if !normalized.IsEchoRequest() || source.Zone() != "" {
		return ICMPMessage{}, syscall.EINVAL
	}
	source = source.Unmap()
	if !source.IsValid() || source.Is4() != normalized.Source.Is4() {
		return ICMPMessage{}, syscall.EINVAL
	}
	normalized.Destination = normalized.Source
	normalized.Source = source
	normalized.Type = icmpEchoMessageType(source.Is6(), false)
	return normalized, nil
}

func (m ICMPMessage) IsError() bool {
	_, _, protocol, valid := normalizeICMPAddresses(m.Source, m.Destination)
	if !valid {
		return false
	}
	return isICMPError(protocol, m.Type, m.Code)
}

func (m ICMPMessage) ICMPError() (ICMPError, error) {
	normalized, _, err := m.wireLayout()
	if err != nil {
		return ICMPError{}, err
	}
	protocol := byte(ProtocolICMPv4)
	if normalized.Source.Is6() {
		protocol = ProtocolICMPv6
	}
	result, valid := parseICMPErrorFields(normalized.Source, protocol, normalized.Type, normalized.Code, normalized.Body)
	if !valid {
		return ICMPError{}, syscall.EINVAL
	}
	return result, nil
}

func (m ICMPMessage) MarshalBinary() ([]byte, error) { return m.AppendBinary(nil) }

func (m ICMPMessage) AppendBinary(dst []byte) ([]byte, error) {
	normalized, totalSize, err := m.wireLayout()
	if err != nil {
		return dst, err
	}
	start := len(dst)
	dst = extendForAppend(dst, totalSize)
	marshalPublicICMPMessage(dst[start:], normalized)
	return dst, nil
}

func (m ICMPMessage) wireLayout() (ICMPMessage, int, error) {
	source, destination, _, valid := normalizeICMPAddresses(m.Source, m.Destination)
	if !valid {
		return ICMPMessage{}, 0, syscall.EINVAL
	}
	m.Source, m.Destination = source, destination
	if len(m.Body) < 4 {
		return ICMPMessage{}, 0, syscall.EINVAL
	}
	if len(m.Body) > 65535-4 {
		return ICMPMessage{}, 0, syscall.EMSGSIZE
	}
	return m, 4 + len(m.Body), nil
}

func marshalPublicICMPMessage(dst []byte, m ICMPMessage) {
	copy(dst[4:], m.Body)
	dst[0], dst[1], dst[2], dst[3] = m.Type, m.Code, 0, 0
	value := checksum(dst)
	if m.Source.Is6() {
		value = transportChecksum(m.Source, m.Destination, ProtocolICMPv6, dst)
	}
	binary.BigEndian.PutUint16(dst[2:4], value)
}

type ICMPExtensionObject struct {
	Class uint8
	Type uint8
	Data []byte
}

func (o ICMPExtensionObject) Pointer() (uint32, bool) {
	if o.Class != ICMPExtensionClassExtendedInformation ||
		o.Type != ICMPExtensionExtendedInformationTypePointer || len(o.Data) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(o.Data), true
}

func (o *ICMPExtensionObject) SetPointer(pointer uint32) {
	o.Class = ICMPExtensionClassExtendedInformation
	o.Type = ICMPExtensionExtendedInformationTypePointer
	o.Data = make([]byte, 4)
	binary.BigEndian.PutUint32(o.Data, pointer)
}

type ICMPError struct {
	Reporter netip.Addr
	Type byte
	Code byte
	MTU uint32
	Pointer uint32
	Extensions []byte
	QuotedSource netip.Addr
	QuotedTarget netip.Addr
	QuotedProtocol byte
	QuotedPacket []byte
	QuotedPayload []byte
	QuotedSourcePort uint16
	QuotedTargetPort uint16
}

const (
	icmpExtensionVersion          = 2
	icmpExtensionHeaderSize       = 4
	icmpExtensionObjectHeaderSize = 4
	icmpExtensionMinimumQuoteSize = 128
	maximumICMPExtensionDataSize  = 65535 - 8 - icmpExtensionMinimumQuoteSize - icmpExtensionHeaderSize
)

type icmpExtensionObjectCursor struct {
	remaining []byte
}

func (c *icmpExtensionObjectCursor) next() (object ICMPExtensionObject, ok, valid bool) {
	if len(c.remaining) == 0 {
		return ICMPExtensionObject{}, false, true
	}
	if len(c.remaining) < icmpExtensionObjectHeaderSize {
		return ICMPExtensionObject{}, false, false
	}
	length := int(binary.BigEndian.Uint16(c.remaining[:2]))
	if length < icmpExtensionObjectHeaderSize || length&3 != 0 || length > len(c.remaining) {
		return ICMPExtensionObject{}, false, false
	}
	object = ICMPExtensionObject{
		Class: c.remaining[2], Type: c.remaining[3],
		Data: c.remaining[icmpExtensionObjectHeaderSize:length],
	}
	c.remaining = c.remaining[length:]
	return object, true, true
}

func validateICMPExtensionObjects(encoded []byte) (hasPointer, valid bool) {
	cursor := icmpExtensionObjectCursor{remaining: encoded}
	count := 0
	for {
		object, ok, framingValid := cursor.next()
		if !framingValid {
			return false, false
		}
		if !ok {
			return hasPointer, count != 0
		}
		count++
		if _, pointer := object.Pointer(); pointer {
			hasPointer = true
		}
	}
}

func (e ICMPError) ExtensionObjects() ([]ICMPExtensionObject, error) {
	if len(e.Extensions) == 0 {
		return nil, nil
	}
	cursor := icmpExtensionObjectCursor{remaining: e.Extensions}
	objects := make([]ICMPExtensionObject, 0, 1)
	for {
		object, ok, valid := cursor.next()
		if !valid {
			return nil, syscall.EINVAL
		}
		if !ok {
			return objects, nil
		}
		objects = append(objects, object)
	}
}

func (e *ICMPError) SetExtensionObjects(objects []ICMPExtensionObject) error {
	if e == nil {
		return syscall.EINVAL
	}
	if len(objects) == 0 {
		e.Extensions = nil
		return nil
	}
	size := 0
	for _, object := range objects {
		if len(object.Data) > 1<<16-1-icmpExtensionObjectHeaderSize {
			return syscall.EMSGSIZE
		}
		if len(object.Data)&3 != 0 {
			return syscall.EINVAL
		}
		length := icmpExtensionObjectHeaderSize + len(object.Data)
		if size > maximumICMPExtensionDataSize-length {
			return syscall.EMSGSIZE
		}
		size += length
	}
	encoded := make([]byte, size)
	offset := 0
	for _, object := range objects {
		length := icmpExtensionObjectHeaderSize + len(object.Data)
		binary.BigEndian.PutUint16(encoded[offset:offset+2], uint16(length))
		encoded[offset+2], encoded[offset+3] = object.Class, object.Type
		copy(encoded[offset+icmpExtensionObjectHeaderSize:offset+length], object.Data)
		offset += length
	}
	e.Extensions = encoded
	return nil
}

func icmpErrorFieldKinds(protocol, messageType, code byte) (mtu, pointer bool) {
	mtu = protocol == ProtocolICMPv4 && messageType == ICMPv4TypeDestinationUnreachable && code == ICMPv4DestinationUnreachableCodeFragmentationNeeded ||
		protocol == ProtocolICMPv6 && messageType == ICMPv6TypePacketTooBig
	pointer = protocol == ProtocolICMPv4 && messageType == ICMPv4TypeParameterProblem ||
		protocol == ProtocolICMPv6 && messageType == ICMPv6TypeParameterProblem
	return
}

func marshalICMPErrorBody(body []byte, protocol, messageType, code byte, mtu, pointer uint32, quote []byte) {
	body[0], body[1], body[2], body[3] = 0, 0, 0, 0
	mtuField, pointerField := icmpErrorFieldKinds(protocol, messageType, code)
	if mtuField {
		if protocol == ProtocolICMPv4 {
			binary.BigEndian.PutUint16(body[2:4], uint16(mtu))
		} else {
			binary.BigEndian.PutUint32(body[:4], mtu)
		}
	} else if pointerField {
		if protocol == ProtocolICMPv4 {
			body[0] = byte(pointer)
		} else {
			binary.BigEndian.PutUint32(body[:4], pointer)
		}
	}
	copy(body[4:], quote)
}

func icmpExtensionLayout(protocol, messageType byte) (lengthOffset, unit int, ok bool) {
	if protocol == ProtocolICMPv4 {
		switch messageType {
		case ICMPv4TypeDestinationUnreachable, ICMPv4TypeTimeExceeded, ICMPv4TypeParameterProblem:
			return 1, 4, true
		}
	}
	if protocol == ProtocolICMPv6 {
		switch messageType {
		case ICMPv6TypeDestinationUnreachable, ICMPv6TypeTimeExceeded:
			return 0, 8, true
		}
	}
	return 0, 0, false
}

func parseICMPExtensionStructure(structure []byte) (objects []byte, hasPointer, ok bool) {
	if len(structure) < icmpExtensionHeaderSize+icmpExtensionObjectHeaderSize ||
		structure[0]>>4 != icmpExtensionVersion {
		return nil, false, false
	}
	if binary.BigEndian.Uint16(structure[2:4]) != 0 && checksum(structure) != 0 {
		return nil, false, false
	}
	objects = structure[icmpExtensionHeaderSize:]
	hasPointer, valid := validateICMPExtensionObjects(objects)
	if !valid {
		return nil, false, false
	}
	return objects, hasPointer, true
}

func quotedIPDeclaredLength(quote []byte) (int, bool) {
	if len(quote) == 0 {
		return 0, false
	}
	switch quote[0] >> 4 {
	case 4:
		if len(quote) < 20 {
			return 0, false
		}
		headerSize := int(quote[0]&0x0f) * 4
		totalSize := int(binary.BigEndian.Uint16(quote[2:4]))
		if headerSize < 20 || totalSize < headerSize {
			return 0, false
		}
		return totalSize, true
	case 6:
		if len(quote) < 40 {
			return 0, false
		}
		payloadSize := int(binary.BigEndian.Uint16(quote[4:6]))
		if payloadSize == 0 {
			if quote[6] == IPv6ExtensionHeaderHopByHop {
				return 0, false
			}
			return 40, true
		}
		return 40 + payloadSize, true
	default:
		return 0, false
	}
}

func trimICMPExtensionQuote(quote []byte) ([]byte, bool) {
	declared, known := quotedIPDeclaredLength(quote)
	if !known || declared > len(quote) {
		return quote, true
	}
	for _, value := range quote[declared:] {
		if value != 0 {
			return nil, false
		}
	}
	return quote[:declared], true
}

func splitICMPErrorQuote(protocol, messageType byte, body []byte) (quote, extensions []byte, hasPointer, ok bool) {
	lengthOffset, unit, extensible := icmpExtensionLayout(protocol, messageType)
	if !extensible || body[lengthOffset] == 0 {
		return body[4:], nil, false, true
	}
	paddedLength := int(body[lengthOffset]) * unit
	if paddedLength < icmpExtensionMinimumQuoteSize || len(body) < 4+paddedLength+icmpExtensionHeaderSize+icmpExtensionObjectHeaderSize {
		return nil, nil, false, false
	}
	extensions, hasPointer, valid := parseICMPExtensionStructure(body[4+paddedLength:])
	if !valid {
		return nil, nil, false, false
	}
	quote, valid = trimICMPExtensionQuote(body[4 : 4+paddedLength])
	if !valid {
		return nil, nil, false, false
	}
	return quote, extensions, hasPointer, true
}

func icmpExtensionQuoteLength(protocol, messageType byte, quote []byte) (int, error) {
	_, unit, ok := icmpExtensionLayout(protocol, messageType)
	if !ok {
		return 0, syscall.EINVAL
	}
	if declared, known := quotedIPDeclaredLength(quote); known {
		if declared <= len(quote) {
			for _, value := range quote[declared:] {
				if value != 0 {
					return 0, syscall.EINVAL
				}
			}
		} else if len(quote) < icmpExtensionMinimumQuoteSize {
			return 0, syscall.EINVAL
		}
	} else if len(quote) < icmpExtensionMinimumQuoteSize {
		return 0, syscall.EINVAL
	}
	paddedLength := len(quote)
	if paddedLength < icmpExtensionMinimumQuoteSize {
		paddedLength = icmpExtensionMinimumQuoteSize
	}
	paddedLength = (paddedLength + unit - 1) &^ (unit - 1)
	if paddedLength/unit > 255 {
		return 0, syscall.EMSGSIZE
	}
	return paddedLength, nil
}

func marshalICMPExtensionStructure(structure, objects []byte) {
	structure[0], structure[1], structure[2], structure[3] = icmpExtensionVersion<<4, 0, 0, 0
	copy(structure[icmpExtensionHeaderSize:], objects)
	binary.BigEndian.PutUint16(structure[2:4], checksum(structure))
}

func (e ICMPError) ICMPMessage(destination netip.Addr) (ICMPMessage, error) {
	reporter, destination, protocol, valid := normalizeICMPAddresses(e.Reporter, destination)
	if !valid || !validICMPErrorCode(protocol, e.Type, e.Code) {
		return ICMPMessage{}, syscall.EINVAL
	}
	if len(e.QuotedPacket) > 65535-8 {
		return ICMPMessage{}, syscall.EMSGSIZE
	}
	quotedSource, quotedTarget, _, _, quoted := quotedIPPayload(e.QuotedPacket)
	if !quoted || protocol == ProtocolICMPv4 && (!quotedSource.Is4() || !quotedTarget.Is4()) ||
		protocol == ProtocolICMPv6 && (!quotedSource.Is6() || !quotedTarget.Is6()) {
		return ICMPMessage{}, syscall.EINVAL
	}
	mtuField, pointerField := icmpErrorFieldKinds(protocol, e.Type, e.Code)
	if !mtuField && e.MTU != 0 || !pointerField && e.Pointer != 0 ||
		protocol == ProtocolICMPv4 && mtuField && e.MTU > 1<<16-1 ||
		protocol == ProtocolICMPv4 && pointerField && e.Pointer > 1<<8-1 {
		return ICMPMessage{}, syscall.EINVAL
	}
	if len(e.Extensions) == 0 {
		if protocol == ProtocolICMPv6 && e.Type == ICMPv6TypeDestinationUnreachable &&
			e.Code == ICMPv6DestinationUnreachableCodeHeadersTooLong {
			return ICMPMessage{}, syscall.EINVAL
		}
		body := make([]byte, 4+len(e.QuotedPacket))
		marshalICMPErrorBody(body, protocol, e.Type, e.Code, e.MTU, e.Pointer, e.QuotedPacket)
		return ICMPMessage{Source: reporter, Destination: destination, Type: e.Type, Code: e.Code, Body: body}, nil
	}
	if len(e.Extensions) > maximumICMPExtensionDataSize {
		return ICMPMessage{}, syscall.EMSGSIZE
	}
	hasPointer, validExtensions := validateICMPExtensionObjects(e.Extensions)
	if !validExtensions || protocol == ProtocolICMPv6 && e.Type == ICMPv6TypeDestinationUnreachable &&
		e.Code == ICMPv6DestinationUnreachableCodeHeadersTooLong && !hasPointer {
		return ICMPMessage{}, syscall.EINVAL
	}
	paddedQuoteLength, err := icmpExtensionQuoteLength(protocol, e.Type, e.QuotedPacket)
	if err != nil {
		return ICMPMessage{}, err
	}
	bodyLength := 4 + paddedQuoteLength + icmpExtensionHeaderSize + len(e.Extensions)
	if bodyLength > 65535-4 {
		return ICMPMessage{}, syscall.EMSGSIZE
	}
	body := make([]byte, bodyLength)
	marshalICMPErrorBody(body, protocol, e.Type, e.Code, e.MTU, e.Pointer, e.QuotedPacket)
	lengthOffset, unit, _ := icmpExtensionLayout(protocol, e.Type)
	body[lengthOffset] = byte(paddedQuoteLength / unit)
	marshalICMPExtensionStructure(body[4+paddedQuoteLength:], e.Extensions)
	return ICMPMessage{Source: reporter, Destination: destination, Type: e.Type, Code: e.Code, Body: body}, nil
}

func normalizeICMPAddresses(source, destination netip.Addr) (netip.Addr, netip.Addr, byte, bool) {
	if source.Zone() != "" || destination.Zone() != "" {
		return netip.Addr{}, netip.Addr{}, 0, false
	}
	source, destination = source.Unmap(), destination.Unmap()
	if !source.IsValid() || !destination.IsValid() || source.Is4() != destination.Is4() {
		return netip.Addr{}, netip.Addr{}, 0, false
	}
	if source.Is4() {
		return source, destination, ProtocolICMPv4, true
	}
	return source, destination, ProtocolICMPv6, true
}

type icmpForwarderIPPacket struct {
	packet       []byte
	parsed       ipPacket
	ipv4DF       bool
	ipv6Fragment ipv6FragmentPoint
}

func validateICMPForwarderReplyPayload(ipv6 bool, payload []byte) error {
	if len(payload) < 8 {
		return syscall.EINVAL
	}
	maximum := 65535
	if !ipv6 {
		maximum -= 20
	}
	if len(payload) > maximum {
		return syscall.EMSGSIZE
	}
	if ipv6 && payload[0] < 128 && len(payload) > ipv6MinimumMTU-40 {
		return syscall.EMSGSIZE
	}
	return nil
}

func prepareICMPForwarderIPPacket(input []byte, destination netip.Addr) (icmpForwarderIPPacket, error) {
	destination = destination.Unmap()
	if !destination.IsValid() || len(input) == 0 {
		return icmpForwarderIPPacket{}, syscall.EINVAL
	}
	switch input[0] >> 4 {
	case 4:
		if len(input) > 65535 {
			return icmpForwarderIPPacket{}, syscall.EMSGSIZE
		}
	case 6:
		if len(input)-40 > 65535 {
			return icmpForwarderIPPacket{}, syscall.EMSGSIZE
		}
	default:
		return icmpForwarderIPPacket{}, syscall.EINVAL
	}
	packet := append([]byte(nil), input...)
	result := icmpForwarderIPPacket{packet: packet}
	switch packet[0] >> 4 {
	case 4:
		if destination.Is6() || len(packet) < 28 || len(packet) > 65535 {
			return icmpForwarderIPPacket{}, syscall.EINVAL
		}
		headerSize := int(packet[0]&0x0f) * 4
		field := binary.BigEndian.Uint16(packet[6:8])
		if headerSize < 20 || headerSize > len(packet)-8 || field&0xbfff != 0 || packet[9] != ProtocolICMPv4 {
			return icmpForwarderIPPacket{}, syscall.EINVAL
		}
		contentSize, validOptions := ipv4OptionsContentLength(packet[20:headerSize])
		if !validOptions {
			return icmpForwarderIPPacket{}, syscall.EINVAL
		}
		for index := 20 + contentSize; index < headerSize; index++ {
			packet[index] = 0
		}
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		packet[10], packet[11] = 0, 0
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:headerSize]))
		result.ipv4DF = field&0x4000 != 0
	case 6:
		if destination.Is4() || len(packet) < 48 || len(packet)-40 > 65535 {
			return icmpForwarderIPPacket{}, syscall.EINVAL
		}
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
		point, ok := inspectIPv6ForwarderFragmentPoint(packet)
		if !ok {
			return icmpForwarderIPPacket{}, syscall.EINVAL
		}
		result.ipv6Fragment = point
		if point.atomicOffset >= 0 {
			packet[point.atomicOffset+1] = 0
			binary.BigEndian.PutUint16(packet[point.atomicOffset+2:point.atomicOffset+4], 0)
		}
	default:
		return icmpForwarderIPPacket{}, syscall.EINVAL
	}
	parsed, ok := parseIPPacket(packet, false)
	if !ok || parsed.parameterError || len(parsed.payload) < 8 || parsed.target != destination {
		return icmpForwarderIPPacket{}, syscall.EINVAL
	}
	if parsed.source.Is4() {
		if parsed.protocol != ProtocolICMPv4 {
			return icmpForwarderIPPacket{}, syscall.EINVAL
		}
		parsed.payload[2], parsed.payload[3] = 0, 0
		binary.BigEndian.PutUint16(parsed.payload[2:4], checksum(parsed.payload))
	} else {
		if parsed.protocol != ProtocolICMPv6 {
			return icmpForwarderIPPacket{}, syscall.EINVAL
		}
		if parsed.payload[0] < 128 && len(packet) > ipv6MinimumMTU {
			return icmpForwarderIPPacket{}, syscall.EMSGSIZE
		}
		parsed.payload[2], parsed.payload[3] = 0, 0
		binary.BigEndian.PutUint16(parsed.payload[2:4], transportChecksum(parsed.source, parsed.target, ProtocolICMPv6, parsed.payload))
	}
	result.parsed = parsed
	return result, nil
}

func (s *Stack) writeICMPForwarderIPPacket(request ipPacket, reply icmpForwarderIPPacket) error {
	state := s.network.Load()
	if !state.acceptsInboundDestination(request.target) {
		return syscall.EADDRNOTAVAIL
	}
	if _, routed := state.routeFor(reply.parsed.target); !routed {
		return syscall.ENETUNREACH
	}
	packets, err := s.icmpForwarderIPPackets(reply, s.mtuFor(reply.parsed.target))
	if err != nil {
		return err
	}
	var flow outputFlowKey
	if len(packets) > 1 {
		flow = s.outbound.ipFlowKey(reply.parsed.source, reply.parsed.target, reply.parsed.protocol, reply.parsed.flowLabel, reply.parsed.payload)
	}
	err = s.tryWritePackets(packets, flow, true)
	if err == ErrResourceLimit {
		return nil
	}
	return err
}

func (e ICMPError) Error() string {
	if e.MTU != 0 {
		return fmt.Sprintf("ICMP error from %s: type=%d code=%d mtu=%d", e.Reporter, e.Type, e.Code, e.MTU)
	}
	return fmt.Sprintf("ICMP error from %s: type=%d code=%d", e.Reporter, e.Type, e.Code)
}

func (e ICMPError) Unwrap() error {
	e.Reporter = e.Reporter.Unmap()
	protocol := byte(ProtocolICMPv6)
	if e.Reporter.Is4() {
		protocol = ProtocolICMPv4
	} else if !e.Reporter.Is6() {
		return nil
	}
	if !isICMPError(protocol, e.Type, e.Code) {
		return nil
	}
	switch linuxICMPErrno(e) {
	case 13:
		return syscall.EACCES
	case 64:
		switch runtime.GOOS {
		case "windows":
			return syscall.Errno(1<<29 + 81)
		case "linux", "android", "solaris", "illumos", "js":
			return syscall.Errno(64)
		default:
			return syscall.ENETUNREACH
		}
	case 71:
		return syscall.EPROTO
	case 90:
		return syscall.EMSGSIZE
	case 92:
		return syscall.ENOPROTOOPT
	case 95:
		return syscall.EOPNOTSUPP
	case 101:
		return syscall.ENETUNREACH
	case 111:
		return syscall.ECONNREFUSED
	case 112:
		switch runtime.GOOS {
		case "windows":
			return syscall.Errno(1<<29 + 33)
		case "darwin", "ios", "dragonfly", "freebsd", "netbsd", "openbsd":
			return syscall.Errno(64)
		case "solaris", "illumos":
			return syscall.Errno(147)
		case "aix":
			return syscall.Errno(80)
		case "linux", "android", "js":
			switch runtime.GOARCH {
			case "mips", "mipsle", "mips64", "mips64le":
				return syscall.Errno(147)
			}
			return syscall.Errno(112)
		default:
			return syscall.EHOSTUNREACH
		}
	case 113:
		return syscall.EHOSTUNREACH
	default:
		return nil
	}
}

func makeICMPEchoReply(protocol byte, request []byte) ([]byte, bool) {
	if len(request) < 4 {
		return nil, false
	}
	isRequest, ok := classifyICMPEcho(protocol, request[0], request[1], len(request)-4)
	if !ok || !isRequest {
		return nil, false
	}
	replyType := icmpEchoMessageType(protocol == ProtocolICMPv6, false)
	reply := append([]byte(nil), request...)
	reply[0], reply[2], reply[3] = replyType, 0, 0
	return reply, true
}

func (s *Stack) handleICMP(packet ipPacket, localDestination, skipChecksum bool) error {
	icmp := packet.payload
	if len(icmp) < 8 {
		return nil
	}
	if packet.protocol == ProtocolICMPv4 {
		if !skipChecksum && checksum(icmp) != 0 {
			return nil
		}
		if localDestination {
			if reply, echoRequest := makeICMPEchoReply(packet.protocol, icmp); echoRequest {
				if !s.allowControlResponse(controlResponseEchoReply) {
					return nil
				}
				binary.BigEndian.PutUint16(reply[2:4], checksum(reply))
				_ = s.writeIPPayload(packet.target, packet.source, ProtocolICMPv4, reply, true)
				return nil
			}
		}
	} else {
		if localDestination {
			if reply, echoRequest := makeICMPEchoReply(packet.protocol, icmp); echoRequest {
				if !s.allowControlResponse(controlResponseEchoReply) {
					return nil
				}
				binary.BigEndian.PutUint16(reply[2:4], transportChecksum(packet.target, packet.source, ProtocolICMPv6, reply))
				_ = s.writeIPPayload(packet.target, packet.source, ProtocolICMPv6, reply, true)
				return nil
			}
		}
	}
	remoteError, ok := parseICMPError(packet)
	if ok && s.deliverICMPError(remoteError) {
		return nil
	}
	s.mu.RLock()
	forwarder := s.icmpForwarder
	s.mu.RUnlock()
	if forwarder != nil && forwarder.handlePacket(packet) {
		return nil
	}
	return nil
}

func (s *Stack) handleMulticastICMPv6(packet ipPacket) error {
	icmp := packet.payload
	if len(icmp) < 8 {
		return nil
	}
	reply, echoRequest := makeICMPEchoReply(ProtocolICMPv6, icmp)
	if !echoRequest || !s.allowControlResponse(controlResponseEchoReply) {
		return nil
	}
	source, err := s.sourceForRequested(packet.source, netip.Addr{})
	if err != nil {
		return nil
	}
	binary.BigEndian.PutUint16(reply[2:4], transportChecksum(source, packet.source, ProtocolICMPv6, reply))
	_ = s.writeIPPayload(source, packet.source, ProtocolICMPv6, reply, true)
	return nil
}

func (s *Stack) deliverICMPError(remoteError ICMPError) bool {
	if remoteError.Type == ICMPv4TypeTimeExceeded &&
		remoteError.Code == ICMPv4TimeExceededCodeFragmentReassembly && remoteError.Reporter.Is4() {
		return false
	}
	accepted := false
	switch remoteError.QuotedProtocol {
	case ProtocolUDP:
		if len(remoteError.QuotedPayload) >= udpHeaderSize {
			sourcePort := remoteError.QuotedSourcePort
			targetPort := remoteError.QuotedTargetPort
			local := netip.AddrPortFrom(remoteError.QuotedSource, sourcePort)
			target := netip.AddrPortFrom(remoteError.QuotedTarget, targetPort)
			s.mu.RLock()
			var connection *UDPConn
			if s.isLocal(remoteError.QuotedSource) {
				connection = s.udpConnectionLocked(local, target)
			} else {
				connection = s.udpForwardedConnectionLocked(local, target)
			}
			s.mu.RUnlock()
			if connection != nil && connection.acceptsLocal(remoteError.QuotedSource) && connection.acceptsError(target) {
				if remoteError.MTU != 0 && connection.acceptsPathMTU() {
					if s.observePathMTU(remoteError.QuotedTarget, remoteError.MTU) {
						s.notifyTCPPathMTU(remoteError.QuotedTarget, nil)
					}
				}
				connection.deliverError(target, cloneICMPError(remoteError))
				accepted = true
			}
		}
	case ProtocolTCP:
		if len(remoteError.QuotedPayload) >= 8 {
			sourcePort := remoteError.QuotedSourcePort
			targetPort := remoteError.QuotedTargetPort
			key := tcpKey{
				local:  netip.AddrPortFrom(remoteError.QuotedSource, sourcePort),
				remote: netip.AddrPortFrom(remoteError.QuotedTarget, targetPort),
			}
			s.mu.RLock()
			connection := s.tcp[key]
			s.mu.RUnlock()
			if connection != nil && connection.acceptsICMPQuote(remoteError.QuotedPayload) {
				if remoteError.MTU != 0 {
					if s.observePathMTU(remoteError.QuotedTarget, remoteError.MTU) {
						s.notifyTCPPathMTU(remoteError.QuotedTarget, nil)
					}
				}
				connection.deliverError(cloneICMPError(remoteError))
				accepted = true
			}
		}
	}
	if s.isLocal(remoteError.QuotedSource) {
		s.mu.RLock()
		raw := s.ip
		s.mu.RUnlock()
		if raw != nil && raw.deliverError(s, remoteError) {
			accepted = true
		}
	}
	return accepted
}

func (s *Stack) writeICMPReply(packet ipPacket, payload []byte) error {
	if len(payload) < 8 {
		return syscall.EINVAL
	}
	return s.writeOwnedICMPReply(packet, append([]byte(nil), payload...))
}

func (s *Stack) writeOwnedICMPReply(packet ipPacket, reply []byte) error {
	if err := validateICMPForwarderReplyPayload(packet.source.Is6(), reply); err != nil {
		return err
	}
	state := s.network.Load()
	if _, routed := state.routeFor(packet.source); !routed {
		return syscall.ENETUNREACH
	}
	if !state.acceptsInboundDestination(packet.target) {
		return syscall.EADDRNOTAVAIL
	}
	reply[2], reply[3] = 0, 0
	if packet.source.Is4() {
		binary.BigEndian.PutUint16(reply[2:4], checksum(reply))
		return s.writeIPPayload(packet.target, packet.source, ProtocolICMPv4, reply, true)
	}
	binary.BigEndian.PutUint16(reply[2:4], transportChecksum(packet.target, packet.source, ProtocolICMPv6, reply))
	return s.writeIPPayload(packet.target, packet.source, ProtocolICMPv6, reply, true)
}

func (s *Stack) writeICMPError(source, target netip.Addr, messageType, code byte, mtu, pointer uint32, quote []byte) error {
	protocol := byte(ProtocolICMPv4)
	if source.Is6() {
		protocol = ProtocolICMPv6
	}
	payload := make([]byte, 8+len(quote))
	body := payload[4:]
	marshalICMPErrorBody(body, protocol, messageType, code, mtu, pointer, quote)
	marshalPublicICMPMessage(payload, ICMPMessage{
		Source: source, Destination: target, Type: messageType, Code: code, Body: body,
	})
	return s.writeIPPayload(source, target, protocol, payload, false)
}

func icmpErrorQuote(packet []byte, ipv6 bool) []byte {
	quoteLength := len(packet)
	if !ipv6 {
		headerSize := int(packet[0]&0x0f) * 4
		if quoteLength > headerSize+8 {
			quoteLength = headerSize + 8
		}
	} else if maximum := ipv6MinimumMTU - 48; quoteLength > maximum {
		quoteLength = maximum
	}
	return packet[:quoteLength]
}

func (s *Stack) sendAdministrativeUnreachable(packet ipPacket) error {
	state := s.network.Load()
	if !state.acceptsInboundDestination(packet.target) {
		return syscall.EADDRNOTAVAIL
	}
	if packetInvokesICMPError(packet.original) {
		return nil
	}
	if _, routed := state.routeFor(packet.source); !routed {
		return syscall.ENETUNREACH
	}
	if !s.allowICMPErrorResponseTo(icmpErrorResponsePortUnreachable, packet.source) {
		return nil
	}
	if packet.source.Is4() {
		return s.writeICMPError(packet.target, packet.source, ICMPv4TypeDestinationUnreachable,
			ICMPv4DestinationUnreachableCodeCommunicationAdministrativelyProhibited, 0, 0, icmpErrorQuote(packet.original, false))
	}
	return s.writeICMPError(packet.target, packet.source, ICMPv6TypeDestinationUnreachable,
		ICMPv6DestinationUnreachableCodeAdministrativelyProhibited, 0, 0, icmpErrorQuote(packet.original, true))
}

func (s *Stack) sendFragmentReassemblyTimeout(entry *ipPacketReassemblyEntry) error {
	state := &entry.state
	if !s.isLocal(state.target) {
		return nil
	}
	fragment, ok := parseFragment(state.firstPacket, true)
	if !ok || fragment.offset != 0 || packetInvokesICMPError(state.firstPacket) || !s.allowICMPErrorResponseTo(icmpErrorResponseFragmentTimeout, state.source) {
		return nil
	}
	if !state.v6 {
		return s.writeICMPError(state.target, state.source, ICMPv4TypeTimeExceeded,
			ICMPv4TimeExceededCodeFragmentReassembly, 0, 0, icmpErrorQuote(state.firstPacket, false))
	}
	return s.writeICMPError(state.target, state.source, ICMPv6TypeTimeExceeded,
		ICMPv6TimeExceededCodeFragmentReassembly, 0, 0, icmpErrorQuote(state.firstPacket, true))
}

func packetInvokesICMPError(packet []byte) bool {
	source, _, protocol, payload, ok := quotedIPPayload(packet)
	if !ok || len(payload) == 0 {
		return false
	}
	if source.Is4() {
		if protocol != ProtocolICMPv4 {
			return false
		}
		switch payload[0] {
		case ICMPv4TypeDestinationUnreachable, 4, 5, ICMPv4TypeTimeExceeded, ICMPv4TypeParameterProblem:
			return true
		}
		return false
	}
	return protocol == ProtocolICMPv6 && payload[0] < 128
}

func parseICMPError(packet ipPacket) (ICMPError, bool) {
	icmp := packet.payload
	if len(icmp) < 8 {
		return ICMPError{}, false
	}
	return parseICMPErrorFields(packet.source, packet.protocol, icmp[0], icmp[1], icmp[4:])
}

func parseICMPErrorFields(reporter netip.Addr, protocol, messageType, code byte, body []byte) (ICMPError, bool) {
	if len(body) < 4 || !isICMPError(protocol, messageType, code) {
		return ICMPError{}, false
	}
	quote := body[4:]
	var extensions []byte
	hasExtensionPointer := false
	if lengthOffset, _, extensible := icmpExtensionLayout(protocol, messageType); extensible && body[lengthOffset] != 0 {
		var split bool
		quote, extensions, hasExtensionPointer, split = splitICMPErrorQuote(protocol, messageType, body)
		if !split {
			return ICMPError{}, false
		}
	}
	if protocol == ProtocolICMPv6 && messageType == ICMPv6TypeDestinationUnreachable &&
		code == ICMPv6DestinationUnreachableCodeHeadersTooLong && !hasExtensionPointer {
		return ICMPError{}, false
	}
	source, target, quotedProtocol, payload, ok := quotedIPPayload(quote)
	if !ok || protocol == ProtocolICMPv4 && (!source.Is4() || !target.Is4()) ||
		protocol == ProtocolICMPv6 && (!source.Is6() || !target.Is6()) {
		return ICMPError{}, false
	}
	if protocol != ProtocolICMPv4 && protocol != ProtocolICMPv6 {
		return ICMPError{}, false
	}
	result := ICMPError{
		Reporter: reporter, Type: messageType, Code: code,
		Extensions:   extensions,
		QuotedSource: source, QuotedTarget: target, QuotedProtocol: quotedProtocol,
		QuotedPacket: quote, QuotedPayload: payload,
	}
	if (quotedProtocol == ProtocolTCP || quotedProtocol == ProtocolUDP) && len(payload) >= 4 {
		result.QuotedSourcePort = binary.BigEndian.Uint16(payload[:2])
		result.QuotedTargetPort = binary.BigEndian.Uint16(payload[2:4])
	}
	if protocol == ProtocolICMPv4 {
		if messageType == ICMPv4TypeDestinationUnreachable && code == ICMPv4DestinationUnreachableCodeFragmentationNeeded {
			result.MTU = uint32(binary.BigEndian.Uint16(body[2:4]))
			if result.MTU == 0 {
				result.MTU = legacyIPv4PathMTU(quote)
			}
		}
		if messageType == ICMPv4TypeParameterProblem {
			result.Pointer = uint32(body[0])
		}
	} else {
		if messageType == ICMPv6TypePacketTooBig {
			result.MTU = binary.BigEndian.Uint32(body[:4])
		}
		if messageType == ICMPv6TypeParameterProblem {
			result.Pointer = binary.BigEndian.Uint32(body[:4])
		}
	}
	return result, true
}

func cloneICMPError(networkError ICMPError) ICMPError {
	payloadOffset := 0
	payloadAliasesPacket := false
	if len(networkError.QuotedPacket) != 0 && len(networkError.QuotedPayload) != 0 &&
		len(networkError.QuotedPayload) <= len(networkError.QuotedPacket) {
		payloadOffset = len(networkError.QuotedPacket) - len(networkError.QuotedPayload)
		payloadAliasesPacket = &networkError.QuotedPayload[0] == &networkError.QuotedPacket[payloadOffset]
	}
	packetLength := len(networkError.QuotedPacket)
	extensionLength := len(networkError.Extensions)
	if packetLength+extensionLength != 0 {
		storage := make([]byte, packetLength+extensionLength)
		copy(storage, networkError.QuotedPacket)
		copy(storage[packetLength:], networkError.Extensions)
		if packetLength != 0 {
			networkError.QuotedPacket = storage[:packetLength:packetLength]
		} else {
			networkError.QuotedPacket = nil
		}
		if extensionLength != 0 {
			networkError.Extensions = storage[packetLength:]
		} else {
			networkError.Extensions = nil
		}
	}
	if payloadAliasesPacket {
		networkError.QuotedPayload = networkError.QuotedPacket[payloadOffset:]
	} else {
		networkError.QuotedPayload = append([]byte(nil), networkError.QuotedPayload...)
	}
	return networkError
}

func isICMPError(protocol, messageType, code byte) bool {
	if protocol == ProtocolICMPv6 {
		switch messageType {
		case ICMPv6TypePacketTooBig:
			return true
		case ICMPv6TypeDestinationUnreachable, ICMPv6TypeTimeExceeded, ICMPv6TypeParameterProblem:
		default:
			return messageType < 128
		}
	}
	return validICMPErrorCode(protocol, messageType, code)
}

func validICMPErrorCode(protocol, messageType, code byte) bool {
	switch protocol {
	case ProtocolICMPv4:
		switch messageType {
		case ICMPv4TypeDestinationUnreachable:
			return code <= ICMPv4DestinationUnreachableCodePrecedenceCutoff
		case ICMPv4TypeTimeExceeded:
			return code <= ICMPv4TimeExceededCodeFragmentReassembly
		case ICMPv4TypeParameterProblem:
			return code <= ICMPv4ParameterProblemCodeBadLength
		}
	case ProtocolICMPv6:
		switch messageType {
		case ICMPv6TypeDestinationUnreachable:
			return code <= ICMPv6DestinationUnreachableCodePRoute
		case ICMPv6TypePacketTooBig:
			return code == ICMPCodeNone
		case ICMPv6TypeTimeExceeded:
			return code <= ICMPv6TimeExceededCodeFragmentReassembly
		case ICMPv6TypeParameterProblem:
			return code <= ICMPv6ParameterProblemCodeOptionTooBig
		}
	}
	return false
}

func legacyIPv4PathMTU(quoted []byte) uint32 {
	if len(quoted) < 20 || quoted[0]>>4 != 4 {
		return 0
	}
	total := uint32(binary.BigEndian.Uint16(quoted[2:4]))
	headerSize := uint32(quoted[0]&0x0f) * 4
	if headerSize < 20 || total < headerSize {
		return 0
	}
	for _, plateau := range [...]uint32{65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68} {
		if plateau < total {
			return plateau
		}
	}
	return 68
}

func quotedIPPayload(packet []byte) (netip.Addr, netip.Addr, byte, []byte, bool) {
	if len(packet) < 1 {
		return netip.Addr{}, netip.Addr{}, 0, nil, false
	}
	if packet[0]>>4 == 4 {
		if len(packet) < 20 {
			return netip.Addr{}, netip.Addr{}, 0, nil, false
		}
		headerSize := int(packet[0]&0x0f) * 4
		if headerSize < 20 || headerSize > len(packet) || binary.BigEndian.Uint16(packet[6:8])&0x1fff != 0 {
			return netip.Addr{}, netip.Addr{}, 0, nil, false
		}
		return netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])), packet[9], packet[headerSize:], true
	}
	if packet[0]>>4 == 6 && len(packet) >= 40 {
		source := netip.AddrFrom16([16]byte(packet[8:24]))
		target := netip.AddrFrom16([16]byte(packet[24:40]))
		if source.Is4In6() || target.Is4In6() {
			return netip.Addr{}, netip.Addr{}, 0, nil, false
		}
		payload := packet[40:]
		next, offset := packet[6], 0
		for {
			if next == ProtocolNoNextHeader {
				return source, target, next, nil, true
			}
			switch next {
			case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderRouting,
				IPv6ExtensionHeaderDestination, IPv6ExtensionHeaderAuthentication:
				length, valid := ipv6ExtensionHeaderLength(next, payload[offset:])
				if !valid {
					return netip.Addr{}, netip.Addr{}, 0, nil, false
				}
				next, offset = payload[offset], offset+length
			case IPv6ExtensionHeaderFragment:
				if len(payload)-offset < 8 {
					return netip.Addr{}, netip.Addr{}, 0, nil, false
				}
				header := payload[offset : offset+8]
				next, offset = header[0], offset+8
				if binary.BigEndian.Uint16(header[2:4])&0xfff8 != 0 {
					return netip.Addr{}, netip.Addr{}, 0, nil, false
				}
			default:
				return source, target, next, payload[offset:], true
			}
		}
	}
	return netip.Addr{}, netip.Addr{}, 0, nil, false
}

func (s *Stack) sendPortUnreachable(packet ipPacket) error {
	state := s.network.Load()
	if !state.acceptsInboundDestination(packet.target) {
		return syscall.EADDRNOTAVAIL
	}
	if _, routed := state.routeFor(packet.source); !routed {
		return syscall.ENETUNREACH
	}
	if !s.allowICMPErrorResponseTo(icmpErrorResponsePortUnreachable, packet.source) {
		return nil
	}
	if packet.source.Is4() {
		return s.writeICMPError(packet.target, packet.source, ICMPv4TypeDestinationUnreachable,
			ICMPv4DestinationUnreachableCodePort, 0, 0, icmpErrorQuote(packet.original, false))
	}
	return s.writeICMPError(packet.target, packet.source, ICMPv6TypeDestinationUnreachable,
		ICMPv6DestinationUnreachableCodePort, 0, 0, icmpErrorQuote(packet.original, true))
}

func (s *Stack) sendProtocolUnreachable(packet ipPacket) error {
	state := s.network.Load()
	if !state.acceptsInboundDestination(packet.target) {
		return syscall.EADDRNOTAVAIL
	}
	if _, routed := state.routeFor(packet.source); !routed {
		return syscall.ENETUNREACH
	}
	if !s.allowICMPErrorResponseTo(icmpErrorResponseParameterProblem, packet.source) {
		return nil
	}
	if packet.source.Is4() {
		return s.writeICMPError(packet.target, packet.source, ICMPv4TypeDestinationUnreachable,
			ICMPv4DestinationUnreachableCodeProtocol, 0, 0, icmpErrorQuote(packet.original, false))
	}
	return s.writeICMPError(packet.target, packet.source, ICMPv6TypeParameterProblem,
		ICMPv6ParameterProblemCodeUnrecognizedNextHeader, 0, uint32(packet.protocolOffset), icmpErrorQuote(packet.original, true))
}

func (s *Stack) sendParameterProblem(packet ipPacket) error {
	if !packet.source.Is4() && !packet.source.Is6() {
		return nil
	}
	if packet.source.Is4() {
		if len(packet.original) < 20 || binary.BigEndian.Uint16(packet.original[6:8])&0x1fff != 0 {
			return nil
		}
		if packetInvokesICMPError(packet.original) || !s.allowICMPErrorResponseTo(icmpErrorResponseParameterProblem, packet.source) {
			return nil
		}
		return s.writeICMPError(packet.target, packet.source, ICMPv4TypeParameterProblem,
			packet.parameterCode, 0, packet.parameterAt, icmpErrorQuote(packet.original, false))
	}
	if packetInvokesICMPError(packet.original) || !s.allowICMPErrorResponseTo(icmpErrorResponseParameterProblem, packet.source) {
		return nil
	}
	return s.writeICMPError(packet.target, packet.source, ICMPv6TypeParameterProblem,
		packet.parameterCode, 0, packet.parameterAt, icmpErrorQuote(packet.original, true))
}
