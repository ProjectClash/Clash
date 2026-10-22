package mipstack

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	linuxControlHeaderSize = 16
	linuxControlAlignment = 8
	linuxLevelIP = 0
	linuxIPTypeOfService = 1
	linuxIPTimeToLive = 2
	linuxIPPacketInfo = 8
	linuxIPReceiveError = 11
	linuxLevelIPv6 = 41
	linuxIPv6FlowInfo = 11
	linuxIPv6FlowInfoMask = 0x0fffffff
	linuxIPv6ReceiveError = 25
	linuxIPv6PacketInfo = 50
	linuxIPv6HopLimit = 52
	linuxIPv6TrafficClass = 67
)

type SocketErrorOrigin uint8

const (
	SocketErrorOriginNone SocketErrorOrigin = iota
	SocketErrorOriginLocal
	SocketErrorOriginICMP
	SocketErrorOriginICMP6
	SocketErrorOriginTXStatus
	SocketErrorOriginZeroCopy
	SocketErrorOriginTXTime
)

type SocketErrorControlMessage struct {
	Errno uint32
	Origin SocketErrorOrigin
	Type uint8
	Code uint8
	Info uint32
	Data uint32
	Offender netip.Addr
}

func (message SocketErrorControlMessage) MarshalBinary() ([]byte, error) {
	return message.AppendBinary(nil)
}

func (message SocketErrorControlMessage) AppendBinary(dst []byte) ([]byte, error) {
	if !message.Offender.IsValid() || message.Offender.Zone() != "" {
		return dst, errors.New("mipstack: invalid socket-error control-message offender")
	}
	offender := message.Offender
	var data [44]byte
	binary.LittleEndian.PutUint32(data[:4], message.Errno)
	data[4], data[5], data[6] = byte(message.Origin), message.Type, message.Code
	binary.LittleEndian.PutUint32(data[8:12], message.Info)
	binary.LittleEndian.PutUint32(data[12:16], message.Data)
	level, kind, size := uint32(linuxLevelIP), uint32(linuxIPReceiveError), 32
	if offender.Is4() {
		binary.LittleEndian.PutUint16(data[16:18], 2)
		address := offender.As4()
		copy(data[20:24], address[:])
	} else {
		level, kind, size = linuxLevelIPv6, linuxIPv6ReceiveError, 44
		binary.LittleEndian.PutUint16(data[16:18], 10)
		address := offender.As16()
		copy(data[24:40], address[:])
	}
	return appendLinuxControl(dst, level, kind, data[:size]), nil
}

func (message *SocketErrorControlMessage) Parse(control []byte) error {
	if message == nil {
		return errors.New("mipstack: nil socket-error control-message receiver")
	}
	var parsed SocketErrorControlMessage
	found := false
	for len(control) >= linuxControlHeaderSize {
		length64 := binary.LittleEndian.Uint64(control[:8])
		if length64 < linuxControlHeaderSize || length64 > uint64(len(control)) {
			return errors.New("mipstack: invalid Linux control length")
		}
		length := int(length64)
		level := binary.LittleEndian.Uint32(control[8:12])
		kind := binary.LittleEndian.Uint32(control[12:16])
		if level == linuxLevelIP && kind == linuxIPReceiveError || level == linuxLevelIPv6 && kind == linuxIPv6ReceiveError {
			if found {
				return errors.New("mipstack: duplicate socket-error control message")
			}
			value, err := parseSocketErrorControl(level == linuxLevelIPv6, control[linuxControlHeaderSize:length])
			if err != nil {
				return err
			}
			parsed, found = value, true
		}
		aligned := (length + linuxControlAlignment - 1) &^ (linuxControlAlignment - 1)
		if aligned > len(control) {
			break
		}
		control = control[aligned:]
	}
	if !found {
		return errors.New("mipstack: socket-error control message not found")
	}
	*message = parsed
	return nil
}

func parseSocketErrorControl(v6 bool, data []byte) (SocketErrorControlMessage, error) {
	want := 32
	if v6 {
		want = 44
	}
	if len(data) != want {
		return SocketErrorControlMessage{}, errors.New("mipstack: invalid socket-error control message")
	}
	message := SocketErrorControlMessage{
		Errno: binary.LittleEndian.Uint32(data[:4]), Origin: SocketErrorOrigin(data[4]),
		Type: data[5], Code: data[6], Info: binary.LittleEndian.Uint32(data[8:12]), Data: binary.LittleEndian.Uint32(data[12:16]),
	}
	family := binary.LittleEndian.Uint16(data[16:18])
	if v6 {
		if family != 10 {
			return SocketErrorControlMessage{}, errors.New("mipstack: invalid IPv6 socket-error offender")
		}
		message.Offender = netip.AddrFrom16([16]byte(data[24:40]))
	} else {
		if family != 2 {
			return SocketErrorControlMessage{}, errors.New("mipstack: invalid IPv4 socket-error offender")
		}
		message.Offender = netip.AddrFrom4([4]byte(data[20:24]))
	}
	return message, nil
}

type IPv4ControlMessage struct {
	TTL int
	TOS int
	Src netip.Addr
	Dst netip.Addr
	IfIndex int
}

func (message *IPv4ControlMessage) Marshal() ([]byte, error) {
	if message == nil {
		return nil, nil
	}
	return message.marshal(message.Src, netip.Addr{}, false)
}

func (message *IPv4ControlMessage) marshalForRead(specDst netip.Addr) ([]byte, error) {
	return message.marshal(specDst, message.Dst, true)
}

func (message *IPv4ControlMessage) marshal(specDst, destination netip.Addr, receiving bool) ([]byte, error) {
	if message.IfIndex != 0 {
		return nil, errors.New("mipstack: nonzero IPv4 control-message interface index is not supported")
	}
	specDst, destination = specDst.Unmap(), destination.Unmap()
	if receiving {
		if specDst.IsValid() && (!specDst.Is4() || specDst.Zone() != "" || specDst.IsMulticast()) {
			return nil, errors.New("mipstack: invalid IPv4 control-message source")
		}
		if destination.IsValid() && (!destination.Is4() || destination.Zone() != "") {
			return nil, errors.New("mipstack: invalid IPv4 control-message destination")
		}
	} else if specDst.IsValid() && (!specDst.Is4() || specDst.Zone() != "" || specDst.IsMulticast()) {
		return nil, errors.New("mipstack: invalid IPv4 control-message source")
	}
	capacity := 0
	if specDst.IsValid() || receiving && destination.IsValid() {
		capacity += 32
	}
	if message.TTL < 0 || message.TTL > 255 {
		return nil, errors.New("mipstack: IPv4 control-message TTL must be between 0 and 255")
	}
	if message.TOS < 0 || message.TOS > 255 {
		return nil, errors.New("mipstack: IPv4 control-message TOS must be between 0 and 255")
	}
	if receiving || message.TTL != 0 {
		capacity += 24
	}
	if receiving || message.TOS != 0 {
		capacity += 24
	}
	control := make([]byte, 0, capacity)
	if specDst.IsValid() || receiving && destination.IsValid() {
		if receiving {
			control = appendLinuxIPv4PacketInfoControl(control, specDst, destination)
		} else {
			control = appendLinuxIPv4PacketInfoControl(control, specDst, netip.Addr{})
		}
	}
	if receiving || message.TTL != 0 {
		control = appendLinuxControlInt32(control, linuxLevelIP, linuxIPTimeToLive, int32(message.TTL))
	}
	if receiving {
		control = appendLinuxControl(control, linuxLevelIP, linuxIPTypeOfService, []byte{byte(message.TOS)})
	} else if message.TOS != 0 {
		control = appendLinuxControlInt32(control, linuxLevelIP, linuxIPTypeOfService, int32(message.TOS))
	}
	return control, nil
}

func (message *IPv4ControlMessage) Parse(control []byte) error {
	if message == nil {
		return errors.New("mipstack: nil IPv4 control-message receiver")
	}
	address, options, err := parseLinuxIPControlValues(control, false, true)
	if err != nil {
		return err
	}
	*message = IPv4ControlMessage{
		TTL: int(options.hopLimit), TOS: int(options.trafficClass), Dst: address,
	}
	return nil
}

func (message *IPv4ControlMessage) parseForWrite(control []byte) (ipPacketOptions, error) {
	address, options, err := parseLinuxIPControlValues(control, false, false)
	if err != nil {
		return ipPacketOptions{}, err
	}
	*message = IPv4ControlMessage{
		TTL: int(options.hopLimit), TOS: int(options.trafficClass), Src: address,
	}
	return options, nil
}

type IPv6ControlMessage struct {
	TrafficClass int
	HopLimit int
	FlowLabel uint32
	Src netip.Addr
	Dst netip.Addr
	IfIndex int
}

func (message *IPv6ControlMessage) Marshal() ([]byte, error) {
	if message == nil {
		return nil, nil
	}
	return message.marshal(message.Src, false)
}

func (message *IPv6ControlMessage) marshalForRead() ([]byte, error) {
	return message.marshal(message.Dst, true)
}

func (message *IPv6ControlMessage) marshal(address netip.Addr, receiving bool) ([]byte, error) {
	if message.IfIndex != 0 {
		return nil, errors.New("mipstack: nonzero IPv6 control-message interface index is not supported")
	}
	address = address.Unmap()
	capacity := 0
	if address.IsValid() {
		if !address.Is6() || address.Zone() != "" || !receiving && address.IsMulticast() {
			field := "source"
			if receiving {
				field = "destination"
			}
			return nil, errors.New("mipstack: invalid IPv6 control-message " + field)
		}
		capacity += 40
	}
	if message.HopLimit < -1 || message.HopLimit > 255 {
		return nil, errors.New("mipstack: IPv6 control-message hop limit must be -1 or between 0 and 255")
	}
	if message.TrafficClass < -1 || message.TrafficClass > 255 {
		return nil, errors.New("mipstack: IPv6 control-message traffic class must be -1 or between 0 and 255")
	}
	if message.FlowLabel > ipv6MaximumFlowLabel {
		return nil, errors.New("mipstack: IPv6 control-message flow label exceeds 20 bits")
	}
	if receiving || message.HopLimit != 0 {
		capacity += 24
	}
	if receiving || message.TrafficClass != 0 {
		capacity += 24
	}
	if message.FlowLabel != 0 || receiving && message.TrafficClass != 0 {
		capacity += 24
	}
	control := make([]byte, 0, capacity)
	if address.IsValid() {
		control = appendLinuxIPv6PacketInfoControl(control, address)
	}
	if receiving || message.HopLimit != 0 {
		control = appendLinuxControlInt32(control, linuxLevelIPv6, linuxIPv6HopLimit, int32(message.HopLimit))
	}
	if receiving || message.TrafficClass != 0 {
		control = appendLinuxControlInt32(control, linuxLevelIPv6, linuxIPv6TrafficClass, int32(message.TrafficClass))
	}
	if message.FlowLabel != 0 || receiving && message.TrafficClass != 0 {
		var flowInfo [4]byte
		trafficClass := uint32(0)
		if message.TrafficClass >= 0 {
			trafficClass = uint32(message.TrafficClass)
		}
		binary.BigEndian.PutUint32(flowInfo[:], trafficClass<<20|message.FlowLabel)
		control = appendLinuxControl(control, linuxLevelIPv6, linuxIPv6FlowInfo, flowInfo[:])
	}
	return control, nil
}

func (message *IPv6ControlMessage) Parse(control []byte) error {
	if message == nil {
		return errors.New("mipstack: nil IPv6 control-message receiver")
	}
	address, options, err := parseLinuxIPControlValues(control, true, true)
	if err != nil {
		return err
	}
	*message = IPv6ControlMessage{
		TrafficClass: int(options.trafficClass), HopLimit: int(options.hopLimit), FlowLabel: options.flowLabel, Dst: address,
	}
	return nil
}

func (message *IPv6ControlMessage) parseForWrite(control []byte) (ipPacketOptions, error) {
	address, options, err := parseLinuxIPControlValues(control, true, false)
	if err != nil {
		return ipPacketOptions{}, err
	}
	*message = IPv6ControlMessage{
		TrafficClass: int(options.trafficClass), HopLimit: int(options.hopLimit), FlowLabel: options.flowLabel, Src: address,
	}
	return options, nil
}

func appendLinuxIPv6PacketInfoControl(control []byte, address netip.Addr) []byte {
	address = address.Unmap()
	var data [20]byte
	addressBytes := address.As16()
	copy(data[0:16], addressBytes[:])
	return appendLinuxControl(control, linuxLevelIPv6, linuxIPv6PacketInfo, data[:])
}

func appendLinuxIPv4PacketInfoControl(control []byte, specDst, destination netip.Addr) []byte {
	var data [12]byte
	if specDst = specDst.Unmap(); specDst.Is4() {
		address := specDst.As4()
		copy(data[4:8], address[:])
	}
	if destination = destination.Unmap(); destination.Is4() {
		address := destination.As4()
		copy(data[8:12], address[:])
	}
	return appendLinuxControl(control, linuxLevelIP, linuxIPPacketInfo, data[:])
}

func controlMessageForRead(specDst, destination netip.Addr, options ipPacketOptions) ([]byte, error) {
	destination = destination.Unmap()
	if destination.Is4() {
		specDst = specDst.Unmap()
		message := IPv4ControlMessage{TTL: int(options.hopLimit), TOS: int(options.trafficClass), Dst: destination}
		return message.marshalForRead(specDst)
	}
	message := IPv6ControlMessage{TrafficClass: int(options.trafficClass), HopLimit: int(options.hopLimit), FlowLabel: options.flowLabel, Dst: destination}
	return message.marshalForRead()
}

func appendLinuxControl(control []byte, level, kind uint32, data []byte) []byte {
	length := linuxControlHeaderSize + len(data)
	space := (length + linuxControlAlignment - 1) &^ (linuxControlAlignment - 1)
	offset := len(control)
	control = append(control, make([]byte, space)...)
	binary.LittleEndian.PutUint64(control[offset:offset+8], uint64(length))
	binary.LittleEndian.PutUint32(control[offset+8:offset+12], level)
	binary.LittleEndian.PutUint32(control[offset+12:offset+16], kind)
	copy(control[offset+linuxControlHeaderSize:offset+length], data)
	return control
}

func appendLinuxControlInt32(control []byte, level, kind uint32, value int32) []byte {
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], uint32(value))
	return appendLinuxControl(control, level, kind, data[:])
}

func socketErrorControlForRead(err error) ([]byte, error) {
	var networkError ICMPError
	if !errors.As(err, &networkError) || !networkError.Reporter.IsValid() {
		return nil, errors.New("mipstack: asynchronous error has no ICMP metadata")
	}
	reporter := networkError.Reporter
	networkError.Reporter = reporter.Unmap()
	origin := SocketErrorOriginICMP
	if networkError.Reporter.Is6() {
		origin = SocketErrorOriginICMP6
	}
	info := networkError.MTU
	if info == 0 {
		info = networkError.Pointer
	}
	return (SocketErrorControlMessage{
		Errno: linuxICMPErrno(networkError), Origin: origin,
		Type: networkError.Type, Code: networkError.Code, Info: info,
		Offender: reporter,
	}).MarshalBinary()
}

type icmpErrorConversion struct {
	linuxErrno uint32
	hard       bool
}

func linuxICMPErrorConversion(networkError ICMPError) icmpErrorConversion {
	if networkError.Reporter.Is4() {
		switch networkError.Type {
		case ICMPv4TypeDestinationUnreachable:
			values := [...]icmpErrorConversion{
				{101, false}, {113, false}, {92, true}, {111, true},
				{90, false}, {95, false}, {101, true}, {112, true},
				{64, true}, {101, true}, {113, true}, {101, false},
				{113, false}, {113, true}, {113, true}, {113, true},
			}
			if int(networkError.Code) < len(values) {
				return values[networkError.Code]
			}
			return icmpErrorConversion{113, false}
		case ICMPv4TypeTimeExceeded:
			return icmpErrorConversion{113, false}
		case ICMPv4TypeParameterProblem:
			return icmpErrorConversion{71, true}
		}
		return icmpErrorConversion{71, false}
	}
	switch networkError.Type {
	case ICMPv6TypeDestinationUnreachable:
		values := [...]icmpErrorConversion{
			{101, false}, {13, true}, {113, false}, {113, false},
			{111, true}, {13, true}, {13, true},
		}
		if int(networkError.Code) < len(values) {
			return values[networkError.Code]
		}
		return icmpErrorConversion{71, true}
	case ICMPv6TypePacketTooBig:
		return icmpErrorConversion{90, false}
	case ICMPv6TypeTimeExceeded:
		return icmpErrorConversion{113, false}
	case ICMPv6TypeParameterProblem:
		return icmpErrorConversion{71, true}
	}
	return icmpErrorConversion{71, false}
}

func linuxICMPErrno(networkError ICMPError) uint32 {
	return linuxICMPErrorConversion(networkError).linuxErrno
}

func linuxDatagramICMPReport(networkError ICMPError, connected, receiveErrors, raw bool, mode PathMTUDiscovery) (pending, queued bool) {
	if !connected && !receiveErrors {
		return false, false
	}
	if networkError.Reporter.Is4() && networkError.Type == ICMPv4TypeDestinationUnreachable && networkError.Code == ICMPv4DestinationUnreachableCodeFragmentationNeeded {
		if !raw && mode == PathMTUDiscoveryDont {
			return false, false
		}
		return receiveErrors || mode != PathMTUDiscoveryDont, receiveErrors
	}
	if networkError.Reporter.Is6() && networkError.Type == ICMPv6TypePacketTooBig {
		if !raw && !mode.acceptsPathMTU() {
			return false, false
		}
		hard := mode != PathMTUDiscoveryDont
		if raw {
			hard = mode == PathMTUDiscoveryDo
		}
		return receiveErrors || hard, receiveErrors
	}
	if receiveErrors {
		return true, true
	}
	return linuxICMPErrorConversion(networkError).hard, false
}

func parseControlMessageForWrite(control []byte, v6 bool) (netip.Addr, ipPacketOptions, error) {
	if v6 {
		var message IPv6ControlMessage
		options, err := message.parseForWrite(control)
		if err != nil {
			return netip.Addr{}, ipPacketOptions{}, err
		}
		return message.Src, options, nil
	}
	var message IPv4ControlMessage
	options, err := message.parseForWrite(control)
	if err != nil {
		return netip.Addr{}, ipPacketOptions{}, err
	}
	return message.Src, options, nil
}

func parseLinuxIPControlValues(oob []byte, v6, receiving bool) (netip.Addr, ipPacketOptions, error) {
	var address netip.Addr
	var options ipPacketOptions
	var flowInfo uint32
	for len(oob) >= linuxControlHeaderSize {
		length64 := binary.LittleEndian.Uint64(oob[0:8])
		if length64 < linuxControlHeaderSize || length64 > uint64(len(oob)) {
			return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: invalid Linux IP control length")
		}
		length := int(length64)
		level := binary.LittleEndian.Uint32(oob[8:12])
		kind := binary.LittleEndian.Uint32(oob[12:16])
		data := oob[linuxControlHeaderSize:length]
		switch {
		case level == linuxLevelIP && kind == linuxIPPacketInfo:
			if v6 || len(data) != 12 {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: invalid IPv4 packet-info control message")
			}
			if binary.LittleEndian.Uint32(data[0:4]) != 0 {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: nonzero packet-info interface index is not supported")
			}
			candidate := netip.AddrFrom4([4]byte(data[4:8]))
			if receiving {
				candidate = netip.AddrFrom4([4]byte(data[8:12]))
			}
			if !receiving && candidate.IsUnspecified() {
				address = netip.Addr{}
			} else {
				address = candidate
			}
		case level == linuxLevelIPv6 && kind == linuxIPv6PacketInfo:
			if !v6 || len(data) < 20 {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: invalid IPv6 packet-info control message")
			}
			if binary.LittleEndian.Uint32(data[16:20]) != 0 {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: nonzero packet-info interface index is not supported")
			}
			candidate := netip.AddrFrom16([16]byte(data[0:16]))
			if receiving || !candidate.IsUnspecified() {
				address = candidate
			}
		case level == linuxLevelIP && kind == linuxIPTimeToLive:
			value, err := linuxControlInt32(data)
			if v6 || err != nil || value < 0 || !receiving && value == 0 || value > 255 {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: invalid IPv4 TTL control message")
			}
			options.hopLimit, options.hopLimitSet = byte(value), true
		case level == linuxLevelIP && kind == linuxIPTypeOfService:
			value, err := linuxControlByteOrInt32(data)
			if v6 || err != nil || value < 0 || value > 255 {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: invalid IPv4 TOS control message")
			}
			options.trafficClass, options.trafficClassSet = byte(value), true
		case level == linuxLevelIPv6 && kind == linuxIPv6HopLimit:
			value, err := linuxControlInt32(data)
			if !v6 || err != nil || value < -1 || value > 255 || receiving && value == -1 {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: invalid IPv6 hop-limit control message")
			}
			if value == -1 {
				options.hopLimit, options.hopLimitSet = 0, false
			} else {
				options.hopLimit, options.hopLimitSet = byte(value), true
			}
		case level == linuxLevelIPv6 && kind == linuxIPv6TrafficClass:
			value, err := linuxControlInt32(data)
			if !v6 || err != nil || value < -1 || value > 255 || receiving && value == -1 {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: invalid IPv6 traffic-class control message")
			}
			if value == -1 {
				options.trafficClass, options.trafficClassSet = 0, false
			} else {
				options.trafficClass, options.trafficClassSet = byte(value), true
			}
		case level == linuxLevelIPv6 && kind == linuxIPv6FlowInfo:
			if !v6 || len(data) < 4 {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: invalid IPv6 flow-info control message")
			}
			rawFlowInfo := binary.BigEndian.Uint32(data)
			if flowInfo != 0 && (flowInfo^rawFlowInfo)&^linuxIPv6FlowInfoMask != 0 {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: conflicting IPv6 flow-info reserved bits")
			}
			flowInfo = rawFlowInfo & linuxIPv6FlowInfoMask
			options.flowLabel, options.flowLabelSet = flowInfo&ipv6MaximumFlowLabel, true
		default:
			return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: unsupported Linux IP control message")
		}
		aligned := (length + linuxControlAlignment - 1) &^ (linuxControlAlignment - 1)
		if aligned > len(oob) {
			break
		}
		oob = oob[aligned:]
	}
	return address, options, nil
}

func linuxControlInt32(data []byte) (int32, error) {
	if len(data) != 4 {
		return 0, errors.New("invalid Linux ancillary integer")
	}
	return int32(binary.LittleEndian.Uint32(data)), nil
}

func linuxControlByteOrInt32(data []byte) (int32, error) {
	if len(data) == 1 {
		return int32(data[0]), nil
	}
	return linuxControlInt32(data)
}
