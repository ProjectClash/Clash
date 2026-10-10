package mipstack

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"testing"
)

var _ encoding.BinaryMarshaler = SocketErrorControlMessage{}

type testLinuxControlRecord struct {
	level uint32
	kind  uint32
	data  []byte
}

func assertLinuxControlRecords(t testing.TB, control []byte, records ...testLinuxControlRecord) {
	t.Helper()
	for index, record := range records {
		if len(control) < linuxControlHeaderSize {
			t.Fatalf("control record %d has only %d header bytes", index, len(control))
		}
		length := int(binary.LittleEndian.Uint64(control[:8]))
		wantLength := linuxControlHeaderSize + len(record.data)
		if length != wantLength || binary.LittleEndian.Uint32(control[8:12]) != record.level ||
			binary.LittleEndian.Uint32(control[12:16]) != record.kind {
			t.Fatalf("control record %d header = length %d level %d kind %d, want %d/%d/%d",
				index, length, binary.LittleEndian.Uint32(control[8:12]), binary.LittleEndian.Uint32(control[12:16]),
				wantLength, record.level, record.kind)
		}
		aligned := (length + linuxControlAlignment - 1) &^ (linuxControlAlignment - 1)
		if aligned > len(control) || length > len(control) {
			t.Fatalf("control record %d length %d exceeds %d available bytes", index, length, len(control))
		}
		if !bytes.Equal(control[linuxControlHeaderSize:length], record.data) {
			t.Fatalf("control record %d data = %x, want %x", index, control[linuxControlHeaderSize:length], record.data)
		}
		for _, value := range control[length:aligned] {
			if value != 0 {
				t.Fatalf("control record %d has nonzero padding: %x", index, control[length:aligned])
			}
		}
		control = control[aligned:]
	}
	if len(control) != 0 {
		t.Fatalf("%d trailing ancillary bytes remain after %d records", len(control), len(records))
	}
}

func TestSocketErrorControlMessageMarshalBinary(t *testing.T) {
	tests := []struct {
		name      string
		message   SocketErrorControlMessage
		wantSize  int
		wantLevel uint32
		wantKind  uint32
	}{
		{
			name: "IPv4",
			message: SocketErrorControlMessage{
				Errno: 111, Origin: SocketErrorOriginICMP, Type: 3, Code: 3,
				Info: 0x10203040, Data: 0x50607080, Offender: netip.MustParseAddr("198.51.100.1"),
			},
			wantSize: 48, wantLevel: linuxLevelIP, wantKind: linuxIPReceiveError,
		},
		{
			name: "IPv4-mapped",
			message: SocketErrorControlMessage{
				Origin: 255, Type: 254, Code: 253, Offender: netip.MustParseAddr("::ffff:192.0.2.1"),
			},
			wantSize: 64, wantLevel: linuxLevelIPv6, wantKind: linuxIPv6ReceiveError,
		},
		{
			name: "IPv6",
			message: SocketErrorControlMessage{
				Errno: 90, Origin: SocketErrorOriginICMP6, Type: 2, Code: 1,
				Info: 1280, Data: 0xfedcba98, Offender: netip.MustParseAddr("2001:db8::1"),
			},
			wantSize: 64, wantLevel: linuxLevelIPv6, wantKind: linuxIPv6ReceiveError,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			control, err := test.message.MarshalBinary()
			if err != nil || len(control) != test.wantSize {
				t.Fatalf("MarshalBinary = %d bytes, %v, want %d", len(control), err, test.wantSize)
			}
			appended, err := test.message.AppendBinary([]byte{0xaa, 0xbb, 0xcc})
			if err != nil || !bytes.Equal(appended[:3], []byte{0xaa, 0xbb, 0xcc}) || !bytes.Equal(appended[3:], control) {
				t.Fatalf("AppendBinary = %x, %v, want prefix and %x", appended, err, control)
			}
			length := int(binary.LittleEndian.Uint64(control[:8]))
			if binary.LittleEndian.Uint32(control[8:12]) != test.wantLevel || binary.LittleEndian.Uint32(control[12:16]) != test.wantKind {
				t.Fatalf("control header = length %d level %d kind %d", length, binary.LittleEndian.Uint32(control[8:12]), binary.LittleEndian.Uint32(control[12:16]))
			}
			wantLength := 48
			if test.wantLevel == linuxLevelIPv6 {
				wantLength = 60
			}
			if length != wantLength {
				t.Fatalf("control length = %d, want %d", length, wantLength)
			}
			data := control[linuxControlHeaderSize:length]
			if binary.LittleEndian.Uint32(data[:4]) != test.message.Errno || data[4] != byte(test.message.Origin) ||
				data[5] != test.message.Type || data[6] != test.message.Code || data[7] != 0 ||
				binary.LittleEndian.Uint32(data[8:12]) != test.message.Info || binary.LittleEndian.Uint32(data[12:16]) != test.message.Data {
				t.Fatalf("sock_extended_err = %x", data[:16])
			}
			if test.wantLevel == linuxLevelIP {
				if binary.LittleEndian.Uint16(data[16:18]) != 2 || !bytes.Equal(data[18:20], []byte{0, 0}) ||
					netip.AddrFrom4([4]byte(data[20:24])) != test.message.Offender || !bytes.Equal(data[24:32], make([]byte, 8)) {
					t.Fatalf("IPv4 offender sockaddr = %x", data[16:])
				}
			} else if binary.LittleEndian.Uint16(data[16:18]) != 10 || !bytes.Equal(data[18:24], make([]byte, 6)) ||
				netip.AddrFrom16([16]byte(data[24:40])) != test.message.Offender || !bytes.Equal(data[40:44], make([]byte, 4)) ||
				!bytes.Equal(control[length:], make([]byte, test.wantSize-length)) {
				t.Fatalf("IPv6 offender sockaddr or alignment = %x / %x", data[16:], control[length:])
			}
			var parsed SocketErrorControlMessage
			if err = parsed.Parse(control); err != nil || parsed != test.message {
				t.Fatalf("Parse(MarshalBinary) = %+v, %v, want %+v", parsed, err, test.message)
			}
			compound := appendLinuxControlInt32(nil, linuxLevelIP, linuxIPTimeToLive, 64)
			compound, err = test.message.AppendBinary(compound)
			if err != nil {
				t.Fatal(err)
			}
			if err = parsed.Parse(compound); err != nil || parsed != test.message {
				t.Fatalf("Parse(compound AppendBinary) = %+v, %v, want %+v", parsed, err, test.message)
			}
		})
	}

	invalid := []SocketErrorControlMessage{
		{},
		{Offender: netip.MustParseAddr("fe80::1%ethernet")},
	}
	for _, message := range invalid {
		storage := bytes.Repeat([]byte{0xa5}, 128)
		dst := storage[:3]
		before := append([]byte(nil), storage...)
		got, err := message.AppendBinary(dst)
		if err == nil || len(got) != len(dst) || &got[0] != &dst[0] || !bytes.Equal(storage, before) {
			t.Fatalf("invalid AppendBinary = %x, %v; storage changed=%v", got, err, !bytes.Equal(storage, before))
		}
	}
}

func TestSocketErrorControlMessageLinuxFixtures(t *testing.T) {
	tests := []struct {
		name    string
		wire    string
		message SocketErrorControlMessage
	}{
		{
			name: "IPv4 port unreachable",
			wire: "3000000000000000000000000b000000" +
				"6f000000020303000000000000000000" +
				"020000007f0000010000000000000000",
			message: SocketErrorControlMessage{
				Errno: 111, Origin: SocketErrorOriginICMP, Type: 3, Code: 3,
				Offender: netip.MustParseAddr("127.0.0.1"),
			},
		},
		{
			name: "IPv6 port unreachable",
			wire: "3c000000000000002900000019000000" +
				"6f000000030104000000000000000000" +
				"0a000000000000000000000000000000000000000000000100000000" +
				"00000000",
			message: SocketErrorControlMessage{
				Errno: 111, Origin: SocketErrorOriginICMP6, Type: 1, Code: 4,
				Offender: netip.MustParseAddr("::1"),
			},
		},
		{
			name: "IPv4-mapped port unreachable on IPv6 socket",
			wire: "3c000000000000002900000019000000" +
				"6f000000020303000000000000000000" +
				"0a0000000000000000000000000000000000ffff7f00000100000000" +
				"00000000",
			message: SocketErrorControlMessage{
				Errno: 111, Origin: SocketErrorOriginICMP, Type: 3, Code: 3,
				Offender: netip.MustParseAddr("::ffff:127.0.0.1"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire, err := hex.DecodeString(test.wire)
			if err != nil {
				t.Fatal(err)
			}
			var message SocketErrorControlMessage
			if err = message.Parse(wire); err != nil || message != test.message {
				t.Fatalf("Parse(Linux fixture) = %+v, %v, want %+v", message, err, test.message)
			}
			encoded, err := test.message.MarshalBinary()
			if err != nil || !bytes.Equal(encoded, wire) {
				t.Fatalf("MarshalBinary = %x, %v, want Linux fixture %x", encoded, err, wire)
			}
		})
	}

	unknownOffender, err := hex.DecodeString(
		"3000000000000000000000000b000000" +
			"5a000000010000000005000000000000" +
			"00000000000000000000000000000000",
	)
	if err != nil {
		t.Fatal(err)
	}
	initial := SocketErrorControlMessage{Errno: 1, Offender: netip.MustParseAddr("192.0.2.1")}
	message := initial
	if err = message.Parse(unknownOffender); err == nil || message != initial {
		t.Fatalf("Parse(AF_UNSPEC Linux fixture) = %+v, %v; want unchanged receiver and error", message, err)
	}
}

func TestSocketErrorControlMessageForRead(t *testing.T) {
	tests := []struct {
		name    string
		input   ICMPError
		want    SocketErrorControlMessage
		control int
	}{
		{
			name:  "IPv4 network administratively prohibited",
			input: ICMPError{Reporter: netip.MustParseAddr("198.51.100.1"), Type: 3, Code: 9},
			want: SocketErrorControlMessage{
				Errno: 101, Origin: SocketErrorOriginICMP, Type: 3, Code: 9,
				Offender: netip.MustParseAddr("198.51.100.1"),
			},
			control: 48,
		},
		{
			name:  "IPv6 packet too big",
			input: ICMPError{Reporter: netip.MustParseAddr("2001:db8::1"), Type: 2, MTU: 1280},
			want: SocketErrorControlMessage{
				Errno: 90, Origin: SocketErrorOriginICMP6, Type: 2, Info: 1280,
				Offender: netip.MustParseAddr("2001:db8::1"),
			},
			control: 64,
		},
		{
			name:  "IPv6 parameter problem",
			input: ICMPError{Reporter: netip.MustParseAddr("2001:db8::2"), Type: 4, Code: 1, Pointer: 48},
			want: SocketErrorControlMessage{
				Errno: 71, Origin: SocketErrorOriginICMP6, Type: 4, Code: 1, Info: 48,
				Offender: netip.MustParseAddr("2001:db8::2"),
			},
			control: 64,
		},
		{
			name:  "IPv4-mapped network administratively prohibited",
			input: ICMPError{Reporter: netip.MustParseAddr("::ffff:198.51.100.1"), Type: 3, Code: 9},
			want: SocketErrorControlMessage{
				Errno: 101, Origin: SocketErrorOriginICMP, Type: 3, Code: 9,
				Offender: netip.MustParseAddr("::ffff:198.51.100.1"),
			},
			control: 64,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			control, err := socketErrorControlForRead(test.input)
			if err != nil || len(control) != test.control {
				t.Fatalf("socket error control = %d bytes, %v, want %d", len(control), err, test.control)
			}
			var message SocketErrorControlMessage
			if err = message.Parse(control); err != nil || message != test.want {
				t.Fatalf("parsed socket error = %+v, %v, want %+v", message, err, test.want)
			}
			var packetInfo []byte
			var packetInfoErr error
			if test.input.Reporter.Unmap().Is4() {
				packetInfo, packetInfoErr = (&IPv4ControlMessage{Src: test.input.Reporter}).Marshal()
			} else {
				packetInfo, packetInfoErr = (&IPv6ControlMessage{Src: test.input.Reporter}).Marshal()
			}
			if packetInfoErr != nil {
				t.Fatal(packetInfoErr)
			}
			packetInfo = append(packetInfo, control...)
			if err = message.Parse(packetInfo); err != nil || message != test.want {
				t.Fatalf("socket error with packet info = %+v, %v", message, err)
			}
			if err = message.Parse(append(control, control...)); err == nil {
				t.Fatal("duplicate socket error control message parsed successfully")
			}
			if err = message.Parse(control[:len(control)-1]); err == nil {
				t.Fatal("truncated socket error control message parsed successfully")
			}
		})
	}
	var message *SocketErrorControlMessage
	if err := message.Parse(nil); err == nil {
		t.Fatal("nil socket error control receiver parsed successfully")
	}
	if _, err := socketErrorControlForRead(ICMPError{Type: 3, Code: 3}); err == nil {
		t.Fatal("socket error without reporter marshaled successfully")
	}
}

func TestIPControlMessageLinuxFixtures(t *testing.T) {
	address4 := netip.MustParseAddr("192.0.2.123")
	packetInfo4 := mustCodecVector(t, "00000000c000027b00000000")
	send4 := mustCodecVector(t,
		"1c00000000000000000000000800000000000000c000027b0000000000000000"+
			"140000000000000000000000020000001f00000000000000"+
			"14000000000000000000000001000000b800000000000000")
	assertLinuxControlRecords(t, send4,
		testLinuxControlRecord{level: linuxLevelIP, kind: linuxIPPacketInfo, data: packetInfo4},
		testLinuxControlRecord{level: linuxLevelIP, kind: linuxIPTimeToLive, data: mustCodecVector(t, "1f000000")},
		testLinuxControlRecord{level: linuxLevelIP, kind: linuxIPTypeOfService, data: mustCodecVector(t, "b8000000")},
	)
	outgoing4 := IPv4ControlMessage{TTL: 31, TOS: 0xb8, Src: address4}
	encoded4, err := outgoing4.Marshal()
	if err != nil || !bytes.Equal(encoded4, send4) {
		t.Fatalf("IPv4 send control = %x, %v, want Linux fixture %x", encoded4, err, send4)
	}
	var parsed4 IPv4ControlMessage
	options4, err := parsed4.parseForWrite(send4)
	if err != nil || parsed4 != outgoing4 || !options4.hopLimitSet || !options4.trafficClassSet {
		t.Fatalf("IPv4 send fixture = %+v options %+v, %v", parsed4, options4, err)
	}

	packetDestination4 := netip.MustParseAddr("198.51.100.7")
	receivePacketInfo4 := mustCodecVector(t, "00000000c000027bc6336407")
	receive4 := mustCodecVector(t,
		"1c00000000000000000000000800000000000000c000027bc633640700000000"+
			"140000000000000000000000020000001f00000000000000"+
			"11000000000000000000000001000000b800000000000000")
	assertLinuxControlRecords(t, receive4,
		testLinuxControlRecord{level: linuxLevelIP, kind: linuxIPPacketInfo, data: receivePacketInfo4},
		testLinuxControlRecord{level: linuxLevelIP, kind: linuxIPTimeToLive, data: mustCodecVector(t, "1f000000")},
		testLinuxControlRecord{level: linuxLevelIP, kind: linuxIPTypeOfService, data: mustCodecVector(t, "b8")},
	)
	incoming4 := IPv4ControlMessage{TTL: 31, TOS: 0xb8, Dst: packetDestination4}
	encoded4, err = controlMessageForRead(address4, packetDestination4, ipPacketOptions{hopLimit: 31, trafficClass: 0xb8})
	if err != nil || !bytes.Equal(encoded4, receive4) {
		t.Fatalf("IPv4 receive control = %x, %v, want Linux fixture %x", encoded4, err, receive4)
	}
	parsed4 = IPv4ControlMessage{}
	if err = parsed4.Parse(receive4); err != nil || parsed4 != incoming4 {
		t.Fatalf("IPv4 receive fixture = %+v, %v, want %+v", parsed4, err, incoming4)
	}

	address6 := netip.MustParseAddr("2001:db8::123")
	packetInfo6 := mustCodecVector(t, "20010db800000000000000000000012300000000")
	control6 := mustCodecVector(t,
		"2400000000000000290000003200000020010db80000000000000000000001230000000000000000"+
			"140000000000000029000000340000001d00000000000000"+
			"140000000000000029000000430000002e00000000000000"+
			"1400000000000000290000000b00000002eabcde00000000")
	assertLinuxControlRecords(t, control6,
		testLinuxControlRecord{level: linuxLevelIPv6, kind: linuxIPv6PacketInfo, data: packetInfo6},
		testLinuxControlRecord{level: linuxLevelIPv6, kind: linuxIPv6HopLimit, data: mustCodecVector(t, "1d000000")},
		testLinuxControlRecord{level: linuxLevelIPv6, kind: linuxIPv6TrafficClass, data: mustCodecVector(t, "2e000000")},
		testLinuxControlRecord{level: linuxLevelIPv6, kind: linuxIPv6FlowInfo, data: mustCodecVector(t, "02eabcde")},
	)
	outgoing6 := IPv6ControlMessage{TrafficClass: 0x2e, HopLimit: 29, FlowLabel: 0xabcde, Src: address6}
	encoded6, err := outgoing6.Marshal()
	if err != nil || !bytes.Equal(encoded6, control6) {
		t.Fatalf("IPv6 send control = %x, %v, want Linux fixture %x", encoded6, err, control6)
	}
	var parsed6 IPv6ControlMessage
	options6, err := parsed6.parseForWrite(control6)
	if err != nil || parsed6 != outgoing6 || !options6.hopLimitSet || !options6.trafficClassSet || !options6.flowLabelSet {
		t.Fatalf("IPv6 send fixture = %+v options %+v, %v", parsed6, options6, err)
	}
	incoming6 := IPv6ControlMessage{TrafficClass: 0x2e, HopLimit: 29, FlowLabel: 0xabcde, Dst: address6}
	encoded6, err = incoming6.marshalForRead()
	if err != nil || !bytes.Equal(encoded6, control6) {
		t.Fatalf("IPv6 receive control = %x, %v, want Linux fixture %x", encoded6, err, control6)
	}
	parsed6 = IPv6ControlMessage{}
	if err = parsed6.Parse(control6); err != nil || parsed6 != incoming6 {
		t.Fatalf("IPv6 receive fixture = %+v, %v, want %+v", parsed6, err, incoming6)
	}
}

func TestIPv4PacketInfoDirectionSelection(t *testing.T) {
	control := mustCodecVector(t, "1c0000000000000000000000080000000000000000000000c633640700000000")
	source, _, err := parseLinuxIPControlValues(control, false, false)
	if err != nil || source.IsValid() {
		t.Fatalf("IPv4 send packet-info source = %v, %v, want automatic selection", source, err)
	}
	destination, _, err := parseLinuxIPControlValues(control, false, true)
	if err != nil || destination != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("IPv4 receive packet-info destination = %v, %v", destination, err)
	}
	var message IPv4ControlMessage
	if err = message.Parse(control); err != nil || message.Dst != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("IPv4 receive packet-info message = %+v, %v", message, err)
	}
	readControl, err := controlMessageForRead(netip.Addr{}, netip.MustParseAddr("198.51.100.7"), ipPacketOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(readControl) < 32 || !bytes.Equal(readControl[20:24], []byte{0, 0, 0, 0}) {
		t.Fatalf("IPv4 receive encoding supplied a send source: %x", readControl)
	}
}

func TestIPControlMessageKnownAnswerMutations(t *testing.T) {
	receive4 := mustCodecVector(t,
		"1c00000000000000000000000800000000000000c000027bc633640700000000"+
			"140000000000000000000000020000001f00000000000000"+
			"11000000000000000000000001000000b800000000000000")
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "short header", mutate: func(wire []byte) []byte { return wire[:15] }},
		{name: "length below header", mutate: func(wire []byte) []byte {
			binary.LittleEndian.PutUint64(wire[:8], 15)
			return wire
		}},
		{name: "length beyond input", mutate: func(wire []byte) []byte {
			binary.LittleEndian.PutUint64(wire[:8], uint64(len(wire)+1))
			return wire
		}},
		{name: "cross-family packet info", mutate: func(wire []byte) []byte {
			binary.LittleEndian.PutUint32(wire[8:12], linuxLevelIPv6)
			return wire
		}},
		{name: "nonzero interface", mutate: func(wire []byte) []byte {
			binary.LittleEndian.PutUint32(wire[16:20], 1)
			return wire
		}},
		{name: "duplicate TTL", mutate: func(wire []byte) []byte { return append(wire, wire[32:56]...) }},
		{name: "invalid TOS width", mutate: func(wire []byte) []byte {
			binary.LittleEndian.PutUint64(wire[56:64], 18)
			return wire
		}},
		{name: "truncated alignment", mutate: func(wire []byte) []byte { return wire[:len(wire)-1] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := test.mutate(append([]byte(nil), receive4...))
			before := append([]byte(nil), wire...)
			initial := IPv4ControlMessage{TTL: 7, TOS: 9, Dst: netip.MustParseAddr("192.0.2.200")}
			message := initial
			if err := message.Parse(wire); err == nil {
				t.Fatal("mutated control message parsed successfully")
			}
			if message != initial || !bytes.Equal(wire, before) {
				t.Fatal("failed control parse modified its receiver or input")
			}
		})
	}
}

func TestIPv4ControlMessageMarshalAndParse(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.123")
	outgoing := &IPv4ControlMessage{TTL: 31, TOS: 0xb8, Src: source}
	control, err := outgoing.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsedSource, options, err := parseControlMessageForWrite(control, false)
	if err != nil || parsedSource != source || options != (ipPacketOptions{hopLimit: 31, trafficClass: 0xb8, hopLimitSet: true, trafficClassSet: true}) {
		t.Fatalf("marshaled IPv4 control = source %v options %+v, %v", parsedSource, options, err)
	}
	var incoming IPv4ControlMessage
	receivedControl, err := controlMessageForRead(source, source, options)
	if err != nil {
		t.Fatal(err)
	}
	if err = incoming.Parse(receivedControl); err != nil {
		t.Fatal(err)
	}
	if incoming != (IPv4ControlMessage{TTL: 31, TOS: 0xb8, Dst: source}) {
		t.Fatalf("parsed IPv4 control = %+v", incoming)
	}
	if control, err = (*IPv4ControlMessage)(nil).Marshal(); err != nil || control != nil {
		t.Fatalf("nil IPv4 control marshal = %x, %v", control, err)
	}
}

func TestIPv6ControlMessageMarshalAndParse(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::123")
	outgoing := &IPv6ControlMessage{TrafficClass: 0x2e, HopLimit: 29, FlowLabel: 0xabcde, Src: source}
	control, err := outgoing.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsedSource, options, err := parseControlMessageForWrite(control, true)
	if err != nil || parsedSource != source || options != (ipPacketOptions{hopLimit: 29, trafficClass: 0x2e, flowLabel: 0xabcde, hopLimitSet: true, trafficClassSet: true, flowLabelSet: true}) {
		t.Fatalf("marshaled IPv6 control = source %v options %+v, %v", parsedSource, options, err)
	}
	var incoming IPv6ControlMessage
	receivedControl, err := controlMessageForRead(source, source, options)
	if err != nil {
		t.Fatal(err)
	}
	if err = incoming.Parse(receivedControl); err != nil {
		t.Fatal(err)
	}
	if incoming != (IPv6ControlMessage{TrafficClass: 0x2e, HopLimit: 29, FlowLabel: 0xabcde, Dst: source}) {
		t.Fatalf("parsed IPv6 control = %+v", incoming)
	}
	if control, err = (*IPv6ControlMessage)(nil).Marshal(); err != nil || control != nil {
		t.Fatalf("nil IPv6 control marshal = %x, %v", control, err)
	}
}

func TestIPv6ZeroFlowInfoIsOmittedOnRead(t *testing.T) {
	control, err := (&IPv6ControlMessage{HopLimit: 64, Dst: netip.MustParseAddr("2001:db8::124")}).marshalForRead()
	if err != nil {
		t.Fatal(err)
	}
	for remaining := control; len(remaining) != 0; {
		length := int(binary.LittleEndian.Uint64(remaining[:8]))
		if binary.LittleEndian.Uint32(remaining[8:12]) == linuxLevelIPv6 &&
			binary.LittleEndian.Uint32(remaining[12:16]) == linuxIPv6FlowInfo {
			t.Fatal("zero IPv6 flow info was emitted on receive")
		}
		aligned := (length + linuxControlAlignment - 1) &^ (linuxControlAlignment - 1)
		remaining = remaining[aligned:]
	}
}

func TestControlMessageValidation(t *testing.T) {
	invalid := []struct {
		name    string
		marshal func() ([]byte, error)
	}{
		{name: "IPv4 interface", marshal: func() ([]byte, error) { return (&IPv4ControlMessage{IfIndex: 1}).Marshal() }},
		{name: "IPv4 source", marshal: func() ([]byte, error) { return (&IPv4ControlMessage{Src: netip.IPv6Unspecified()}).Marshal() }},
		{name: "IPv4 TTL", marshal: func() ([]byte, error) { return (&IPv4ControlMessage{TTL: 256}).Marshal() }},
		{name: "IPv4 TOS", marshal: func() ([]byte, error) { return (&IPv4ControlMessage{TOS: -1}).Marshal() }},
		{name: "IPv6 interface", marshal: func() ([]byte, error) { return (&IPv6ControlMessage{IfIndex: 1}).Marshal() }},
		{name: "IPv6 source", marshal: func() ([]byte, error) { return (&IPv6ControlMessage{Src: netip.IPv4Unspecified()}).Marshal() }},
		{name: "IPv6 hop limit", marshal: func() ([]byte, error) { return (&IPv6ControlMessage{HopLimit: 256}).Marshal() }},
		{name: "IPv6 traffic class", marshal: func() ([]byte, error) { return (&IPv6ControlMessage{TrafficClass: -1}).Marshal() }},
		{name: "IPv6 flow label", marshal: func() ([]byte, error) { return (&IPv6ControlMessage{FlowLabel: ipv6MaximumFlowLabel + 1}).Marshal() }},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.marshal(); err == nil {
				t.Fatal("invalid control message marshaled successfully")
			}
		})
	}
	var ipv4 *IPv4ControlMessage
	if err := ipv4.Parse(nil); err == nil {
		t.Fatal("nil IPv4 control receiver parsed successfully")
	}
	var ipv6 *IPv6ControlMessage
	if err := ipv6.Parse(nil); err == nil {
		t.Fatal("nil IPv6 control receiver parsed successfully")
	}
	for _, address := range []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	} {
		control, err := controlMessageForRead(address, address, ipPacketOptions{})
		if err != nil {
			t.Fatalf("controlMessageForRead(%v): %v", address, err)
		}
		parsedAddress, options, err := parseLinuxIPControlValues(control, address.Is6(), true)
		if err != nil || parsedAddress != address || options.hopLimit != 0 {
			t.Fatalf("zero-hop control for %v = %v, %+v, %v", address, parsedAddress, options, err)
		}
	}
	zeroHopLimit := appendLinuxControlInt32(nil, linuxLevelIPv6, linuxIPv6HopLimit, 0)
	_, options, err := parseLinuxIPControlValues(zeroHopLimit, true, false)
	if err != nil || options.hopLimit != 0 || !options.hopLimitSet {
		t.Fatalf("IPv6 zero hop-limit control = %+v, %v", options, err)
	}
	zeroTTL := appendLinuxControlInt32(nil, linuxLevelIP, linuxIPTimeToLive, 0)
	if _, _, err = parseLinuxIPControlValues(zeroTTL, false, false); err == nil {
		t.Fatal("IPv4 zero TTL control message parsed successfully")
	}
	var zeroFlowInfo [4]byte
	zeroFlowControl := appendLinuxControl(nil, linuxLevelIPv6, linuxIPv6FlowInfo, zeroFlowInfo[:])
	_, options, err = parseLinuxIPControlValues(zeroFlowControl, true, false)
	if err != nil || options.flowLabel != 0 || !options.flowLabelSet {
		t.Fatalf("IPv6 explicit zero flow label = %+v, %v", options, err)
	}
	conflicting := appendLinuxControlInt32(nil, linuxLevelIPv6, linuxIPv6TrafficClass, 1)
	flowInfo := [4]byte{0x02, 0, 0, 1}
	conflicting = appendLinuxControl(conflicting, linuxLevelIPv6, linuxIPv6FlowInfo, flowInfo[:])
	if _, _, err = parseLinuxIPControlValues(conflicting, true, false); err == nil {
		t.Fatal("conflicting IPv6 flow-info traffic class parsed successfully")
	}
}

func FuzzControlMessageParsing(f *testing.F) {
	control4, _ := (&IPv4ControlMessage{TTL: 31, TOS: 0xb8, Src: netip.MustParseAddr("192.0.2.1")}).Marshal()
	control6, _ := (&IPv6ControlMessage{HopLimit: 29, TrafficClass: 0x2e, FlowLabel: 0x12345, Src: netip.MustParseAddr("2001:db8::1")}).Marshal()
	error4, _ := socketErrorControlForRead(ICMPError{Reporter: netip.MustParseAddr("198.51.100.1"), Type: 3, Code: 1})
	error6, _ := socketErrorControlForRead(ICMPError{Reporter: netip.MustParseAddr("2001:db8::2"), Type: 2, MTU: 1280})
	f.Add([]byte(nil))
	f.Add(control4)
	f.Add(control6)
	f.Add(error4)
	f.Add(error6)
	f.Fuzz(func(t *testing.T, control []byte) {
		if len(control) > 4096 {
			control = control[:4096]
		}
		before := append([]byte(nil), control...)
		initial4 := IPv4ControlMessage{TTL: -1, TOS: 256, Src: netip.MustParseAddr("192.0.2.200"), Dst: netip.MustParseAddr("192.0.2.201"), IfIndex: 7}
		ipv4 := initial4
		if err := ipv4.Parse(control); err != nil {
			if ipv4 != initial4 {
				t.Fatal("failed IPv4 control parse modified its receiver")
			}
		} else {
			encoded, marshalErr := ipv4.marshalForRead(netip.Addr{})
			var repeated IPv4ControlMessage
			if marshalErr != nil || repeated.Parse(encoded) != nil || repeated != ipv4 {
				t.Fatalf("IPv4 control round trip = %+v, %v, want %+v", repeated, marshalErr, ipv4)
			}
		}
		_, _, _ = parseControlMessageForWrite(control, false)

		initial6 := IPv6ControlMessage{
			TrafficClass: -1, HopLimit: 256, FlowLabel: ipv6MaximumFlowLabel + 1,
			Src: netip.MustParseAddr("2001:db8::200"), Dst: netip.MustParseAddr("2001:db8::201"), IfIndex: 7,
		}
		ipv6 := initial6
		if err := ipv6.Parse(control); err != nil {
			if ipv6 != initial6 {
				t.Fatal("failed IPv6 control parse modified its receiver")
			}
		} else {
			encoded, marshalErr := ipv6.marshalForRead()
			var repeated IPv6ControlMessage
			if marshalErr != nil || repeated.Parse(encoded) != nil || repeated != ipv6 {
				t.Fatalf("IPv6 control round trip = %+v, %v, want %+v", repeated, marshalErr, ipv6)
			}
		}
		_, _, _ = parseControlMessageForWrite(control, true)

		initialError := SocketErrorControlMessage{
			Errno: 1, Origin: SocketErrorOriginLocal, Type: 2, Code: 3, Info: 4, Data: 5,
			Offender: netip.MustParseAddr("192.0.2.202"),
		}
		socketError := initialError
		if err := socketError.Parse(control); err != nil {
			if socketError != initialError {
				t.Fatal("failed socket-error control parse modified its receiver")
			}
		} else {
			if !socketError.Offender.Is4() && !socketError.Offender.Is6() {
				t.Fatalf("parsed invalid socket-error offender %v", socketError.Offender)
			}
			encoded, marshalErr := socketError.AppendBinary(nil)
			var repeated SocketErrorControlMessage
			if marshalErr != nil || repeated.Parse(encoded) != nil || repeated != socketError {
				t.Fatalf("socket-error control round trip = %+v, %v, want %+v", repeated, marshalErr, socketError)
			}
		}
		if !bytes.Equal(control, before) {
			t.Fatal("control-message parsing modified its input")
		}
	})
}

func FuzzSocketErrorControlMessageMarshalBinary(f *testing.F) {
	f.Add(false, []byte{192, 0, 2, 1}, uint32(111), uint8(SocketErrorOriginICMP), uint8(3), uint8(3), uint32(0), uint32(1))
	f.Add(true, netip.MustParseAddr("2001:db8::1").AsSlice(), uint32(90), uint8(SocketErrorOriginICMP6), uint8(2), uint8(0), uint32(1280), uint32(2))
	f.Fuzz(func(t *testing.T, v6 bool, address []byte, errno uint32, origin, messageType, code uint8, info, data uint32) {
		var offender netip.Addr
		if v6 {
			var value [16]byte
			copy(value[:], address)
			offender = netip.AddrFrom16(value)
		} else {
			var value [4]byte
			copy(value[:], address)
			offender = netip.AddrFrom4(value)
		}
		message := SocketErrorControlMessage{
			Errno: errno, Origin: SocketErrorOrigin(origin), Type: messageType,
			Code: code, Info: info, Data: data, Offender: offender,
		}
		prefix := []byte{0xaa, 0xbb}
		encoded, err := message.AppendBinary(prefix)
		if err != nil || !bytes.Equal(encoded[:len(prefix)], prefix) {
			t.Fatalf("AppendBinary = %x, %v", encoded, err)
		}
		marshaled, err := message.MarshalBinary()
		if err != nil || !bytes.Equal(encoded[len(prefix):], marshaled) {
			t.Fatalf("MarshalBinary = %x, %v, want %x", marshaled, err, encoded[len(prefix):])
		}
		var parsed SocketErrorControlMessage
		if err = parsed.Parse(marshaled); err != nil {
			t.Fatal(err)
		}
		if parsed != message {
			t.Fatalf("round trip = %+v, want %+v", parsed, message)
		}
	})
}

func FuzzIPControlMessageMarshal(f *testing.F) {
	f.Add(false, []byte{1, 2, 3}, byte(31), byte(0xb8), uint32(0))
	f.Add(true, []byte{1, 2, 3, 4, 5}, byte(29), byte(0x2e), uint32(0xabcde))
	f.Fuzz(func(t *testing.T, ipv6 bool, addressSeed []byte, hopLimit, trafficClass byte, rawFlowLabel uint32) {
		flowLabel := rawFlowLabel & ipv6MaximumFlowLabel
		var address netip.Addr
		var packetInfo []byte
		var records []testLinuxControlRecord
		if ipv6 {
			var value [16]byte
			copy(value[:], addressSeed)
			value[0] = 0x20
			address = netip.AddrFrom16(value)
			packetInfo = make([]byte, 20)
			copy(packetInfo[:16], value[:])
			records = append(records, testLinuxControlRecord{level: linuxLevelIPv6, kind: linuxIPv6PacketInfo, data: packetInfo})
			if hopLimit != 0 {
				data := make([]byte, 4)
				binary.LittleEndian.PutUint32(data, uint32(hopLimit))
				records = append(records, testLinuxControlRecord{level: linuxLevelIPv6, kind: linuxIPv6HopLimit, data: data})
			}
			if trafficClass != 0 {
				data := make([]byte, 4)
				binary.LittleEndian.PutUint32(data, uint32(trafficClass))
				records = append(records, testLinuxControlRecord{level: linuxLevelIPv6, kind: linuxIPv6TrafficClass, data: data})
			}
			if flowLabel != 0 {
				data := make([]byte, 4)
				binary.BigEndian.PutUint32(data, uint32(trafficClass)<<20|flowLabel)
				records = append(records, testLinuxControlRecord{level: linuxLevelIPv6, kind: linuxIPv6FlowInfo, data: data})
			}
			message := IPv6ControlMessage{TrafficClass: int(trafficClass), HopLimit: int(hopLimit), FlowLabel: flowLabel, Src: address}
			control, err := message.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			assertLinuxControlRecords(t, control, records...)
			var parsed IPv6ControlMessage
			if _, err = parsed.parseForWrite(control); err != nil || parsed != message {
				t.Fatalf("IPv6 control round trip = %+v, %v, want %+v", parsed, err, message)
			}
			return
		}

		var value [4]byte
		copy(value[:], addressSeed)
		value[0] = 192
		address = netip.AddrFrom4(value)
		packetInfo = make([]byte, 12)
		copy(packetInfo[4:8], value[:])
		records = append(records, testLinuxControlRecord{level: linuxLevelIP, kind: linuxIPPacketInfo, data: packetInfo})
		if hopLimit != 0 {
			data := make([]byte, 4)
			binary.LittleEndian.PutUint32(data, uint32(hopLimit))
			records = append(records, testLinuxControlRecord{level: linuxLevelIP, kind: linuxIPTimeToLive, data: data})
		}
		if trafficClass != 0 {
			data := make([]byte, 4)
			binary.LittleEndian.PutUint32(data, uint32(trafficClass))
			records = append(records, testLinuxControlRecord{level: linuxLevelIP, kind: linuxIPTypeOfService, data: data})
		}
		message := IPv4ControlMessage{TTL: int(hopLimit), TOS: int(trafficClass), Src: address}
		control, err := message.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		assertLinuxControlRecords(t, control, records...)
		var parsed IPv4ControlMessage
		if _, err = parsed.parseForWrite(control); err != nil || parsed != message {
			t.Fatalf("IPv4 control round trip = %+v, %v, want %+v", parsed, err, message)
		}
	})
}

func BenchmarkControlMessageMarshal(b *testing.B) {
	address4 := netip.MustParseAddr("192.0.2.245")
	address6 := netip.MustParseAddr("2001:db8::245")
	socketError4 := SocketErrorControlMessage{
		Errno: 111, Origin: SocketErrorOriginICMP, Type: 3, Code: 3, Data: 1, Offender: address4,
	}
	socketError6 := SocketErrorControlMessage{
		Errno: 90, Origin: SocketErrorOriginICMP6, Type: 2, Info: 1280, Data: 1, Offender: address6,
	}
	reusedSocketErrorControl := make([]byte, 0, 64)
	benchmarks := []struct {
		name    string
		marshal func() ([]byte, error)
	}{
		{name: "IPv4Send", marshal: (&IPv4ControlMessage{TTL: 31, TOS: 0xb8, Src: address4}).Marshal},
		{name: "IPv4Receive", marshal: func() ([]byte, error) {
			return controlMessageForRead(address4, address4, ipPacketOptions{hopLimit: 31, trafficClass: 0xb8})
		}},
		{name: "IPv6Send", marshal: (&IPv6ControlMessage{HopLimit: 29, TrafficClass: 0x2e, FlowLabel: 0x12345, Src: address6}).Marshal},
		{name: "IPv6Receive", marshal: func() ([]byte, error) {
			return controlMessageForRead(address6, address6, ipPacketOptions{hopLimit: 29, trafficClass: 0x2e, flowLabel: 0x12345})
		}},
		{name: "SocketErrorIPv4", marshal: socketError4.MarshalBinary},
		{name: "SocketErrorIPv6", marshal: socketError6.MarshalBinary},
		{name: "SocketErrorIPv6AppendReuse", marshal: func() ([]byte, error) {
			return socketError6.AppendBinary(reusedSocketErrorControl[:0])
		}},
		{name: "SocketErrorForRead", marshal: func() ([]byte, error) {
			return socketErrorControlForRead(ICMPError{Reporter: address6, Type: ICMPv6TypePacketTooBig, MTU: 1280})
		}},
	}
	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			for iteration := 0; iteration < b.N; iteration++ {
				control, err := benchmark.marshal()
				if err != nil || len(control) == 0 {
					b.Fatalf("Marshal = %d bytes, %v", len(control), err)
				}
			}
		})
	}
}
