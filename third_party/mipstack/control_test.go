package mipstack

import (
	"bytes"
	"context"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
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
			for _, compound := range []bool{false, true} {
				for tail := 0; tail <= linuxControlHeaderSize; tail++ {
					t.Run(fmt.Sprintf("compound-%v/tail-%d", compound, tail), func(t *testing.T) {
						var control []byte
						if compound {
							control = appendLinuxControlInt32(nil, linuxLevelIP, linuxIPTimeToLive, 31)
						}
						control = append(control, wire...)
						control = append(control, bytes.Repeat([]byte{0xa5}, tail)...)
						before := append([]byte(nil), control...)
						initial := SocketErrorControlMessage{Errno: 1, Offender: netip.MustParseAddr("192.0.2.1")}
						message := initial
						err := message.Parse(control)
						if tail == linuxControlHeaderSize {
							if err == nil || message != initial {
								t.Fatalf("invalid trailing record Parse = %+v, %v", message, err)
							}
						} else if err != nil || message != test.message {
							t.Fatalf("Parse = %+v, %v, want %+v", message, err, test.message)
						}
						if !bytes.Equal(control, before) {
							t.Fatal("socket-error parsing modified its input")
						}
					})
				}
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
			if err = message.Parse(control[:len(control)-linuxControlAlignment]); err == nil {
				t.Fatal("truncated socket error payload parsed successfully")
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
		{name: "invalid TOS width", mutate: func(wire []byte) []byte {
			binary.LittleEndian.PutUint64(wire[56:64], 18)
			return wire
		}},
		{name: "truncated payload", mutate: func(wire []byte) []byte { return wire[:len(wire)-linuxControlAlignment] }},
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

func TestControlMessageShortHeader(t *testing.T) {
	control := mustCodecVector(t, "1c000000000000000000000008000000")
	for length := 0; length < linuxControlHeaderSize; length++ {
		t.Run(fmt.Sprintf("length-%d", length), func(t *testing.T) {
			wire := control[:length]
			before := append([]byte(nil), wire...)
			message4 := IPv4ControlMessage{TTL: 7, TOS: 9, Dst: netip.MustParseAddr("192.0.2.1")}
			if err := message4.Parse(wire); err != nil || message4 != (IPv4ControlMessage{}) {
				t.Fatalf("IPv4 Parse = %+v, %v; want empty metadata", message4, err)
			}
			message6 := IPv6ControlMessage{HopLimit: 7, TrafficClass: 9, Dst: netip.MustParseAddr("2001:db8::1")}
			if err := message6.Parse(wire); err != nil || message6 != (IPv6ControlMessage{}) {
				t.Fatalf("IPv6 Parse = %+v, %v; want empty metadata", message6, err)
			}
			for _, v6 := range []bool{false, true} {
				address, options, err := parseControlMessageForWrite(wire, v6)
				if err != nil || address.IsValid() || options != (ipPacketOptions{}) {
					t.Fatalf("IPv6 %v send control = %v/%+v, %v; want defaults", v6, address, options, err)
				}
			}
			initial := SocketErrorControlMessage{Errno: 1, Offender: netip.MustParseAddr("192.0.2.1")}
			message := initial
			if err := message.Parse(wire); err == nil || err.Error() != "mipstack: socket-error control message not found" || message != initial {
				t.Fatalf("socket-error Parse = %+v, %v; want unchanged receiver and not-found error", message, err)
			}
			if !bytes.Equal(wire, before) {
				t.Fatal("short-header parsing modified its input")
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
	_, options, err = parseLinuxIPControlValues(conflicting, true, false)
	if err != nil || options.trafficClass != 1 || options.flowLabel != 1 {
		t.Fatalf("IPv6 flow-info class was not kept independent: %+v, %v", options, err)
	}
	reserved := appendLinuxControl(nil, linuxLevelIPv6, linuxIPv6FlowInfo, []byte{0x10, 0, 0, 1})
	_, options, err = parseLinuxIPControlValues(reserved, true, false)
	if err != nil || options.flowLabel != 1 || !options.flowLabelSet {
		t.Fatalf("IPv6 flow-info reserved bits were not masked: %+v, %v", options, err)
	}
}

func TestLinuxControlMessageLastWinsAndSentinels(t *testing.T) {
	first4 := appendLinuxControlInt32(nil, linuxLevelIP, linuxIPTimeToLive, 11)
	first4 = appendLinuxControlInt32(first4, linuxLevelIP, linuxIPTypeOfService, 22)
	last4 := appendLinuxControlInt32(nil, linuxLevelIP, linuxIPTimeToLive, 33)
	last4 = appendLinuxControlInt32(last4, linuxLevelIP, linuxIPTypeOfService, 44)
	_, options4, err := parseLinuxIPControlValues(append(first4, last4...), false, false)
	if err != nil || options4.hopLimit != 33 || options4.trafficClass != 44 {
		t.Fatalf("duplicate IPv4 controls = %+v, %v", options4, err)
	}
	first := appendLinuxControlInt32(nil, linuxLevelIPv6, linuxIPv6HopLimit, 11)
	first = appendLinuxControlInt32(first, linuxLevelIPv6, linuxIPv6TrafficClass, 22)
	last := appendLinuxControlInt32(nil, linuxLevelIPv6, linuxIPv6HopLimit, 33)
	last = appendLinuxControlInt32(last, linuxLevelIPv6, linuxIPv6TrafficClass, 44)
	control := append(first, last...)
	_, options, err := parseLinuxIPControlValues(control, true, false)
	if err != nil || options.hopLimit != 33 || options.trafficClass != 44 || !options.hopLimitSet || !options.trafficClassSet {
		t.Fatalf("duplicate IPv6 controls = %+v, %v", options, err)
	}
	address4 := appendLinuxIPv4PacketInfoControl(nil, netip.MustParseAddr("192.0.2.1"), netip.Addr{})
	address4 = append(address4, appendLinuxIPv4PacketInfoControl(nil, netip.MustParseAddr("192.0.2.2"), netip.Addr{})...)
	parsedAddress, _, err := parseLinuxIPControlValues(address4, false, false)
	if err != nil || parsedAddress != netip.MustParseAddr("192.0.2.2") {
		t.Fatalf("duplicate IPv4 packet-info = %v, %v", parsedAddress, err)
	}
	address4 = append(address4, appendLinuxIPv4PacketInfoControl(nil, netip.IPv4Unspecified(), netip.Addr{})...)
	parsedAddress, _, err = parseLinuxIPControlValues(address4, false, false)
	if err != nil || parsedAddress.IsValid() {
		t.Fatalf("zero IPv4 packet-info did not clear source = %v, %v", parsedAddress, err)
	}
	address6 := appendLinuxIPv6PacketInfoControl(nil, netip.MustParseAddr("2001:db8::1"))
	address6 = append(address6, appendLinuxIPv6PacketInfoControl(nil, netip.IPv6Unspecified())...)
	parsedAddress, _, err = parseLinuxIPControlValues(address6, true, false)
	if err != nil || parsedAddress != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("unspecified IPv6 packet-info changed source = %v, %v", parsedAddress, err)
	}
	flowFirst := appendLinuxControl(nil, linuxLevelIPv6, linuxIPv6FlowInfo, []byte{0, 0, 0, 1})
	flowLast := appendLinuxControl(nil, linuxLevelIPv6, linuxIPv6FlowInfo, []byte{0, 0, 0, 2})
	_, options, err = parseLinuxIPControlValues(append(flowFirst, flowLast...), true, false)
	if err != nil || options.flowLabel != 2 {
		t.Fatalf("duplicate IPv6 flow-info = %+v, %v", options, err)
	}
	reservedFlow := appendLinuxControl(nil, linuxLevelIPv6, linuxIPv6FlowInfo, []byte{0, 0, 0, 1})
	reservedFlow = append(reservedFlow, appendLinuxControl(nil, linuxLevelIPv6, linuxIPv6FlowInfo, []byte{0x10, 0, 0, 1})...)
	if _, _, err = parseLinuxIPControlValues(reservedFlow, true, false); err == nil {
		t.Fatal("duplicate IPv6 flow-info accepted conflicting reserved bits")
	}
	zeroFlow := appendLinuxControl(nil, linuxLevelIPv6, linuxIPv6FlowInfo, []byte{0x10, 0, 0, 0})
	zeroFlow = append(zeroFlow, appendLinuxControl(nil, linuxLevelIPv6, linuxIPv6FlowInfo, []byte{0, 0, 0, 1})...)
	if _, options, err = parseLinuxIPControlValues(zeroFlow, true, false); err != nil || options.flowLabel != 1 {
		t.Fatalf("zero masked IPv6 flow-info did not permit later value = %+v, %v", options, err)
	}
	sentinel := appendLinuxControlInt32(nil, linuxLevelIPv6, linuxIPv6HopLimit, -1)
	sentinel = appendLinuxControlInt32(sentinel, linuxLevelIPv6, linuxIPv6TrafficClass, -1)
	_, options, err = parseLinuxIPControlValues(sentinel, true, false)
	if err != nil || options.hopLimit != 0 || options.hopLimitSet || options.trafficClass != 0 || options.trafficClassSet {
		t.Fatalf("IPv6 default sentinels = %+v, %v", options, err)
	}
	if _, _, err = parseLinuxIPControlValues(sentinel, true, true); err == nil {
		t.Fatal("IPv6 receive ancillary accepted the outbound-only -1 sentinel")
	}
	message := &IPv6ControlMessage{HopLimit: -1, TrafficClass: -1, FlowLabel: 1}
	encoded, err := message.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	_, options, err = parseControlMessageForWrite(encoded, true)
	if err != nil || options.hopLimitSet || options.trafficClassSet || options.flowLabel != 1 || !options.flowLabelSet {
		t.Fatalf("structured IPv6 sentinels = %+v, %v", options, err)
	}
}

func TestLinuxControlMessageTruncation(t *testing.T) {
	partial := appendLinuxControl(nil, linuxLevelIPv6, linuxIPv6HopLimit, make([]byte, 8))
	padded := appendLinuxControlInt32(nil, linuxLevelIPv6, linuxIPv6HopLimit, 31)
	for _, test := range []struct {
		name      string
		control   []byte
		capacity  int
		want      int
		truncated bool
		length    uint64
	}{
		{name: "empty", control: partial, capacity: 0, want: 0, truncated: true},
		{name: "header only", control: partial, capacity: 16, want: 16, truncated: true, length: 16},
		{name: "partial payload", control: partial, capacity: 20, want: 20, truncated: true, length: 20},
		{name: "missing tail padding", control: padded, capacity: 20, want: 20, truncated: false, length: 20},
	} {
		t.Run(test.name, func(t *testing.T) {
			buffer := make([]byte, test.capacity)
			n, truncated := copyLinuxControlMessages(buffer, test.control)
			if n != test.want || truncated != test.truncated {
				t.Fatalf("copy control = %d/%t, want %d/%t", n, truncated, test.want, test.truncated)
			}
			if test.length != 0 && binary.LittleEndian.Uint64(buffer[:8]) != test.length {
				t.Fatalf("partial cmsg length = %d, want %d", binary.LittleEndian.Uint64(buffer[:8]), test.length)
			}
		})
	}
	second := appendLinuxControlInt32(nil, linuxLevelIPv6, linuxIPv6TrafficClass, 47)
	compound := append(append([]byte(nil), padded...), second...)
	for _, test := range []struct {
		name      string
		capacity  int
		want      int
		truncated bool
		secondLen uint64
	}{
		{name: "compound first record", capacity: len(padded), want: len(padded), truncated: true},
		{name: "compound second header", capacity: len(padded) + 4, want: len(padded), truncated: true},
		{name: "compound second payload", capacity: len(padded) + linuxControlHeaderSize, want: len(padded) + linuxControlHeaderSize, truncated: true, secondLen: linuxControlHeaderSize},
		{name: "compound second without padding", capacity: len(padded) + 20, want: len(padded) + 20, truncated: false, secondLen: 20},
	} {
		t.Run(test.name, func(t *testing.T) {
			buffer := make([]byte, test.capacity)
			n, truncated := copyLinuxControlMessages(buffer, compound)
			if n != test.want || truncated != test.truncated {
				t.Fatalf("copy compound control = %d/%t, want %d/%t", n, truncated, test.want, test.truncated)
			}
			if n >= len(padded)+linuxControlHeaderSize && test.secondLen != 0 {
				if length := binary.LittleEndian.Uint64(buffer[len(padded) : len(padded)+8]); length != test.secondLen {
					t.Fatalf("partial second cmsg length = %d, want %d", length, test.secondLen)
				}
			}
		})
	}
	for _, test := range []struct {
		name  string
		parse func([]byte) error
	}{
		{name: "IPv4", parse: func(control []byte) error { var message IPv4ControlMessage; return message.Parse(control) }},
		{name: "IPv6", parse: func(control []byte) error { var message IPv6ControlMessage; return message.Parse(control) }},
		{name: "socket error", parse: func(control []byte) error { var message SocketErrorControlMessage; return message.Parse(control) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var control []byte
			switch test.name {
			case "IPv4":
				control, _ = (&IPv4ControlMessage{TTL: 31}).Marshal()
			case "IPv6":
				control, _ = (&IPv6ControlMessage{HopLimit: 31}).Marshal()
			case "socket error":
				control, _ = (SocketErrorControlMessage{Errno: 111, Offender: netip.MustParseAddr("2001:db8::1")}).MarshalBinary()
			}
			if len(control) < 2 || test.parse(control[:len(control)-1]) != nil {
				t.Fatal("complete ancillary payload with partial final padding was rejected")
			}
		})
	}
}

func TestLinuxControlMessageFinalPadding(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		var level, hopKind, classKind uint32 = linuxLevelIP, linuxIPTimeToLive, linuxIPTypeOfService
		if v6 {
			level, hopKind, classKind = linuxLevelIPv6, linuxIPv6HopLimit, linuxIPv6TrafficClass
		}
		last := appendLinuxControlInt32(nil, level, hopKind, 31)
		for i := 20; i < len(last); i++ {
			last[i] = 0xa5
		}
		last = append(last, bytes.Repeat([]byte{0xa5}, linuxControlHeaderSize)...)
		for _, compound := range []bool{false, true} {
			for length := 19; length <= len(last); length++ {
				t.Run(fmt.Sprintf("IPv6-%v/compound-%v/length-%d", v6, compound, length), func(t *testing.T) {
					var control []byte
					if compound {
						control = appendLinuxControlInt32(nil, level, classKind, 47)
					}
					control = append(control, last[:length]...)
					before := append([]byte(nil), control...)
					invalid := length < 20 || length == len(last)
					for _, receiving := range []bool{false, true} {
						_, options, err := parseLinuxIPControlValues(control, v6, receiving)
						if invalid {
							if err == nil {
								t.Fatal("invalid control record was accepted")
							}
							continue
						}
						if err != nil || !options.hopLimitSet || options.hopLimit != 31 ||
							compound && (!options.trafficClassSet || options.trafficClass != 47) {
							t.Fatalf("receiving %v control = %+v, %v", receiving, options, err)
						}
					}
					class := 0
					if compound {
						class = 47
					}
					if v6 {
						initial := IPv6ControlMessage{HopLimit: 7, TrafficClass: 9}
						message := initial
						err := message.Parse(control)
						if invalid {
							if err == nil || message != initial {
								t.Fatalf("invalid IPv6 Parse = %+v, %v", message, err)
							}
						} else if err != nil || message != (IPv6ControlMessage{HopLimit: 31, TrafficClass: class}) {
							t.Fatalf("IPv6 Parse = %+v, %v", message, err)
						}
					} else {
						initial := IPv4ControlMessage{TTL: 7, TOS: 9}
						message := initial
						err := message.Parse(control)
						if invalid {
							if err == nil || message != initial {
								t.Fatalf("invalid IPv4 Parse = %+v, %v", message, err)
							}
						} else if err != nil || message != (IPv4ControlMessage{TTL: 31, TOS: class}) {
							t.Fatalf("IPv4 Parse = %+v, %v", message, err)
						}
					}
					if !bytes.Equal(control, before) {
						t.Fatal("control parsing modified its input")
					}
				})
			}
		}
	}
}

func TestLinuxControlMessageInvalidTrailingRecord(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		var level, kind uint32 = linuxLevelIP, linuxIPTimeToLive
		if v6 {
			level, kind = linuxLevelIPv6, linuxIPv6HopLimit
		}
		valid := appendLinuxControlInt32(nil, level, kind, 31)
		for _, test := range []struct {
			name    string
			length  uint64
			payload []byte
		}{
			{name: "length below header", length: 15},
			{name: "length beyond input", length: 20},
			{name: "missing scalar", length: 16},
			{name: "short scalar", length: 19, payload: []byte{31, 0, 0}},
		} {
			t.Run(fmt.Sprintf("IPv6-%v/%s", v6, test.name), func(t *testing.T) {
				tail := make([]byte, linuxControlHeaderSize+len(test.payload))
				binary.LittleEndian.PutUint64(tail[:8], test.length)
				binary.LittleEndian.PutUint32(tail[8:12], level)
				binary.LittleEndian.PutUint32(tail[12:16], kind)
				copy(tail[linuxControlHeaderSize:], test.payload)
				control := append(append([]byte(nil), valid...), tail...)
				before := append([]byte(nil), control...)
				if _, _, err := parseControlMessageForWrite(control, v6); err == nil {
					t.Fatal("invalid complete trailing record accepted on write")
				}
				if v6 {
					initial := IPv6ControlMessage{HopLimit: 7, TrafficClass: 9}
					message := initial
					if err := message.Parse(control); err == nil || message != initial {
						t.Fatalf("invalid IPv6 Parse = %+v, %v", message, err)
					}
				} else {
					initial := IPv4ControlMessage{TTL: 7, TOS: 9}
					message := initial
					if err := message.Parse(control); err == nil || message != initial {
						t.Fatalf("invalid IPv4 Parse = %+v, %v", message, err)
					}
				}
				errorControl, err := (SocketErrorControlMessage{Errno: 111, Origin: SocketErrorOriginICMP, Offender: netip.MustParseAddr("192.0.2.1")}).MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if test.length < linuxControlHeaderSize || test.length > uint64(len(tail)) {
					initial := SocketErrorControlMessage{Errno: 1}
					message := initial
					if err = message.Parse(append(errorControl, tail...)); err == nil || message != initial {
						t.Fatalf("invalid socket-error framing Parse = %+v, %v", message, err)
					}
				}
				if !bytes.Equal(control, before) {
					t.Fatal("failed parsing modified its input")
				}
			})
		}
	}
}

func TestLinuxControlMessagePayloadLengths(t *testing.T) {
	packetInfo6 := make([]byte, 20)
	address := netip.MustParseAddr("2001:db8::1").As16()
	copy(packetInfo6, address[:])
	for _, test := range []struct {
		name        string
		level, kind uint32
		data        []byte
		v6, extra   bool
	}{
		{name: "IPv6 packet info", level: linuxLevelIPv6, kind: linuxIPv6PacketInfo, data: packetInfo6, v6: true, extra: true},
		{name: "IPv6 flow info", level: linuxLevelIPv6, kind: linuxIPv6FlowInfo, data: []byte{0, 0, 0, 7}, v6: true, extra: true},
		{name: "IPv4 packet info", level: linuxLevelIP, kind: linuxIPPacketInfo, data: make([]byte, 12)},
		{name: "IPv4 TTL", level: linuxLevelIP, kind: linuxIPTimeToLive, data: []byte{31, 0, 0, 0}},
		{name: "IPv6 hop limit", level: linuxLevelIPv6, kind: linuxIPv6HopLimit, data: []byte{31, 0, 0, 0}, v6: true},
		{name: "IPv6 traffic class", level: linuxLevelIPv6, kind: linuxIPv6TrafficClass, data: []byte{47, 0, 0, 0}, v6: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var level, kind uint32 = linuxLevelIP, linuxIPTimeToLive
			if test.v6 {
				level, kind = linuxLevelIPv6, linuxIPv6HopLimit
			}
			for _, delta := range []int{-1, 0, 1, 4, 8} {
				t.Run(fmt.Sprintf("extra-%d", delta), func(t *testing.T) {
					data := bytes.Repeat([]byte{0xa5}, len(test.data)+8)
					copy(data, test.data)
					control := appendLinuxControl(nil, test.level, test.kind, data[:len(test.data)+delta])
					control = appendLinuxControlInt32(control, level, kind, 61)
					canonical := appendLinuxControl(nil, test.level, test.kind, test.data)
					canonical = appendLinuxControlInt32(canonical, level, kind, 61)
					for _, receiving := range []bool{false, true} {
						address, options, err := parseLinuxIPControlValues(control, test.v6, receiving)
						if delta < 0 || delta > 0 && !test.extra {
							if err == nil {
								t.Fatal("invalid payload length was accepted")
							}
							continue
						}
						wantAddress, wantOptions, wantErr := parseLinuxIPControlValues(canonical, test.v6, receiving)
						if err != nil || wantErr != nil || address != wantAddress || options != wantOptions || options.hopLimit != 61 {
							t.Fatalf("receiving %v control = %v/%+v, %v; want %v/%+v, %v", receiving, address, options, err, wantAddress, wantOptions, wantErr)
						}
					}
				})
			}
		})
	}
}

func TestLinuxControlMessageWritePaths(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		local, remote := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.10")
		if v6 {
			local, remote = netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("2001:db8:1::10")
		}
		for _, mode := range []string{"UDP", "IP", "IP header included"} {
			t.Run(fmt.Sprintf("IPv6-%v/%s", v6, mode), func(t *testing.T) {
				defaults := DatagramSocketDefaults{HopLimit: 53, TrafficClass: 17, FlowLabel: 9}
				stack, err := New(Config{
					LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, local.BitLen())},
					UDP:            UDPSocketDefaults{DatagramSocketDefaults: defaults},
					IP:             IPSocketDefaults{DatagramSocketDefaults: defaults},
				})
				if err != nil {
					t.Fatal(err)
				}
				if err = stack.Start(); err != nil {
					t.Fatal(err)
				}
				defer stack.Close()
				var udp *UDPConn
				var ip *IPConn
				if mode == "UDP" {
					connection, err := stack.ListenUDP(context.Background(), "udp", netip.AddrPortFrom(local, 50123))
					if err != nil {
						t.Fatal(err)
					}
					udp = connection.(*UDPConn)
					defer udp.Close()
				} else {
					connection, err := stack.ListenIP(context.Background(), "ip:99", local)
					if err != nil {
						t.Fatal(err)
					}
					ip = connection.(*IPConn)
					defer ip.Close()
					if err = ip.SetIPHeaderIncludedOnWrite(mode == "IP header included"); err != nil {
						t.Fatal(err)
					}
				}
				for _, oversized := range []bool{false, true} {
					var control []byte
					if v6 {
						data := make([]byte, 20)
						address := local.As16()
						copy(data, address[:])
						if oversized {
							data = append(data, 0xa5, 0xa5, 0xa5, 0xa5)
						}
						control = appendLinuxControl(nil, linuxLevelIPv6, linuxIPv6PacketInfo, data)
						data = []byte{0, 0, 0, 7}
						if oversized {
							data = append(data, 0xa5, 0xa5, 0xa5, 0xa5)
						}
						control = appendLinuxControl(control, linuxLevelIPv6, linuxIPv6FlowInfo, data)
						control = appendLinuxControlInt32(control, linuxLevelIPv6, linuxIPv6HopLimit, 31)
						control = appendLinuxControlInt32(control, linuxLevelIPv6, linuxIPv6TrafficClass, 47)
					} else {
						control = appendLinuxIPv4PacketInfoControl(nil, local, netip.Addr{})
						control = appendLinuxControlInt32(control, linuxLevelIP, linuxIPTimeToLive, 31)
						control = appendLinuxControlInt32(control, linuxLevelIP, linuxIPTypeOfService, 47)
					}
					type controlTest struct {
						name              string
						oob               []byte
						defaults, invalid bool
					}
					tests := []controlTest{
						{name: "partial padding", oob: control[:len(control)-1]},
					}
					for tail := 0; tail <= linuxControlHeaderSize; tail++ {
						oob := append([]byte(nil), control...)
						oob = append(oob, bytes.Repeat([]byte{0xa5}, tail)...)
						tests = append(tests, controlTest{name: fmt.Sprintf("tail-%d", tail), oob: oob, invalid: tail == linuxControlHeaderSize})
					}
					for length := 0; length < linuxControlHeaderSize; length++ {
						tests = append(tests, controlTest{name: fmt.Sprintf("short-%d", length), oob: bytes.Repeat([]byte{0xa5}, length), defaults: true})
					}
					methods := []string{"message", "batch single buffer", "batch scatter"}
					if udp != nil {
						methods = append(methods, "message addrport")
					}
					for _, test := range tests {
						for _, method := range methods {
							t.Run(fmt.Sprintf("oversized-%v/%s/%s", oversized, test.name, method), func(t *testing.T) {
								before := append([]byte(nil), test.oob...)
								payload := []byte("control boundaries")
								var address net.Addr = ipNetAddr(remote)
								if udp != nil {
									address = net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 50124))
								} else if mode == "IP header included" {
									payload = buildIPPacketWithOptions(local, remote, 99, payload, 1, true, ipPacketOptions{hopLimit: 31, trafficClass: 47, flowLabel: 7})
								}
								batch := method == "batch single buffer" || method == "batch scatter"
								if batch {
									buffers := [][]byte{payload}
									if method == "batch scatter" {
										buffers = [][]byte{payload[:3], payload[3:]}
									}
									messages := []SocketMessage{{Buffers: buffers, OOB: test.oob, Addr: address}}
									if test.invalid {
										messages = []SocketMessage{
											{Buffers: buffers, OOB: control, Addr: address},
											{Buffers: buffers, OOB: test.oob, Addr: address, N: -1, NN: -1, Flags: -1},
											{Buffers: buffers, OOB: control, Addr: address, N: -1, NN: -1, Flags: -1},
										}
									}
									var n int
									if udp != nil {
										n, err = udp.WriteBatch(messages, 0)
									} else {
										n, err = ip.WriteBatch(messages, 0)
									}
									wantNN := len(test.oob)
									if test.invalid {
										wantNN = len(control)
									}
									if n != 1 || err != nil || messages[0].N != len(payload) || messages[0].NN != wantNN {
										t.Fatalf("WriteBatch = %d, %v, message %+v", n, err, messages[0])
									}
									if test.invalid {
										for _, message := range messages[1:] {
											if message.N != -1 || message.NN != -1 || message.Flags != -1 {
												t.Fatalf("unwritten batch suffix modified: %+v", message)
											}
										}
										if udp != nil {
											n, err = udp.WriteBatch(messages[1:2], 0)
										} else {
											n, err = ip.WriteBatch(messages[1:2], 0)
										}
										if n != 0 || err == nil || messages[1].N != -1 || messages[1].NN != -1 || messages[1].Flags != -1 {
											t.Fatalf("invalid first WriteBatch = %d, %v, message %+v", n, err, messages[1])
										}
									}
								} else {
									var n, nn int
									if method == "message addrport" {
										n, nn, err = udp.WriteMsgUDPAddrPort(payload, test.oob, netip.AddrPortFrom(remote, 50124))
									} else if udp != nil {
										n, nn, err = udp.WriteMsgUDP(payload, test.oob, address.(*net.UDPAddr))
									} else {
										n, nn, err = ip.WriteMsgIP(payload, test.oob, address.(*net.IPAddr))
									}
									if test.invalid {
										if err == nil || n != 0 || nn != 0 || stack.outbound.len() != 0 {
											t.Fatalf("invalid WriteMsg = %d/%d, %v, queued %d packets", n, nn, err, stack.outbound.len())
										}
										if !bytes.Equal(test.oob, before) {
											t.Fatal("failed write modified its control data")
										}
										return
									}
									if err != nil || n != len(payload) || nn != len(test.oob) {
										t.Fatalf("WriteMsg = %d/%d, %v", n, nn, err)
									}
								}
								hop, class, label := uint8(31), uint8(47), uint32(7)
								if test.defaults && mode != "IP header included" {
									hop, class, label = 53, 17, 9
								}
								packet, valid := parseIPPacket(readOutboundPacket(t, stack), false)
								data := packet.payload
								if udp != nil && valid {
									data = data[udpHeaderSize:]
								}
								if !valid || packet.source != local || packet.target != remote || packet.hopLimit != hop || packet.trafficClass != class ||
									v6 && packet.flowLabel != label || string(data) != "control boundaries" {
									t.Fatalf("packet = %+v, parsed %v; want hop/class/label %d/%d/%d", packet, valid, hop, class, label)
								}
								if stack.outbound.len() != 0 || !bytes.Equal(test.oob, before) {
									t.Fatal("write queued extra packets or modified its control data")
								}
							})
						}
					}
					if !v6 {
						break
					}
				}
			})
		}
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
	for _, control := range [][]byte{control4, control6, error4, error6} {
		for _, tail := range []int{1, 7, 8, 15, 16} {
			seed := append([]byte(nil), control...)
			f.Add(append(seed, bytes.Repeat([]byte{0xa5}, tail)...))
		}
	}
	f.Add(bytes.Repeat([]byte{0xa5}, linuxControlHeaderSize-1))
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

func BenchmarkControlMessageParse(b *testing.B) {
	control4, err := (&IPv4ControlMessage{TTL: 31, TOS: 0xb8, Src: netip.MustParseAddr("192.0.2.245")}).Marshal()
	if err != nil {
		b.Fatal(err)
	}
	control6, err := (&IPv6ControlMessage{HopLimit: 29, TrafficClass: 0x2e, FlowLabel: 0x12345, Src: netip.MustParseAddr("2001:db8::245")}).Marshal()
	if err != nil {
		b.Fatal(err)
	}
	for _, benchmark := range []struct {
		name    string
		control []byte
		v6      bool
	}{
		{name: "Empty"},
		{name: "IPv4", control: control4},
		{name: "IPv6", control: control6, v6: true},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			for _, receiving := range []bool{false, true} {
				name := "Write"
				if receiving {
					name = "Read"
				}
				b.Run(name, func(b *testing.B) {
					b.ReportAllocs()
					for i := 0; i < b.N; i++ {
						if _, _, err := parseLinuxIPControlValues(benchmark.control, benchmark.v6, receiving); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func BenchmarkSocketErrorControlMessageParse(b *testing.B) {
	for _, address := range []string{"192.0.2.245", "2001:db8::245"} {
		b.Run(address, func(b *testing.B) {
			control, err := (SocketErrorControlMessage{Errno: 111, Offender: netip.MustParseAddr(address)}).MarshalBinary()
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var message SocketErrorControlMessage
				if err := message.Parse(control); err != nil || message.Errno != 111 {
					b.Fatalf("Parse = %+v, %v", message, err)
				}
			}
		})
	}
}

func BenchmarkLinuxControlMessageWrite(b *testing.B) {
	const payloadSize = 1200
	for _, v6 := range []bool{false, true} {
		local, remote := netip.MustParseAddr("192.0.2.245"), netip.MustParseAddr("198.51.100.245")
		if v6 {
			local, remote = netip.MustParseAddr("2001:db8::245"), netip.MustParseAddr("2001:db8:1::245")
		}
		for _, mode := range []string{"UDP", "IP", "IP header included"} {
			for _, oob := range []bool{false, true} {
				methods := []string{"message", "batch"}
				if mode == "UDP" {
					methods = append(methods, "message addrport")
				}
				for _, method := range methods {
					b.Run(fmt.Sprintf("IPv6-%v/%s/OOB-%v/%s", v6, mode, oob, method), func(b *testing.B) {
						stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, local.BitLen())}})
						if err != nil {
							b.Fatal(err)
						}
						b.Cleanup(func() { _ = stack.Close() })
						if err = stack.Start(); err != nil {
							b.Fatal(err)
						}
						var udp *UDPConn
						var ip *IPConn
						var address net.Addr = ipNetAddr(remote)
						if mode == "UDP" {
							connection, err := stack.ListenUDP(context.Background(), "udp", netip.AddrPortFrom(local, 50123))
							if err != nil {
								b.Fatal(err)
							}
							udp = connection.(*UDPConn)
							b.Cleanup(func() { _ = udp.Close() })
							address = net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 50124))
						} else {
							connection, err := stack.ListenIP(context.Background(), "ip:99", local)
							if err != nil {
								b.Fatal(err)
							}
							ip = connection.(*IPConn)
							b.Cleanup(func() { _ = ip.Close() })
							if err = ip.SetIPHeaderIncludedOnWrite(mode == "IP header included"); err != nil {
								b.Fatal(err)
							}
						}
						var control []byte
						if oob {
							if v6 {
								control, err = (&IPv6ControlMessage{Src: local, HopLimit: 31, TrafficClass: 47, FlowLabel: 7}).Marshal()
							} else {
								control, err = (&IPv4ControlMessage{Src: local, TTL: 31, TOS: 47}).Marshal()
							}
							if err != nil {
								b.Fatal(err)
							}
						}
						payload := make([]byte, payloadSize)
						if mode == "IP header included" {
							payload = buildIPPacketWithOptions(local, remote, 99, payload, 1, true, ipPacketOptions{hopLimit: 31, trafficClass: 47, flowLabel: 7})
						}
						count := 1
						if method == "batch" {
							count = 16
						}
						messages := make([]SocketMessage, count)
						packets := make([][]byte, count)
						sizes := make([]int, count)
						for i := range messages {
							messages[i] = SocketMessage{Buffers: [][]byte{payload[:400], payload[400:]}, OOB: control, Addr: address}
							packets[i] = make([]byte, 1500)
						}
						b.SetBytes(int64(count * len(payload)))
						b.ReportAllocs()
						b.ResetTimer()
						for i := 0; i < b.N; i++ {
							var n, nn int
							switch method {
							case "batch":
								if udp != nil {
									n, err = udp.WriteBatch(messages, 0)
								} else {
									n, err = ip.WriteBatch(messages, 0)
								}
								if err != nil || n != count || messages[count-1].N != len(payload) || messages[count-1].NN != len(control) {
									b.Fatalf("WriteBatch = %d, %v", n, err)
								}
							case "message addrport":
								n, nn, err = udp.WriteMsgUDPAddrPort(payload, control, netip.AddrPortFrom(remote, 50124))
							default:
								if udp != nil {
									n, nn, err = udp.WriteMsgUDP(payload, control, address.(*net.UDPAddr))
								} else {
									n, nn, err = ip.WriteMsgIP(payload, control, address.(*net.IPAddr))
								}
							}
							if method != "batch" && (err != nil || n != len(payload) || nn != len(control)) {
								b.Fatalf("WriteMsg = %d/%d, %v", n, nn, err)
							}
							if n, err = stack.Read(packets, sizes, 0); err != nil || n != count {
								b.Fatalf("Stack.Read = %d, %v", n, err)
							}
						}
					})
				}
			}
		}
	}
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
