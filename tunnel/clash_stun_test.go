package tunnel

import (
	"encoding/binary"
	"hash/crc32"
	"net"
	"net/netip"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
)

func stunResponse(transaction [12]byte, attributes ...[2]any) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], stunBindingSuccess)
	binary.BigEndian.PutUint32(b[4:8], stunMagicCookie)
	copy(b[8:20], transaction[:])
	for _, a := range attributes {
		value := a[1].([]byte)
		header := make([]byte, 4)
		binary.BigEndian.PutUint16(header[0:2], uint16(a[0].(int)))
		binary.BigEndian.PutUint16(header[2:4], uint16(len(value)))
		b = append(b, header...)
		b = append(b, value...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
	}
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)-20))
	return b
}

func xorAddress(b []byte, addr netip.Addr, port uint16) []byte {
	ip := addr.AsSlice()
	family := byte(0x01)
	if addr.Is6() {
		family = 0x02
	}
	value := []byte{0, family, 0, 0}
	binary.BigEndian.PutUint16(value[2:], port^uint16(stunMagicCookie>>16))
	for i := range ip {
		ip[i] ^= b[4+i]
	}
	return append(value, ip...)
}

func readXORAddress(header []byte, value []byte) netip.Addr {
	ip := append([]byte(nil), value[4:]...)
	for i := range ip {
		ip[i] ^= header[4+i]
	}
	addr, _ := netip.AddrFromSlice(ip)
	return addr
}

func withFingerprint(b []byte) []byte {
	b = append(b, 0x80, 0x28, 0, 4, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)-20))
	binary.BigEndian.PutUint32(b[len(b)-4:], crc32.ChecksumIEEE(b[:len(b)-8])^stunFingerprintXOR)
	return b
}

func TestASTUNAnswerNamesTheConfiguredAddresses(t *testing.T) {
	transaction := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	header := make([]byte, 20)
	binary.BigEndian.PutUint32(header[4:8], stunMagicCookie)
	copy(header[8:], transaction[:])
	public4, public6 := netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("2001:db8::9")
	fake4, fake6 := netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("::1")

	answer := withFingerprint(stunResponse(transaction,
		[2]any{stunAttrXORMappedAddress, xorAddress(header, public4, 50000)},
		[2]any{stunAttrMappedAddress, append([]byte{0, 1, 0xc3, 0x50}, public4.AsSlice()...)},
		[2]any{stunAttrXORMappedAddress, xorAddress(header, public6, 50000)},
	))
	if !rewriteSTUNMappedAddresses(answer, fake4, fake6) {
		t.Fatal("the answer was not rewritten")
	}
	if got := readXORAddress(header, answer[24:32]); got != fake4 {
		t.Errorf("XOR-MAPPED-ADDRESS reads %s, want %s", got, fake4)
	}
	if got, _ := netip.AddrFromSlice(answer[40:44]); got != fake4 {
		t.Errorf("MAPPED-ADDRESS reads %s, want %s", got, fake4)
	}
	if got := readXORAddress(header, answer[48:68]); got != fake6 {
		t.Errorf("the IPv6 XOR-MAPPED-ADDRESS reads %s, want %s", got, fake6)
	}
	if port := binary.BigEndian.Uint16(answer[26:28]) ^ uint16(stunMagicCookie>>16); port != 50000 {
		t.Errorf("the port became %d", port)
	}
	n := len(answer)
	if crc := binary.BigEndian.Uint32(answer[n-4:]); crc != crc32.ChecksumIEEE(answer[:n-8])^stunFingerprintXOR {
		t.Error("the FINGERPRINT was not computed again")
	}
}

func TestASTUNAnswerIsLeftAloneWhenItCannotBeRewritten(t *testing.T) {
	transaction := [12]byte{9}
	header := make([]byte, 20)
	binary.BigEndian.PutUint32(header[4:8], stunMagicCookie)
	copy(header[8:], transaction[:])
	public4 := netip.MustParseAddr("203.0.113.9")
	fake4 := netip.MustParseAddr("1.1.1.1")
	for name, answer := range map[string][]byte{
		"signed": stunResponse(transaction,
			[2]any{stunAttrXORMappedAddress, xorAddress(header, public4, 1)},
			[2]any{stunAttrMessageIntegrity, make([]byte, 20)}),
		"a request": func() []byte {
			b := stunResponse(transaction, [2]any{stunAttrXORMappedAddress, xorAddress(header, public4, 1)})
			binary.BigEndian.PutUint16(b[0:2], 0x0001)
			return b
		}(),
		"no IPv6 configured for an IPv6 answer": stunResponse(transaction,
			[2]any{stunAttrXORMappedAddress, xorAddress(header, netip.MustParseAddr("2001:db8::1"), 1)}),
		"truncated": stunResponse(transaction, [2]any{stunAttrXORMappedAddress, xorAddress(header, public4, 1)})[:26],
	} {
		before := append([]byte(nil), answer...)
		if rewriteSTUNMappedAddresses(answer, fake4, netip.Addr{}) || string(before) != string(answer) {
			t.Errorf("%s: rewritten", name)
		}
	}
}

type capturedWriteBack struct{ written [][]byte }

func (c *capturedWriteBack) WriteBack(b []byte, _ net.Addr) (int, error) {
	c.written = append(c.written, append([]byte(nil), b...))
	return len(b), nil
}

func TestOnlyASTUNFlowWithAnAddressIsRewritten(t *testing.T) {
	plain := &capturedWriteBack{}
	routing := C.ClashRouting{STUNResponseIPv4: netip.MustParseAddr("1.1.1.1")}
	if got := stunWriteBack(plain, "QUIC", routing); got != C.WriteBack(plain) {
		t.Fatal("a QUIC flow got the STUN rewrite")
	}
	if got := stunWriteBack(plain, "STUN", C.ClashRouting{}); got != C.WriteBack(plain) {
		t.Fatal("a STUN flow got the rewrite with no address configured")
	}
	transaction := [12]byte{7}
	header := make([]byte, 20)
	binary.BigEndian.PutUint32(header[4:8], stunMagicCookie)
	copy(header[8:], transaction[:])
	answer := stunResponse(transaction, [2]any{stunAttrXORMappedAddress, xorAddress(header, netip.MustParseAddr("203.0.113.9"), 1)})
	if _, err := stunWriteBack(plain, "STUN", routing).WriteBack(answer, &net.UDPAddr{}); err != nil {
		t.Fatal(err)
	}
	if got := readXORAddress(header, plain.written[0][24:32]); got != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("the client read %s, want 1.1.1.1", got)
	}
}
