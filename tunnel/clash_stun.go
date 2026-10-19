package tunnel

import (
	"encoding/binary"
	"hash/crc32"
	"net"
	"net/netip"

	C "github.com/ProjectClash/Clash/constant"
)


const (
	stunBindingSuccess          = 0x0101
	stunAttrMappedAddress       = 0x0001
	stunAttrXORMappedAddress    = 0x0020
	stunAttrXORMappedAddressOld = 0x8020
	stunAttrMessageIntegrity    = 0x0008
	stunAttrIntegritySHA256     = 0x001c
	stunAttrFingerprint         = 0x8028
	stunFingerprintXOR          = 0x5354554e
)

type stunResponseWriteBack struct {
	client     C.WriteBack
	ipv4, ipv6 netip.Addr
}

func (w stunResponseWriteBack) WriteBack(b []byte, addr net.Addr) (int, error) {
	rewriteSTUNMappedAddresses(b, w.ipv4, w.ipv6)
	return w.client.WriteBack(b, addr)
}

func stunWriteBack(wb C.WriteBack, firstProtocol string, routing C.ClashRouting) C.WriteBack {
	if firstProtocol != "STUN" || (!routing.STUNResponseIPv4.IsValid() && !routing.STUNResponseIPv6.IsValid()) {
		return wb
	}
	return stunResponseWriteBack{client: wb, ipv4: routing.STUNResponseIPv4, ipv6: routing.STUNResponseIPv6}
}

func rewriteSTUNMappedAddresses(b []byte, ipv4, ipv6 netip.Addr) bool {
	if len(b) < 20 || binary.BigEndian.Uint16(b[0:2]) != stunBindingSuccess ||
		binary.BigEndian.Uint32(b[4:8]) != stunMagicCookie {
		return false
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if 20+length > len(b) || length%4 != 0 {
		return false
	}
	message := b[:20+length]
	type attribute struct{ typ, offset, length int }
	var addresses []attribute
	fingerprint := -1
	for offset := 20; offset+4 <= len(message); {
		typ := int(binary.BigEndian.Uint16(message[offset:]))
		size := int(binary.BigEndian.Uint16(message[offset+2:]))
		value := offset + 4
		if value+size > len(message) {
			return false
		}
		switch typ {
		case stunAttrMessageIntegrity, stunAttrIntegritySHA256:
			return false
		case stunAttrMappedAddress, stunAttrXORMappedAddress, stunAttrXORMappedAddressOld:
			addresses = append(addresses, attribute{typ, value, size})
		case stunAttrFingerprint:
			if size == 4 {
				fingerprint = offset
			}
		}
		offset = value + (size+3)&^3
	}
	changed := false
	for _, a := range addresses {
		if a.length < 4 {
			continue
		}
		value := message[a.offset : a.offset+a.length]
		var replacement netip.Addr
		switch value[1] {
		case 0x01:
			if a.length != 8 {
				continue
			}
			replacement = ipv4
		case 0x02:
			if a.length != 20 {
				continue
			}
			replacement = ipv6
		}
		if !replacement.IsValid() {
			continue
		}
		address := replacement.AsSlice()
		if a.typ != stunAttrMappedAddress {
			for i := range address {
				address[i] ^= message[4+i]
			}
		}
		copy(value[4:], address)
		changed = true
	}
	if changed && fingerprint >= 0 {
		crc := crc32.ChecksumIEEE(message[:fingerprint]) ^ stunFingerprintXOR
		binary.BigEndian.PutUint32(message[fingerprint+4:], crc)
	}
	return changed
}
