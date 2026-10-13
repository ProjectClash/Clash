package stun

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net/netip"

	E "github.com/metacubex/sing/common/exceptions"
)

const (
	TransactionIDSize = 12
	HeaderSize        = 20

	magicCookie         = 0x2112A442
	bindingRequestType  = 0x0001
	attrXORMappedAddr   = 0x0020
	xorMappedFamilyIPv4 = 0x01
	xorMappedFamilyIPv6 = 0x02
)

type TransactionID [TransactionIDSize]byte

type Message struct {
	Raw           []byte
	TransactionID TransactionID
}

func IsMessage(b []byte) bool {
	return len(b) >= HeaderSize && binary.BigEndian.Uint32(b[4:8]) == magicCookie
}

func NewBindingRequest() (*Message, error) {
	var transactionID TransactionID
	_, err := io.ReadFull(rand.Reader, transactionID[:])
	if err != nil {
		return nil, E.Cause(err, "generate STUN transaction ID")
	}
	raw := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(raw[0:2], bindingRequestType)
	binary.BigEndian.PutUint16(raw[2:4], 0)
	binary.BigEndian.PutUint32(raw[4:8], magicCookie)
	copy(raw[8:HeaderSize], transactionID[:])
	return &Message{Raw: raw, TransactionID: transactionID}, nil
}

func Decode(data []byte) (*Message, error) {
	if len(data) < HeaderSize {
		return nil, E.New("STUN message too short: ", len(data))
	}
	if binary.BigEndian.Uint32(data[4:8]) != magicCookie {
		return nil, E.New("invalid STUN magic cookie")
	}
	attrLen := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < HeaderSize+attrLen {
		return nil, E.New("truncated STUN message")
	}
	raw := make([]byte, HeaderSize+attrLen)
	copy(raw, data[:HeaderSize+attrLen])
	var transactionID TransactionID
	copy(transactionID[:], raw[8:HeaderSize])
	return &Message{Raw: raw, TransactionID: transactionID}, nil
}

func (m *Message) XORMappedAddress() (netip.AddrPort, error) {
	attrLen := int(binary.BigEndian.Uint16(m.Raw[2:4]))
	body := m.Raw[HeaderSize : HeaderSize+attrLen]
	for len(body) >= 4 {
		attrType := binary.BigEndian.Uint16(body[0:2])
		valueLen := int(binary.BigEndian.Uint16(body[2:4]))
		paddedLen := (valueLen + 3) &^ 3
		if 4+paddedLen > len(body) {
			return netip.AddrPort{}, E.New("truncated STUN attribute")
		}
		value := body[4 : 4+valueLen]
		body = body[4+paddedLen:]
		if attrType != attrXORMappedAddr {
			continue
		}
		if len(value) < 4 {
			return netip.AddrPort{}, E.New("XOR-MAPPED-ADDRESS too short: ", len(value))
		}
		family := value[1]
		port := binary.BigEndian.Uint16(value[2:4]) ^ uint16(magicCookie>>16)
		var ipLen int
		switch family {
		case xorMappedFamilyIPv4:
			ipLen = 4
		case xorMappedFamilyIPv6:
			ipLen = 16
		default:
			return netip.AddrPort{}, E.New("unknown XOR-MAPPED-ADDRESS family: ", family)
		}
		if len(value) != 4+ipLen {
			return netip.AddrPort{}, E.New("XOR-MAPPED-ADDRESS length mismatch: ", len(value))
		}
		var key [4 + TransactionIDSize]byte
		binary.BigEndian.PutUint32(key[0:4], magicCookie)
		copy(key[4:], m.TransactionID[:])
		ip := make([]byte, ipLen)
		for i := 0; i < ipLen; i++ {
			ip[i] = value[4+i] ^ key[i]
		}
		address, ok := netip.AddrFromSlice(ip)
		if !ok {
			return netip.AddrPort{}, E.New("invalid IP in XOR-MAPPED-ADDRESS")
		}
		return netip.AddrPortFrom(address, port), nil
	}
	return netip.AddrPort{}, E.New("XOR-MAPPED-ADDRESS not found")
}
