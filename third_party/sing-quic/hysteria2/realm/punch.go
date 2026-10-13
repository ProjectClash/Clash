package realm

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"

	E "github.com/metacubex/sing/common/exceptions"
)

type PunchMetadata struct {
	Nonce          [16]byte
	ObfuscationKey [32]byte
}

func GeneratePunchMetadata() (PunchMetadata, error) {
	var metadata PunchMetadata
	_, err := rand.Read(metadata.Nonce[:])
	if err != nil {
		return metadata, E.Cause(err, "generate nonce")
	}
	_, err = rand.Read(metadata.ObfuscationKey[:])
	if err != nil {
		return metadata, E.Cause(err, "generate obfuscation key")
	}
	return metadata, nil
}

const (
	PunchHello byte = 0x01
	PunchAck   byte = 0x02
)

const (
	saltLength   = 8
	magicLength  = 8
	nonceLength  = 16
	minBodySize  = magicLength + 1 + nonceLength
	maxPadding   = 1024
	minPacketLen = saltLength + minBodySize
)

var punchMagic = [magicLength]byte{'H', 'Y', 'R', 'L', 'M', 'v', '1', 0}

func xorObfuscate(obfuscationKey [32]byte, salt []byte, body []byte) {
	var keyMaterial [40]byte
	copy(keyMaterial[:32], obfuscationKey[:])
	copy(keyMaterial[32:], salt)
	key := sha256.Sum256(keyMaterial[:])
	for i := range body {
		body[i] ^= key[i%sha256.Size]
	}
}

func EncodePunchPacket(packetType byte, metadata PunchMetadata) ([]byte, error) {
	var randomBuffer [saltLength + 2 + maxPadding]byte
	_, err := rand.Read(randomBuffer[:])
	if err != nil {
		return nil, E.Cause(err, "generate punch random bytes")
	}
	paddingLength := (int(randomBuffer[saltLength])<<8 | int(randomBuffer[saltLength+1])) % (maxPadding + 1)
	packet := make([]byte, saltLength+minBodySize+paddingLength)
	copy(packet[:saltLength], randomBuffer[:saltLength])
	body := packet[saltLength:]
	copy(body[:magicLength], punchMagic[:])
	body[magicLength] = packetType
	copy(body[magicLength+1:magicLength+1+nonceLength], metadata.Nonce[:])
	if paddingLength > 0 {
		copy(body[minBodySize:], randomBuffer[saltLength+2:saltLength+2+paddingLength])
	}
	xorObfuscate(metadata.ObfuscationKey, packet[:saltLength], body)
	return packet, nil
}

func DecodePunchPacket(data []byte, metadata PunchMetadata) (byte, error) {
	if len(data) < minPacketLen {
		return 0, E.New("packet too short")
	}
	if len(data) > saltLength+minBodySize+maxPadding {
		return 0, E.New("packet too long")
	}
	body := make([]byte, len(data)-saltLength)
	copy(body, data[saltLength:])
	xorObfuscate(metadata.ObfuscationKey, data[:saltLength], body)
	if !bytes.Equal(body[:magicLength], punchMagic[:]) {
		return 0, E.New("magic mismatch")
	}
	packetType := body[magicLength]
	if packetType != PunchHello && packetType != PunchAck {
		return 0, E.New("unknown punch type: ", packetType)
	}
	var nonce [nonceLength]byte
	copy(nonce[:], body[magicLength+1:magicLength+1+nonceLength])
	if nonce != metadata.Nonce {
		return 0, E.New("nonce mismatch")
	}
	return packetType, nil
}
