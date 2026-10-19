package mtproto


import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const initLen = 64

var (
	tagAbridged     = [4]byte{0xef, 0xef, 0xef, 0xef}
	tagIntermediate = [4]byte{0xee, 0xee, 0xee, 0xee}
	tagPadded       = [4]byte{0xdd, 0xdd, 0xdd, 0xdd}
)

var (
	errUnknownProtocol = errors.New("mtproto: unknown protocol tag, the secret does not match")
	errPaddedOnly      = errors.New("mtproto: a dd secret takes padded intermediate only")
)

type clientInit struct {
	tag     [4]byte
	dc      int16
	decrypt cipher.Stream
	encrypt cipher.Stream
}

func acceptInit(frame *[initLen]byte, secret Secret) (clientInit, error) {
	decrypt, encrypt, err := initStreams(frame, secret.key[:])
	if err != nil {
		return clientInit{}, err
	}
	var plain [initLen]byte
	decrypt.XORKeyStream(plain[:], frame[:])
	init := clientInit{dc: int16(binary.LittleEndian.Uint16(plain[60:62])), decrypt: decrypt, encrypt: encrypt}
	copy(init.tag[:], plain[56:60])
	switch init.tag {
	case tagPadded:
	case tagAbridged, tagIntermediate:
		if secret.paddedOnly {
			return clientInit{}, errPaddedOnly
		}
	default:
		return clientInit{}, errUnknownProtocol
	}
	return init, nil
}

func newDCInit(random io.Reader, tag [4]byte, dc int16) (frame [initLen]byte, encrypt, decrypt cipher.Stream, err error) {
	for {
		if _, err = io.ReadFull(random, frame[:]); err != nil {
			return
		}
		if !reservedInit(&frame) {
			break
		}
	}
	copy(frame[56:60], tag[:])
	binary.LittleEndian.PutUint16(frame[60:62], uint16(dc))
	if encrypt, decrypt, err = initStreams(&frame, nil); err != nil {
		return
	}
	var sealed [initLen]byte
	encrypt.XORKeyStream(sealed[:], frame[:])
	copy(frame[56:], sealed[56:])
	return
}

func reservedInit(frame *[initLen]byte) bool {
	if frame[0] == 0xef {
		return true
	}
	switch binary.LittleEndian.Uint32(frame[0:4]) {
	case 0x44414548,
		0x54534f50,
		0x20544547,
		0x4954504f,
		0x02010316,
		0xdddddddd,
		0xeeeeeeee:
		return true
	}
	return binary.LittleEndian.Uint32(frame[4:8]) == 0
}

func initStreams(frame *[initLen]byte, secret []byte) (forward, backward cipher.Stream, err error) {
	var reversed [48]byte
	for i := range reversed {
		reversed[i] = frame[55-i]
	}
	if forward, err = ctrStream(frame[8:40], frame[40:56], secret); err != nil {
		return
	}
	backward, err = ctrStream(reversed[:32], reversed[32:], secret)
	return
}

func ctrStream(key, iv, secret []byte) (cipher.Stream, error) {
	if secret != nil {
		h := sha256.New()
		h.Write(key)
		h.Write(secret)
		var sum [sha256.Size]byte
		key = h.Sum(sum[:0])
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}
