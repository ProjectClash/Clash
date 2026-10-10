package helper

import (
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

func Uint8to16(in []uint8) ([]uint16, error) {
	s := cryptobyte.String(in)
	var out []uint16
	for !s.Empty() {
		var v uint16
		if s.ReadUint16(&v) {
			out = append(out, v)
		} else {
			return nil, errors.New("ReadUint16 failed")
		}
	}
	return out, nil
}
