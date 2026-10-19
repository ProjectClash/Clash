package mtproto

import (
	"encoding/hex"
	"errors"
	"strings"
)

const secretLen = 16

type Secret struct {
	key [secretLen]byte
	paddedOnly bool
}

var (
	errSecretRequired = errors.New("mtproto secret is required")
	errSecretFakeTLS  = errors.New("mtproto secret: the fake-TLS (ee) form is not supported, use 32 hex characters, optionally prefixed with dd")
	errSecretFormat   = errors.New("mtproto secret must be 32 hex characters, optionally prefixed with dd")
)

func ParseSecret(s string) (Secret, error) {
	s = strings.TrimSpace(s)
	var secret Secret
	switch {
	case s == "":
		return secret, errSecretRequired
	case len(s) == 2*secretLen:
	case len(s) == 2+2*secretLen && strings.EqualFold(s[:2], "dd"):
		secret.paddedOnly = true
		s = s[2:]
	case len(s) > 2*secretLen && strings.EqualFold(s[:2], "ee"):
		return secret, errSecretFakeTLS
	default:
		return secret, errSecretFormat
	}
	if _, err := hex.Decode(secret.key[:], []byte(s)); err != nil {
		return Secret{}, errSecretFormat
	}
	return secret, nil
}
