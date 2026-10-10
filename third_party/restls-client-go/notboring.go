// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package tls

import (
	"crypto/cipher"
	"errors"
)

func needFIPS() bool { return false }

func supportedSignatureAlgorithms() []SignatureScheme {
	return defaultSupportedSignatureAlgorithms
}

func fipsMinVersion(c *Config) uint16          { panic("fipsMinVersion") }
func fipsMaxVersion(c *Config) uint16          { panic("fipsMaxVersion") }
func fipsCurvePreferences(c *Config) []CurveID { panic("fipsCurvePreferences") }
func fipsCipherSuites(c *Config) []uint16      { panic("fipsCipherSuites") }

var fipsSupportedSignatureAlgorithms []SignatureScheme

type Boring struct {
	Enabled bool
}

func (*Boring) NewGCMTLS(_ cipher.Block) (cipher.AEAD, error) {
	return nil, errors.New("boring not implemented")
}

func (*Boring) Unreachable() {
}

var boring Boring
