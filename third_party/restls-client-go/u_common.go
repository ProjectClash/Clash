// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"log"

	"github.com/metacubex/restls-client-go/internal/helper"
	"golang.org/x/crypto/cryptobyte"
)


const (
	utlsTypeEncryptedExtensions uint8 = 8
	utlsTypeCompressedCertificate uint8 = 25
)

const (
	extensionNextProtoNeg uint16 = 13172

	utlsExtensionPadding             uint16 = 21
	utlsExtensionCompressCertificate uint16 = 27
	utlsExtensionApplicationSettings uint16 = 17513
	utlsFakeExtensionCustom          uint16 = 1234

	fakeExtensionEncryptThenMAC       uint16 = 22
	fakeExtensionTokenBinding         uint16 = 24
	fakeExtensionDelegatedCredentials uint16 = 34
	fakeExtensionPreSharedKey         uint16 = 41
	fakeOldExtensionChannelID         uint16 = 30031
	fakeExtensionChannelID            uint16 = 30032
)

const (
	OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = uint16(0xcc13)
	OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc14)

	DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = uint16(0xc024)
	DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   = uint16(0xc028)
	DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256         = uint16(0x003d)

	FAKE_OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc15)
	FAKE_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256           = uint16(0x009e)

	FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA    = uint16(0x0033)
	FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA    = uint16(0x0039)
	FAKE_TLS_RSA_WITH_RC4_128_MD5            = uint16(0x0004)
	FAKE_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = uint16(0x009f)
	FAKE_TLS_DHE_DSS_WITH_AES_128_CBC_SHA    = uint16(0x0032)
	FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = uint16(0x006b)
	FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = uint16(0x0067)
	FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV   = uint16(0x00ff)

	FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = uint16(0xc008)
)

const (
	CurveSECP256R1 CurveID = 0x0017
	CurveSECP384R1 CurveID = 0x0018
	CurveSECP521R1 CurveID = 0x0019
	CurveX25519    CurveID = 0x001d

	FakeCurveFFDHE2048 CurveID = 0x0100
	FakeCurveFFDHE3072 CurveID = 0x0101
	FakeCurveFFDHE4096 CurveID = 0x0102
	FakeCurveFFDHE6144 CurveID = 0x0103
	FakeCurveFFDHE8192 CurveID = 0x0104
)

const (
	fakeRecordSizeLimit uint16 = 0x001c
)

var (
	FakePKCS1WithSHA224 SignatureScheme = 0x0301
	FakeECDSAWithSHA224 SignatureScheme = 0x0303

	FakeSHA1WithDSA   SignatureScheme = 0x0202
	FakeSHA256WithDSA SignatureScheme = 0x0402

)

var (
	FakeFFDHE2048 = uint16(0x0100)
	FakeFFDHE3072 = uint16(0x0101)
)

type CertCompressionAlgo uint16

const (
	CertCompressionZlib   CertCompressionAlgo = 0x0001
	CertCompressionBrotli CertCompressionAlgo = 0x0002
	CertCompressionZstd   CertCompressionAlgo = 0x0003
)

const (
	PskModePlain uint8 = pskModePlain
	PskModeDHE   uint8 = pskModeDHE
)

type ClientHelloID struct {
	Client string

	Version string

	Seed *PRNGSeed

	Weights *Weights
}

func (p *ClientHelloID) Str() string {
	return fmt.Sprintf("%s-%s", p.Client, p.Version)
}

func (p *ClientHelloID) IsSet() bool {
	return (p.Client == "") && (p.Version == "")
}

const (
	helloGolang           = "Golang"
	helloRandomized       = "Randomized"
	helloRandomizedALPN   = "Randomized-ALPN"
	helloRandomizedNoALPN = "Randomized-NoALPN"
	helloCustom           = "Custom"
	helloFirefox          = "Firefox"
	helloChrome           = "Chrome"
	helloIOS              = "iOS"
	helloAndroid          = "Android"
	helloEdge             = "Edge"
	helloSafari           = "Safari"
	hello360              = "360Browser"
	helloQQ               = "QQBrowser"

	helloAutoVers = "0"
)

type ClientHelloSpec struct {
	CipherSuites       []uint16
	CompressionMethods []uint8
	Extensions         []TLSExtension

	TLSVersMin uint16
	TLSVersMax uint16

	GetSessionID func(ticket []byte) [32]byte

}

func (chs *ClientHelloSpec) ReadCipherSuites(b []byte) error {
	cipherSuites := []uint16{}
	s := cryptobyte.String(b)
	for !s.Empty() {
		var suite uint16
		if !s.ReadUint16(&suite) {
			return errors.New("unable to read ciphersuite")
		}
		cipherSuites = append(cipherSuites, unGREASEUint16(suite))
	}
	chs.CipherSuites = cipherSuites
	return nil
}

func (chs *ClientHelloSpec) ReadCompressionMethods(compressionMethods []byte) error {
	chs.CompressionMethods = compressionMethods
	return nil
}

func (chs *ClientHelloSpec) ReadTLSExtensions(b []byte, allowBluntMimicry bool) error {
	extensions := cryptobyte.String(b)
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) {
			return fmt.Errorf("unable to read extension ID")
		}
		if !extensions.ReadUint16LengthPrefixed(&extData) {
			return fmt.Errorf("unable to read data for extension %x", extension)
		}

		ext := ExtensionFromID(extension)
		extWriter, ok := ext.(TLSExtensionWriter)
		if ext != nil && ok {
			if extension == extensionSupportedVersions {
				chs.TLSVersMin = 0
				chs.TLSVersMax = 0
			}
			if _, err := extWriter.Write(extData); err != nil {
				return err
			}

			chs.Extensions = append(chs.Extensions, extWriter)
		} else {
			if allowBluntMimicry {
				chs.Extensions = append(chs.Extensions, &GenericExtension{extension, extData})
			} else {
				return fmt.Errorf("unsupported extension %d", extension)
			}
		}
	}
	return nil
}

func (chs *ClientHelloSpec) AlwaysAddPadding() {
	alreadyHasPadding := false
	for _, ext := range chs.Extensions {
		if _, ok := ext.(*UtlsPaddingExtension); ok {
			alreadyHasPadding = true
			break
		}
		if _, ok := ext.(*FakePreSharedKeyExtension); ok {
			alreadyHasPadding = true
			break
		}
	}
	if !alreadyHasPadding {
		chs.Extensions = append(chs.Extensions, &UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle})
	}
}

func (chs *ClientHelloSpec) ImportTLSClientHello(data map[string][]byte) error {
	var tlsExtensionTypes []uint16
	var err error

	if data["cipher_suites"] == nil {
		return errors.New("cipher_suites is required")
	}
	chs.CipherSuites, err = helper.Uint8to16(data["cipher_suites"])
	if err != nil {
		return err
	}

	if data["compression_methods"] == nil {
		return errors.New("compression_methods is required")
	}
	chs.CompressionMethods = data["compression_methods"]

	if data["extensions"] == nil {
		return errors.New("extensions is required")
	}
	tlsExtensionTypes, err = helper.Uint8to16(data["extensions"])
	if err != nil {
		return err
	}

	for _, extType := range tlsExtensionTypes {
		extension := ExtensionFromID(extType)
		extWriter, ok := extension.(TLSExtensionWriter)
		if !ok {
			return fmt.Errorf("unsupported extension %d", extType)
		}
		if extension == nil || !ok {
			log.Printf("[Warning] Unsupported extension %d added as a &GenericExtension without Data", extType)
			chs.Extensions = append(chs.Extensions, &GenericExtension{extType, []byte{}})
		} else {
			switch extType {
			case extensionSupportedPoints:
				if data["pt_fmts"] == nil {
					return errors.New("pt_fmts is required")
				}
				_, err = extWriter.Write(data["pt_fmts"])
				if err != nil {
					return err
				}
			case extensionSignatureAlgorithms:
				if data["sig_algs"] == nil {
					return errors.New("sig_algs is required")
				}
				_, err = extWriter.Write(data["sig_algs"])
				if err != nil {
					return err
				}
			case extensionSupportedVersions:
				chs.TLSVersMin = 0
				chs.TLSVersMax = 0

				if data["supported_versions"] == nil {
					return errors.New("supported_versions is required")
				}

				fixedData := make([]byte, len(data["supported_versions"])+1)
				fixedData[0] = uint8(len(data["supported_versions"]) & 0xff)
				copy(fixedData[1:], data["supported_versions"])
				_, err = extWriter.Write(fixedData)
				if err != nil {
					return err
				}
			case extensionSupportedCurves:
				if data["curves"] == nil {
					return errors.New("curves is required")
				}

				_, err = extWriter.Write(data["curves"])
				if err != nil {
					return err
				}
			case extensionALPN:
				if data["alpn"] == nil {
					return errors.New("alpn is required")
				}

				_, err = extWriter.Write(data["alpn"])
				if err != nil {
					return err
				}
			case extensionKeyShare:
				if data["key_share"] == nil {
					return errors.New("key_share is required")
				}

				fixedData := make([]byte, 0)
				for i := 0; i < len(data["key_share"]); i += 4 {
					fixedData = append(fixedData, data["key_share"][i:i+4]...)
					for j := 0; j < int(data["key_share"][i+3]); j++ {
						fixedData = append(fixedData, 0)
					}
				}
				fixedData = append([]byte{uint8(len(fixedData) >> 8), uint8(len(fixedData) & 0xff)}, fixedData...)

				_, err = extWriter.Write(fixedData)
				if err != nil {
					return err
				}
			case extensionPSKModes:
				if data["psk_key_exchange_modes"] == nil {
					return errors.New("psk_key_exchange_modes is required")
				}

				fixedData := make([]byte, len(data["psk_key_exchange_modes"])+1)
				fixedData[0] = uint8(len(data["psk_key_exchange_modes"]) & 0xff)
				copy(fixedData[1:], data["psk_key_exchange_modes"])
				_, err = extWriter.Write(fixedData)
				if err != nil {
					return err
				}
			case utlsExtensionCompressCertificate:
				if data["cert_compression_algs"] == nil {
					return errors.New("cert_compression_algs is required")
				}

				fixedData := make([]byte, len(data["cert_compression_algs"])+1)
				fixedData[0] = uint8(len(data["cert_compression_algs"]) & 0xff)
				copy(fixedData[1:], data["cert_compression_algs"])
				_, err = extWriter.Write(fixedData)
				if err != nil {
					return err
				}
			case fakeRecordSizeLimit:
				if data["record_size_limit"] == nil {
					return errors.New("record_size_limit is required")
				}

				_, err = extWriter.Write(data["record_size_limit"])
				if err != nil {
					return err
				}
			case utlsExtensionApplicationSettings:
				extWriter.(*ApplicationSettingsExtension).SupportedProtocols = []string{"h2"}
			case extensionPreSharedKey:
				log.Printf("[Warning] PSK extension added without data")
			default:
				if !isGREASEUint16(extType) {
					log.Printf("[Warning] extension %d added without data", extType)
				}
			}
			chs.Extensions = append(chs.Extensions, extWriter)
		}
	}
	return nil
}

func (chs *ClientHelloSpec) ImportTLSClientHelloFromJSON(jsonB []byte) error {
	var data map[string][]byte
	err := json.Unmarshal(jsonB, &data)
	if err != nil {
		return err
	}
	return chs.ImportTLSClientHello(data)
}

func (chs *ClientHelloSpec) FromRaw(raw []byte, allowBluntMimicry ...bool) error {
	if chs == nil {
		return errors.New("cannot unmarshal into nil ClientHelloSpec")
	}

	var bluntMimicry = false
	if len(allowBluntMimicry) == 1 {
		bluntMimicry = allowBluntMimicry[0]
	}

	*chs = ClientHelloSpec{}
	s := cryptobyte.String(raw)

	var contentType uint8
	var recordVersion uint16
	if !s.ReadUint8(&contentType) ||
		!s.ReadUint16(&recordVersion) || !s.Skip(2) {
		return errors.New("unable to read record type, version, and length")
	}

	if recordType(contentType) != recordTypeHandshake {
		return errors.New("record is not a handshake")
	}

	var handshakeVersion uint16
	var handshakeType uint8

	if !s.ReadUint8(&handshakeType) || !s.Skip(3) ||
		!s.ReadUint16(&handshakeVersion) || !s.Skip(32) {
		return errors.New("unable to read handshake message type, length, and random")
	}

	if handshakeType != typeClientHello {
		return errors.New("handshake message is not a ClientHello")
	}

	chs.TLSVersMin = recordVersion
	chs.TLSVersMax = handshakeVersion

	var ignoredSessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&ignoredSessionID) {
		return errors.New("unable to read session id")
	}

	var cipherSuitesBytes cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuitesBytes) {
		return errors.New("unable to read ciphersuites")
	}

	if err := chs.ReadCipherSuites(cipherSuitesBytes); err != nil {
		return err
	}

	var compressionMethods cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&compressionMethods) {
		return errors.New("unable to read compression methods")
	}

	if err := chs.ReadCompressionMethods(compressionMethods); err != nil {
		return err
	}

	if s.Empty() {
		return nil
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return errors.New("unable to read extensions data")
	}

	if err := chs.ReadTLSExtensions(extensions, bluntMimicry); err != nil {
		return err
	}

	return nil
}

func (chs *ClientHelloSpec) UnmarshalJSON(jsonB []byte) error {
	var chsju ClientHelloSpecJSONUnmarshaler
	if err := json.Unmarshal(jsonB, &chsju); err != nil {
		return err
	}

	*chs = chsju.ClientHelloSpec()
	return nil
}

var (
	HelloGolang = ClientHelloID{helloGolang, helloAutoVers, nil, nil}

	HelloCustom = ClientHelloID{helloCustom, helloAutoVers, nil, nil}

	HelloRandomized       = ClientHelloID{helloRandomized, helloAutoVers, nil, nil}
	HelloRandomizedALPN   = ClientHelloID{helloRandomizedALPN, helloAutoVers, nil, nil}
	HelloRandomizedNoALPN = ClientHelloID{helloRandomizedNoALPN, helloAutoVers, nil, nil}

	HelloFirefox_Auto = HelloFirefox_105
	HelloFirefox_55   = ClientHelloID{helloFirefox, "55", nil, nil}
	HelloFirefox_56   = ClientHelloID{helloFirefox, "56", nil, nil}
	HelloFirefox_63   = ClientHelloID{helloFirefox, "63", nil, nil}
	HelloFirefox_65   = ClientHelloID{helloFirefox, "65", nil, nil}
	HelloFirefox_99   = ClientHelloID{helloFirefox, "99", nil, nil}
	HelloFirefox_102  = ClientHelloID{helloFirefox, "102", nil, nil}
	HelloFirefox_105  = ClientHelloID{helloFirefox, "105", nil, nil}

	HelloChrome_Auto        = HelloChrome_106_Shuffle
	HelloChrome_58          = ClientHelloID{helloChrome, "58", nil, nil}
	HelloChrome_62          = ClientHelloID{helloChrome, "62", nil, nil}
	HelloChrome_70          = ClientHelloID{helloChrome, "70", nil, nil}
	HelloChrome_72          = ClientHelloID{helloChrome, "72", nil, nil}
	HelloChrome_83          = ClientHelloID{helloChrome, "83", nil, nil}
	HelloChrome_87          = ClientHelloID{helloChrome, "87", nil, nil}
	HelloChrome_96          = ClientHelloID{helloChrome, "96", nil, nil}
	HelloChrome_100         = ClientHelloID{helloChrome, "100", nil, nil}
	HelloChrome_102         = ClientHelloID{helloChrome, "102", nil, nil}
	HelloChrome_106_Shuffle = ClientHelloID{helloChrome, "106", nil, nil}

	HelloChrome_100_PSK      = ClientHelloID{helloChrome, "100_PSK", nil, nil}
	HelloChrome_112_PSK_Shuf = ClientHelloID{helloChrome, "112_PSK", nil, nil}

	HelloIOS_Auto = HelloIOS_14
	HelloIOS_11_1 = ClientHelloID{helloIOS, "111", nil, nil}
	HelloIOS_12_1 = ClientHelloID{helloIOS, "12.1", nil, nil}
	HelloIOS_13   = ClientHelloID{helloIOS, "13", nil, nil}
	HelloIOS_14   = ClientHelloID{helloIOS, "14", nil, nil}

	HelloAndroid_11_OkHttp = ClientHelloID{helloAndroid, "11", nil, nil}

	HelloEdge_Auto = HelloEdge_85
	HelloEdge_85   = ClientHelloID{helloEdge, "85", nil, nil}
	HelloEdge_106  = ClientHelloID{helloEdge, "106", nil, nil}

	HelloSafari_Auto = HelloSafari_16_0
	HelloSafari_16_0 = ClientHelloID{helloSafari, "16.0", nil, nil}

	Hello360_Auto = Hello360_7_5
	Hello360_7_5  = ClientHelloID{hello360, "7.5", nil, nil}
	Hello360_11_0 = ClientHelloID{hello360, "11.0", nil, nil}

	HelloQQ_Auto = HelloQQ_11_1
	HelloQQ_11_1 = ClientHelloID{helloQQ, "11.1", nil, nil}
)

type Weights struct {
	Extensions_Append_ALPN                             float64
	TLSVersMax_Set_VersionTLS13                        float64
	CipherSuites_Remove_RandomCiphers                  float64
	SigAndHashAlgos_Append_ECDSAWithSHA1               float64
	SigAndHashAlgos_Append_ECDSAWithP521AndSHA512      float64
	SigAndHashAlgos_Append_PSSWithSHA256               float64
	SigAndHashAlgos_Append_PSSWithSHA384_PSSWithSHA512 float64
	CurveIDs_Append_X25519                             float64
	CurveIDs_Append_CurveP521                          float64
	Extensions_Append_Padding                          float64
	Extensions_Append_Status                           float64
	Extensions_Append_SCT                              float64
	Extensions_Append_Reneg                            float64
	Extensions_Append_EMS                              float64
	FirstKeyShare_Set_CurveP256                        float64
	Extensions_Append_ALPS                             float64
}

var DefaultWeights = Weights{
	Extensions_Append_ALPN:                             0.7,
	TLSVersMax_Set_VersionTLS13:                        0.4,
	CipherSuites_Remove_RandomCiphers:                  0.4,
	SigAndHashAlgos_Append_ECDSAWithSHA1:               0.63,
	SigAndHashAlgos_Append_ECDSAWithP521AndSHA512:      0.59,
	SigAndHashAlgos_Append_PSSWithSHA256:               0.51,
	SigAndHashAlgos_Append_PSSWithSHA384_PSSWithSHA512: 0.9,
	CurveIDs_Append_X25519:                             0.71,
	CurveIDs_Append_CurveP521:                          0.46,
	Extensions_Append_Padding:                          0.62,
	Extensions_Append_Status:                           0.74,
	Extensions_Append_SCT:                              0.46,
	Extensions_Append_Reneg:                            0.75,
	Extensions_Append_EMS:                              0.77,
	FirstKeyShare_Set_CurveP256:                        0.25,
	Extensions_Append_ALPS:                             0.33,
}

const GREASE_PLACEHOLDER = 0x0a0a

func isGREASEUint16(v uint16) bool {
	return ((v >> 8) == v&0xff) && v&0xf == 0xa
}

func unGREASEUint16(v uint16) uint16 {
	if isGREASEUint16(v) {
		return GREASE_PLACEHOLDER
	} else {
		return v
	}
}

func utlsMacSHA384(key []byte) hash.Hash {
	return hmac.New(sha512.New384, key)
}

var utlsSupportedCipherSuites []*cipherSuite

func init() {
	utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
		{OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheRSAKA,
			suiteECDHE | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
		{OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheECDSAKA,
			suiteECDHE | suiteECSign | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
	}...)
}

func EnableWeakCiphers() {
	utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
		{DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256, 32, 32, 16, rsaKA,
			suiteTLS12, cipherAES, macSHA256, nil},

		{DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheECDSAKA,
			suiteECDHE | suiteECSign | suiteTLS12 | suiteSHA384, cipherAES, utlsMacSHA384, nil},
		{DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheRSAKA,
			suiteECDHE | suiteTLS12 | suiteSHA384, cipherAES, utlsMacSHA384, nil},
	}...)
}
