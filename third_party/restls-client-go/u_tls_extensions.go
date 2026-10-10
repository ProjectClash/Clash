// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/gaukas/godicttls"
	"golang.org/x/crypto/cryptobyte"
)

func ExtensionFromID(id uint16) TLSExtension {
	switch id {
	case extensionServerName:
		return &SNIExtension{}
	case extensionStatusRequest:
		return &StatusRequestExtension{}
	case extensionSupportedCurves:
		return &SupportedCurvesExtension{}
	case extensionSupportedPoints:
		return &SupportedPointsExtension{}
	case extensionSignatureAlgorithms:
		return &SignatureAlgorithmsExtension{}
	case extensionALPN:
		return &ALPNExtension{}
	case extensionStatusRequestV2:
		return &StatusRequestV2Extension{}
	case extensionSCT:
		return &SCTExtension{}
	case utlsExtensionPadding:
		return &UtlsPaddingExtension{}
	case extensionExtendedMasterSecret:
		return &ExtendedMasterSecretExtension{}
	case fakeExtensionTokenBinding:
		return &FakeTokenBindingExtension{}
	case utlsExtensionCompressCertificate:
		return &UtlsCompressCertExtension{}
	case fakeExtensionDelegatedCredentials:
		return &FakeDelegatedCredentialsExtension{}
	case extensionSessionTicket:
		return &SessionTicketExtension{}
	case extensionPreSharedKey:
		return &FakePreSharedKeyExtension{}
	case extensionSupportedVersions:
		return &SupportedVersionsExtension{}
	case extensionPSKModes:
		return &PSKKeyExchangeModesExtension{}
	case extensionSignatureAlgorithmsCert:
		return &SignatureAlgorithmsCertExtension{}
	case extensionKeyShare:
		return &KeyShareExtension{}
	case extensionQUICTransportParameters:
		return &QUICTransportParametersExtension{}
	case extensionNextProtoNeg:
		return &NPNExtension{}
	case utlsExtensionApplicationSettings:
		return &ApplicationSettingsExtension{}
	case fakeOldExtensionChannelID:
		return &FakeChannelIDExtension{true}
	case fakeExtensionChannelID:
		return &FakeChannelIDExtension{}
	case fakeRecordSizeLimit:
		return &FakeRecordSizeLimitExtension{}
	case extensionRenegotiationInfo:
		return &RenegotiationInfoExtension{}
	default:
		if isGREASEUint16(id) {
			return &UtlsGREASEExtension{}
		}
		return nil
	}
}

type TLSExtension interface {
	writeToUConn(*UConn) error

	Len() int

	Read(p []byte) (n int, err error)
}

type TLSExtensionWriter interface {
	TLSExtension

	Write(b []byte) (n int, err error)
}

type TLSExtensionJSON interface {
	TLSExtension

	UnmarshalJSON([]byte) error
}

type SNIExtension struct {
	ServerName string
}

func (e *SNIExtension) Len() int {
	hostName := hostnameInSNI(e.ServerName)
	if len(hostName) == 0 {
		return 0
	}
	return 4 + 2 + 1 + 2 + len(hostName)
}

func (e *SNIExtension) Read(b []byte) (int, error) {
	hostName := hostnameInSNI(e.ServerName)
	if len(hostName) == 0 {
		return 0, io.EOF
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(extensionServerName >> 8)
	b[1] = byte(extensionServerName)
	b[2] = byte((len(hostName) + 5) >> 8)
	b[3] = byte(len(hostName) + 5)
	b[4] = byte((len(hostName) + 3) >> 8)
	b[5] = byte(len(hostName) + 3)
	b[7] = byte(len(hostName) >> 8)
	b[8] = byte(len(hostName))
	copy(b[9:], []byte(hostName))
	return e.Len(), io.EOF
}

func (e *SNIExtension) UnmarshalJSON(_ []byte) error {
	return nil
}

func (e *SNIExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	var nameList cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
		return fullLen, errors.New("unable to read server name extension data")
	}
	var serverName string
	for !nameList.Empty() {
		var nameType uint8
		var serverNameBytes cryptobyte.String
		if !nameList.ReadUint8(&nameType) ||
			!nameList.ReadUint16LengthPrefixed(&serverNameBytes) ||
			serverNameBytes.Empty() {
			return fullLen, errors.New("unable to read server name extension data")
		}
		if nameType != 0 {
			continue
		}
		if len(serverName) != 0 {
			return fullLen, errors.New("multiple names of the same name_type in server name extension are prohibited")
		}
		serverName = string(serverNameBytes)
		if strings.HasSuffix(serverName, ".") {
			return fullLen, errors.New("SNI value may not include a trailing dot")
		}
	}

	return fullLen, nil
}

func (e *SNIExtension) writeToUConn(uc *UConn) error {
	uc.config.ServerName = e.ServerName
	hostName := hostnameInSNI(e.ServerName)
	uc.HandshakeState.Hello.ServerName = hostName

	return nil
}

type StatusRequestExtension struct {
}

func (e *StatusRequestExtension) Len() int {
	return 9
}

func (e *StatusRequestExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(extensionStatusRequest >> 8)
	b[1] = byte(extensionStatusRequest)
	b[2] = 0
	b[3] = 5
	b[4] = 1
	return e.Len(), io.EOF
}

func (e *StatusRequestExtension) UnmarshalJSON(_ []byte) error {
	return nil
}

func (e *StatusRequestExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	var statusType uint8
	var ignored cryptobyte.String
	if !extData.ReadUint8(&statusType) ||
		!extData.ReadUint16LengthPrefixed(&ignored) ||
		!extData.ReadUint16LengthPrefixed(&ignored) {
		return fullLen, errors.New("unable to read status request extension data")
	}

	if statusType != statusTypeOCSP {
		return fullLen, errors.New("status request extension statusType is not statusTypeOCSP(1)")
	}

	return fullLen, nil
}

func (e *StatusRequestExtension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.OcspStapling = true
	return nil
}

type SupportedCurvesExtension struct {
	Curves []CurveID
}

func (e *SupportedCurvesExtension) Len() int {
	return 6 + 2*len(e.Curves)
}

func (e *SupportedCurvesExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(extensionSupportedCurves >> 8)
	b[1] = byte(extensionSupportedCurves)
	b[2] = byte((2 + 2*len(e.Curves)) >> 8)
	b[3] = byte(2 + 2*len(e.Curves))
	b[4] = byte((2 * len(e.Curves)) >> 8)
	b[5] = byte(2 * len(e.Curves))
	for i, curve := range e.Curves {
		b[6+2*i] = byte(curve >> 8)
		b[7+2*i] = byte(curve)
	}
	return e.Len(), io.EOF
}

func (e *SupportedCurvesExtension) UnmarshalJSON(data []byte) error {
	var namedGroups struct {
		NamedGroupList []string `json:"named_group_list"`
	}
	if err := json.Unmarshal(data, &namedGroups); err != nil {
		return err
	}

	for _, namedGroup := range namedGroups.NamedGroupList {
		if namedGroup == "GREASE" {
			e.Curves = append(e.Curves, GREASE_PLACEHOLDER)
			continue
		}

		if group, ok := godicttls.DictSupportedGroupsNameIndexed[namedGroup]; ok {
			e.Curves = append(e.Curves, CurveID(group))
		} else {
			return fmt.Errorf("unknown named group: %s", namedGroup)
		}
	}
	return nil
}

func (e *SupportedCurvesExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	var curvesBytes cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&curvesBytes) || curvesBytes.Empty() {
		return 0, errors.New("unable to read supported curves extension data")
	}
	curves := []CurveID{}
	for !curvesBytes.Empty() {
		var curve uint16
		if !curvesBytes.ReadUint16(&curve) {
			return 0, errors.New("unable to read supported curves extension data")
		}
		curves = append(curves, CurveID(unGREASEUint16(curve)))
	}
	e.Curves = curves
	return fullLen, nil
}

func (e *SupportedCurvesExtension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.SupportedCurves = e.Curves
	return nil
}

type SupportedPointsExtension struct {
	SupportedPoints []uint8
}

func (e *SupportedPointsExtension) Len() int {
	return 5 + len(e.SupportedPoints)
}

func (e *SupportedPointsExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(extensionSupportedPoints >> 8)
	b[1] = byte(extensionSupportedPoints)
	b[2] = byte((1 + len(e.SupportedPoints)) >> 8)
	b[3] = byte(1 + len(e.SupportedPoints))
	b[4] = byte(len(e.SupportedPoints))
	for i, pointFormat := range e.SupportedPoints {
		b[5+i] = pointFormat
	}
	return e.Len(), io.EOF
}

func (e *SupportedPointsExtension) UnmarshalJSON(data []byte) error {
	var pointFormatList struct {
		ECPointFormatList []string `json:"ec_point_format_list"`
	}
	if err := json.Unmarshal(data, &pointFormatList); err != nil {
		return err
	}

	for _, pointFormat := range pointFormatList.ECPointFormatList {
		if format, ok := godicttls.DictECPointFormatNameIndexed[pointFormat]; ok {
			e.SupportedPoints = append(e.SupportedPoints, format)
		} else {
			return fmt.Errorf("unknown point format: %s", pointFormat)
		}
	}
	return nil
}

func (e *SupportedPointsExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	supportedPoints := []uint8{}
	if !readUint8LengthPrefixed(&extData, &supportedPoints) ||
		len(supportedPoints) == 0 {
		return 0, errors.New("unable to read supported points extension data")
	}
	e.SupportedPoints = supportedPoints
	return fullLen, nil
}

func (e *SupportedPointsExtension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.SupportedPoints = e.SupportedPoints
	return nil
}

type SignatureAlgorithmsExtension struct {
	SupportedSignatureAlgorithms []SignatureScheme
}

func (e *SignatureAlgorithmsExtension) Len() int {
	return 6 + 2*len(e.SupportedSignatureAlgorithms)
}

func (e *SignatureAlgorithmsExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(extensionSignatureAlgorithms >> 8)
	b[1] = byte(extensionSignatureAlgorithms)
	b[2] = byte((2 + 2*len(e.SupportedSignatureAlgorithms)) >> 8)
	b[3] = byte(2 + 2*len(e.SupportedSignatureAlgorithms))
	b[4] = byte((2 * len(e.SupportedSignatureAlgorithms)) >> 8)
	b[5] = byte(2 * len(e.SupportedSignatureAlgorithms))
	for i, sigScheme := range e.SupportedSignatureAlgorithms {
		b[6+2*i] = byte(sigScheme >> 8)
		b[7+2*i] = byte(sigScheme)
	}
	return e.Len(), io.EOF
}

func (e *SignatureAlgorithmsExtension) UnmarshalJSON(data []byte) error {
	var signatureAlgorithms struct {
		Algorithms []string `json:"supported_signature_algorithms"`
	}
	if err := json.Unmarshal(data, &signatureAlgorithms); err != nil {
		return err
	}

	for _, sigScheme := range signatureAlgorithms.Algorithms {
		if sigScheme == "GREASE" {
			e.SupportedSignatureAlgorithms = append(e.SupportedSignatureAlgorithms, GREASE_PLACEHOLDER)
			continue
		}

		if scheme, ok := godicttls.DictSignatureSchemeNameIndexed[sigScheme]; ok {
			e.SupportedSignatureAlgorithms = append(e.SupportedSignatureAlgorithms, SignatureScheme(scheme))
		} else {
			return fmt.Errorf("unknown signature scheme: %s", sigScheme)
		}
	}
	return nil
}

func (e *SignatureAlgorithmsExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	var sigAndAlgs cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
		return 0, errors.New("unable to read signature algorithms extension data")
	}
	supportedSignatureAlgorithms := []SignatureScheme{}
	for !sigAndAlgs.Empty() {
		var sigAndAlg uint16
		if !sigAndAlgs.ReadUint16(&sigAndAlg) {
			return 0, errors.New("unable to read signature algorithms extension data")
		}
		supportedSignatureAlgorithms = append(
			supportedSignatureAlgorithms, SignatureScheme(sigAndAlg))
	}
	e.SupportedSignatureAlgorithms = supportedSignatureAlgorithms
	return fullLen, nil
}

func (e *SignatureAlgorithmsExtension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.SupportedSignatureAlgorithms = e.SupportedSignatureAlgorithms
	return nil
}

type StatusRequestV2Extension struct {
}

func (e *StatusRequestV2Extension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.OcspStapling = true
	return nil
}

func (e *StatusRequestV2Extension) Len() int {
	return 13
}

func (e *StatusRequestV2Extension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(extensionStatusRequestV2 >> 8)
	b[1] = byte(extensionStatusRequestV2)
	b[2] = 0
	b[3] = 9
	b[4] = 0
	b[5] = 7
	b[6] = 2
	b[7] = 0
	b[8] = 4
	return e.Len(), io.EOF
}

func (e *StatusRequestV2Extension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	var statusType uint8
	var ignored cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&ignored) ||
		!extData.ReadUint8(&statusType) ||
		!extData.ReadUint16LengthPrefixed(&ignored) ||
		!extData.ReadUint16LengthPrefixed(&ignored) ||
		!extData.ReadUint16LengthPrefixed(&ignored) {
		return fullLen, errors.New("unable to read status request v2 extension data")
	}

	if statusType != statusV2TypeOCSP {
		return fullLen, errors.New("status request v2 extension statusType is not statusV2TypeOCSP(2)")
	}

	return fullLen, nil
}

func (e *StatusRequestV2Extension) UnmarshalJSON(_ []byte) error {
	return nil
}

type SignatureAlgorithmsCertExtension struct {
	SupportedSignatureAlgorithms []SignatureScheme
}

func (e *SignatureAlgorithmsCertExtension) Len() int {
	return 6 + 2*len(e.SupportedSignatureAlgorithms)
}

func (e *SignatureAlgorithmsCertExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(extensionSignatureAlgorithmsCert >> 8)
	b[1] = byte(extensionSignatureAlgorithmsCert)
	b[2] = byte((2 + 2*len(e.SupportedSignatureAlgorithms)) >> 8)
	b[3] = byte(2 + 2*len(e.SupportedSignatureAlgorithms))
	b[4] = byte((2 * len(e.SupportedSignatureAlgorithms)) >> 8)
	b[5] = byte(2 * len(e.SupportedSignatureAlgorithms))
	for i, sigAndHash := range e.SupportedSignatureAlgorithms {
		b[6+2*i] = byte(sigAndHash >> 8)
		b[7+2*i] = byte(sigAndHash)
	}
	return e.Len(), io.EOF
}

func (e *SignatureAlgorithmsCertExtension) UnmarshalJSON(data []byte) error {
	var signatureAlgorithms struct {
		Algorithms []string `json:"supported_signature_algorithms"`
	}
	if err := json.Unmarshal(data, &signatureAlgorithms); err != nil {
		return err
	}

	for _, sigScheme := range signatureAlgorithms.Algorithms {
		if sigScheme == "GREASE" {
			e.SupportedSignatureAlgorithms = append(e.SupportedSignatureAlgorithms, GREASE_PLACEHOLDER)
			continue
		}

		if scheme, ok := godicttls.DictSignatureSchemeNameIndexed[sigScheme]; ok {
			e.SupportedSignatureAlgorithms = append(e.SupportedSignatureAlgorithms, SignatureScheme(scheme))
		} else {
			return fmt.Errorf("unknown cert signature scheme: %s", sigScheme)
		}
	}
	return nil
}

func (e *SignatureAlgorithmsCertExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	var sigAndAlgs cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
		return 0, errors.New("unable to read signature algorithms extension data")
	}
	supportedSignatureAlgorithms := []SignatureScheme{}
	for !sigAndAlgs.Empty() {
		var sigAndAlg uint16
		if !sigAndAlgs.ReadUint16(&sigAndAlg) {
			return 0, errors.New("unable to read signature algorithms extension data")
		}
		supportedSignatureAlgorithms = append(
			supportedSignatureAlgorithms, SignatureScheme(sigAndAlg))
	}
	e.SupportedSignatureAlgorithms = supportedSignatureAlgorithms
	return fullLen, nil
}

func (e *SignatureAlgorithmsCertExtension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.SupportedSignatureAlgorithms = e.SupportedSignatureAlgorithms
	return nil
}

type ALPNExtension struct {
	AlpnProtocols []string
}

func (e *ALPNExtension) writeToUConn(uc *UConn) error {
	uc.config.NextProtos = e.AlpnProtocols
	uc.HandshakeState.Hello.AlpnProtocols = e.AlpnProtocols
	return nil
}

func (e *ALPNExtension) Len() int {
	bLen := 2 + 2 + 2
	for _, s := range e.AlpnProtocols {
		bLen += 1 + len(s)
	}
	return bLen
}

func (e *ALPNExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(extensionALPN >> 8)
	b[1] = byte(extensionALPN & 0xff)
	lengths := b[2:]
	b = b[6:]

	stringsLength := 0
	for _, s := range e.AlpnProtocols {
		l := len(s)
		b[0] = byte(l)
		copy(b[1:], s)
		b = b[1+l:]
		stringsLength += 1 + l
	}

	lengths[2] = byte(stringsLength >> 8)
	lengths[3] = byte(stringsLength)
	stringsLength += 2
	lengths[0] = byte(stringsLength >> 8)
	lengths[1] = byte(stringsLength)

	return e.Len(), io.EOF
}

func (e *ALPNExtension) UnmarshalJSON(b []byte) error {
	var protocolNames struct {
		ProtocolNameList []string `json:"protocol_name_list"`
	}

	if err := json.Unmarshal(b, &protocolNames); err != nil {
		return err
	}

	e.AlpnProtocols = protocolNames.ProtocolNameList
	return nil
}

func (e *ALPNExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	var protoList cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
		return 0, errors.New("unable to read ALPN extension data")
	}
	alpnProtocols := []string{}
	for !protoList.Empty() {
		var proto cryptobyte.String
		if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
			return 0, errors.New("unable to read ALPN extension data")
		}
		alpnProtocols = append(alpnProtocols, string(proto))

	}
	e.AlpnProtocols = alpnProtocols
	return fullLen, nil
}

type ApplicationSettingsExtension struct {
	SupportedProtocols []string
}

func (e *ApplicationSettingsExtension) writeToUConn(uc *UConn) error {
	return nil
}

func (e *ApplicationSettingsExtension) Len() int {
	bLen := 2 + 2 + 2
	for _, s := range e.SupportedProtocols {
		bLen += 1 + len(s)
	}
	return bLen
}

func (e *ApplicationSettingsExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(utlsExtensionApplicationSettings >> 8)
	b[1] = byte(utlsExtensionApplicationSettings & 0xff)

	lengths := b[2:]
	b = b[6:]

	stringsLength := 0
	for _, s := range e.SupportedProtocols {
		l := len(s)
		b[0] = byte(l)
		copy(b[1:], s)
		b = b[1+l:]
		stringsLength += 1 + l
	}

	lengths[2] = byte(stringsLength >> 8)
	lengths[3] = byte(stringsLength)
	stringsLength += 2
	lengths[0] = byte(stringsLength >> 8)
	lengths[1] = byte(stringsLength)

	return e.Len(), io.EOF
}

func (e *ApplicationSettingsExtension) UnmarshalJSON(b []byte) error {
	var applicationSettingsSupport struct {
		SupportedProtocols []string `json:"supported_protocols"`
	}

	if err := json.Unmarshal(b, &applicationSettingsSupport); err != nil {
		return err
	}

	e.SupportedProtocols = applicationSettingsSupport.SupportedProtocols
	return nil
}

func (e *ApplicationSettingsExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	var protoList cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
		return 0, errors.New("unable to read ALPN extension data")
	}
	alpnProtocols := []string{}
	for !protoList.Empty() {
		var proto cryptobyte.String
		if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
			return 0, errors.New("unable to read ALPN extension data")
		}
		alpnProtocols = append(alpnProtocols, string(proto))

	}
	e.SupportedProtocols = alpnProtocols
	return fullLen, nil
}

type SCTExtension struct {
}

func (e *SCTExtension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.Scts = true
	return nil
}

func (e *SCTExtension) Len() int {
	return 4
}

func (e *SCTExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(extensionSCT >> 8)
	b[1] = byte(extensionSCT)
	return e.Len(), io.EOF
}

func (e *SCTExtension) UnmarshalJSON(_ []byte) error {
	return nil
}

func (e *SCTExtension) Write(_ []byte) (int, error) {
	return 0, nil
}

type SessionTicketExtension struct {
	Session *ClientSessionState
}

func (e *SessionTicketExtension) writeToUConn(uc *UConn) error {
	if e.Session != nil {
		uc.HandshakeState.Session = e.Session.session
		uc.HandshakeState.Hello.SessionTicket = e.Session.ticket
	}
	return nil
}

func (e *SessionTicketExtension) Len() int {
	if e.Session != nil {
		return 4 + len(e.Session.ticket)
	}
	return 4
}

func (e *SessionTicketExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	extBodyLen := e.Len() - 4

	b[0] = byte(extensionSessionTicket >> 8)
	b[1] = byte(extensionSessionTicket)
	b[2] = byte(extBodyLen >> 8)
	b[3] = byte(extBodyLen)
	if extBodyLen > 0 {
		copy(b[4:], e.Session.ticket)
	}
	return e.Len(), io.EOF
}

func (e *SessionTicketExtension) UnmarshalJSON(_ []byte) error {
	return nil
}

func (e *SessionTicketExtension) Write(_ []byte) (int, error) {
	return 0, nil
}

type GenericExtension struct {
	Id   uint16
	Data []byte
}

func (e *GenericExtension) writeToUConn(uc *UConn) error {
	return nil
}

func (e *GenericExtension) Len() int {
	return 4 + len(e.Data)
}

func (e *GenericExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(e.Id >> 8)
	b[1] = byte(e.Id)
	b[2] = byte(len(e.Data) >> 8)
	b[3] = byte(len(e.Data))
	if len(e.Data) > 0 {
		copy(b[4:], e.Data)
	}
	return e.Len(), io.EOF
}

func (e *GenericExtension) UnmarshalJSON(b []byte) error {
	var genericExtension struct {
		Name string `json:"name"`
		Data []byte `json:"data"`
	}
	if err := json.Unmarshal(b, &genericExtension); err != nil {
		return err
	}

	if id, ok := godicttls.DictExtTypeNameIndexed[genericExtension.Name]; ok {
		e.Id = id
	} else {
		return fmt.Errorf("unknown extension name %s", genericExtension.Name)
	}
	e.Data = genericExtension.Data
	return nil
}

type ExtendedMasterSecretExtension struct {
}

func (e *ExtendedMasterSecretExtension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.Ems = true
	return nil
}

func (e *ExtendedMasterSecretExtension) Len() int {
	return 4
}

func (e *ExtendedMasterSecretExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(extensionExtendedMasterSecret >> 8)
	b[1] = byte(extensionExtendedMasterSecret)
	return e.Len(), io.EOF
}

func (e *ExtendedMasterSecretExtension) UnmarshalJSON(_ []byte) error {
	return nil
}

func (e *ExtendedMasterSecretExtension) Write(_ []byte) (int, error) {
	return 0, nil
}


func extendedMasterFromPreMasterSecret(version uint16, suite *cipherSuite, preMasterSecret []byte, sessionHash []byte) []byte {
	masterSecret := make([]byte, masterSecretLength)
	prfForVersion(version, suite)(masterSecret, preMasterSecret, extendedMasterSecretLabel, sessionHash)
	return masterSecret
}

const (
	ssl_grease_cipher = iota
	ssl_grease_group
	ssl_grease_extension1
	ssl_grease_extension2
	ssl_grease_version
	ssl_grease_ticket_extension
	ssl_grease_last_index = ssl_grease_ticket_extension
)

type UtlsGREASEExtension struct {
	Value uint16
	Body  []byte
}

func (e *UtlsGREASEExtension) writeToUConn(uc *UConn) error {
	return nil
}

func GetBoringGREASEValue(greaseSeed [ssl_grease_last_index]uint16, index int) uint16 {
	ret := uint16(greaseSeed[index])
	ret = (ret & 0xf0) | 0x0a
	ret |= ret << 8
	return ret
}

func (e *UtlsGREASEExtension) Len() int {
	return 4 + len(e.Body)
}

func (e *UtlsGREASEExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(e.Value >> 8)
	b[1] = byte(e.Value)
	b[2] = byte(len(e.Body) >> 8)
	b[3] = byte(len(e.Body))
	if len(e.Body) > 0 {
		copy(b[4:], e.Body)
	}
	return e.Len(), io.EOF
}

func (e *UtlsGREASEExtension) Write(b []byte) (int, error) {
	e.Value = GREASE_PLACEHOLDER
	e.Body = make([]byte, len(b))
	n := copy(e.Body, b)
	return n, nil
}

func (e *UtlsGREASEExtension) UnmarshalJSON(b []byte) error {
	var jsonObj struct {
		Id       uint16 `json:"id"`
		Data     []byte `json:"data"`
		KeepID   bool   `json:"keep_id"`
		KeepData bool   `json:"keep_data"`
	}

	if err := json.Unmarshal(b, &jsonObj); err != nil {
		return err
	}

	if jsonObj.Id == 0 {
		return nil
	}

	if isGREASEUint16(jsonObj.Id) {
		if jsonObj.KeepID {
			e.Value = jsonObj.Id
		}
		if jsonObj.KeepData {
			e.Body = jsonObj.Data
		}
		return nil
	} else {
		return errors.New("GREASE extension id must be a GREASE value")
	}
}

type UtlsPaddingExtension struct {
	PaddingLen int
	WillPad    bool

	GetPaddingLen func(clientHelloUnpaddedLen int) (paddingLen int, willPad bool)
}

func (e *UtlsPaddingExtension) writeToUConn(uc *UConn) error {
	return nil
}

func (e *UtlsPaddingExtension) Len() int {
	if e.WillPad {
		return 4 + e.PaddingLen
	} else {
		return 0
	}
}

func (e *UtlsPaddingExtension) Update(clientHelloUnpaddedLen int) {
	if e.GetPaddingLen != nil {
		e.PaddingLen, e.WillPad = e.GetPaddingLen(clientHelloUnpaddedLen)
	}
}

func (e *UtlsPaddingExtension) Read(b []byte) (int, error) {
	if !e.WillPad {
		return 0, io.EOF
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(utlsExtensionPadding >> 8)
	b[1] = byte(utlsExtensionPadding)
	b[2] = byte(e.PaddingLen >> 8)
	b[3] = byte(e.PaddingLen)
	return e.Len(), io.EOF
}

func (e *UtlsPaddingExtension) UnmarshalJSON(b []byte) error {
	var jsonObj struct {
		Length uint `json:"len"`
	}
	if err := json.Unmarshal(b, &jsonObj); err != nil {
		return err
	}

	if jsonObj.Length == 0 {
		e.GetPaddingLen = BoringPaddingStyle
	} else {
		e.PaddingLen = int(jsonObj.Length)
		e.WillPad = true
	}

	return nil
}

func (e *UtlsPaddingExtension) Write(_ []byte) (int, error) {
	e.GetPaddingLen = BoringPaddingStyle
	return 0, nil
}

func BoringPaddingStyle(unpaddedLen int) (int, bool) {
	if unpaddedLen > 0xff && unpaddedLen < 0x200 {
		paddingLen := 0x200 - unpaddedLen
		if paddingLen >= 4+1 {
			paddingLen -= 4
		} else {
			paddingLen = 1
		}
		return paddingLen, true
	}
	return 0, false
}

type UtlsCompressCertExtension struct {
	Algorithms []CertCompressionAlgo
}

func (e *UtlsCompressCertExtension) writeToUConn(uc *UConn) error {
	uc.certCompressionAlgs = e.Algorithms
	return nil
}

func (e *UtlsCompressCertExtension) Len() int {
	return 4 + 1 + (2 * len(e.Algorithms))
}

func (e *UtlsCompressCertExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(utlsExtensionCompressCertificate >> 8)
	b[1] = byte(utlsExtensionCompressCertificate & 0xff)

	extLen := 2 * len(e.Algorithms)
	if extLen > 255 {
		return 0, errors.New("too many certificate compression methods")
	}

	b[2] = byte((extLen + 1) >> 8)
	b[3] = byte((extLen + 1) & 0xff)

	b[4] = byte(extLen)

	i := 5
	for _, compMethod := range e.Algorithms {
		b[i] = byte(compMethod >> 8)
		b[i+1] = byte(compMethod)
		i += 2
	}
	return e.Len(), io.EOF
}

func (e *UtlsCompressCertExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	methods := []CertCompressionAlgo{}
	methodsRaw := new(cryptobyte.String)
	if !extData.ReadUint8LengthPrefixed(methodsRaw) {
		return 0, errors.New("unable to read cert compression algorithms extension data")
	}
	for !methodsRaw.Empty() {
		var method uint16
		if !methodsRaw.ReadUint16(&method) {
			return 0, errors.New("unable to read cert compression algorithms extension data")
		}
		methods = append(methods, CertCompressionAlgo(method))
	}

	e.Algorithms = methods
	return fullLen, nil
}

func (e *UtlsCompressCertExtension) UnmarshalJSON(b []byte) error {
	var certificateCompressionAlgorithms struct {
		Algorithms []string `json:"algorithms"`
	}
	if err := json.Unmarshal(b, &certificateCompressionAlgorithms); err != nil {
		return err
	}

	for _, algorithm := range certificateCompressionAlgorithms.Algorithms {
		if alg, ok := godicttls.DictCertificateCompressionAlgorithmNameIndexed[algorithm]; ok {
			e.Algorithms = append(e.Algorithms, CertCompressionAlgo(alg))
		} else {
			return fmt.Errorf("unknown certificate compression algorithm %s", algorithm)
		}
	}
	return nil
}

type KeyShareExtension struct {
	KeyShares []KeyShare
}

func (e *KeyShareExtension) Len() int {
	return 4 + 2 + e.keySharesLen()
}

func (e *KeyShareExtension) keySharesLen() int {
	extLen := 0
	for _, ks := range e.KeyShares {
		extLen += 4 + len(ks.Data)
	}
	return extLen
}

func (e *KeyShareExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(extensionKeyShare >> 8)
	b[1] = byte(extensionKeyShare)
	keySharesLen := e.keySharesLen()
	b[2] = byte((keySharesLen + 2) >> 8)
	b[3] = byte(keySharesLen + 2)
	b[4] = byte((keySharesLen) >> 8)
	b[5] = byte(keySharesLen)

	i := 6
	for _, ks := range e.KeyShares {
		b[i] = byte(ks.Group >> 8)
		b[i+1] = byte(ks.Group)
		b[i+2] = byte(len(ks.Data) >> 8)
		b[i+3] = byte(len(ks.Data))
		copy(b[i+4:], ks.Data)
		i += 4 + len(ks.Data)
	}

	return e.Len(), io.EOF
}

func (e *KeyShareExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	var clientShares cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&clientShares) {
		return 0, errors.New("unable to read key share extension data")
	}
	keyShares := []KeyShare{}
	for !clientShares.Empty() {
		var ks KeyShare
		var group uint16
		if !clientShares.ReadUint16(&group) ||
			!readUint16LengthPrefixed(&clientShares, &ks.Data) ||
			len(ks.Data) == 0 {
			return 0, errors.New("unable to read key share extension data")
		}
		ks.Group = CurveID(unGREASEUint16(group))
		if ks.Group != GREASE_PLACEHOLDER {
			ks.Data = nil
		}
		keyShares = append(keyShares, ks)
	}
	e.KeyShares = keyShares
	return fullLen, nil
}

func (e *KeyShareExtension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.KeyShares = e.KeyShares
	return nil
}

func (e *KeyShareExtension) UnmarshalJSON(b []byte) error {
	var keyShareClientHello struct {
		ClientShares []struct {
			Group       string  `json:"group"`
			KeyExchange []uint8 `json:"key_exchange"`
		} `json:"client_shares"`
	}
	if err := json.Unmarshal(b, &keyShareClientHello); err != nil {
		return err
	}

	for _, clientShare := range keyShareClientHello.ClientShares {
		if clientShare.Group == "GREASE" {
			e.KeyShares = append(e.KeyShares, KeyShare{
				Group: GREASE_PLACEHOLDER,
				Data:  clientShare.KeyExchange,
			})
			continue
		}

		if groupID, ok := godicttls.DictSupportedGroupsNameIndexed[clientShare.Group]; ok {
			ks := KeyShare{
				Group: CurveID(groupID),
				Data:  clientShare.KeyExchange,
			}
			e.KeyShares = append(e.KeyShares, ks)
		} else {
			return fmt.Errorf("unknown group %s", clientShare.Group)
		}
	}
	return nil
}

type QUICTransportParametersExtension struct {
	TransportParameters TransportParameters

	marshalResult []byte
}

func (e *QUICTransportParametersExtension) Len() int {
	if e.marshalResult == nil {
		e.marshalResult = e.TransportParameters.Marshal()
	}
	return 4 + len(e.marshalResult)
}

func (e *QUICTransportParametersExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(extensionQUICTransportParameters >> 8)
	b[1] = byte(extensionQUICTransportParameters)
	b[2] = byte((len(e.marshalResult)) >> 8)
	b[3] = byte(len(e.marshalResult))
	copy(b[4:], e.marshalResult)

	return e.Len(), io.EOF
}

func (e *QUICTransportParametersExtension) writeToUConn(*UConn) error {
	return nil
}

type PSKKeyExchangeModesExtension struct {
	Modes []uint8
}

func (e *PSKKeyExchangeModesExtension) Len() int {
	return 4 + 1 + len(e.Modes)
}

func (e *PSKKeyExchangeModesExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	if len(e.Modes) > 255 {
		return 0, errors.New("too many PSK Key Exchange modes")
	}

	b[0] = byte(extensionPSKModes >> 8)
	b[1] = byte(extensionPSKModes)

	modesLen := len(e.Modes)
	b[2] = byte((modesLen + 1) >> 8)
	b[3] = byte(modesLen + 1)
	b[4] = byte(modesLen)

	if len(e.Modes) > 0 {
		copy(b[5:], e.Modes)
	}

	return e.Len(), io.EOF
}

func (e *PSKKeyExchangeModesExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	pskModes := []uint8{}
	if !readUint8LengthPrefixed(&extData, &pskModes) {
		return 0, errors.New("unable to read PSK extension data")
	}
	e.Modes = pskModes
	return fullLen, nil
}

func (e *PSKKeyExchangeModesExtension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.PskModes = e.Modes
	return nil
}

func (e *PSKKeyExchangeModesExtension) UnmarshalJSON(b []byte) error {
	var pskKeyExchangeModes struct {
		Modes []string `json:"ke_modes"`
	}
	if err := json.Unmarshal(b, &pskKeyExchangeModes); err != nil {
		return err
	}

	for _, mode := range pskKeyExchangeModes.Modes {
		if modeID, ok := godicttls.DictPSKKeyExchangeModeNameIndexed[mode]; ok {
			e.Modes = append(e.Modes, modeID)
		} else {
			return fmt.Errorf("unknown PSK Key Exchange Mode %s", mode)
		}
	}
	return nil
}

type SupportedVersionsExtension struct {
	Versions []uint16
}

func (e *SupportedVersionsExtension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.SupportedVersions = e.Versions
	return nil
}

func (e *SupportedVersionsExtension) Len() int {
	return 4 + 1 + (2 * len(e.Versions))
}

func (e *SupportedVersionsExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	extLen := 2 * len(e.Versions)
	if extLen > 255 {
		return 0, errors.New("too many supported versions")
	}

	b[0] = byte(extensionSupportedVersions >> 8)
	b[1] = byte(extensionSupportedVersions)
	b[2] = byte((extLen + 1) >> 8)
	b[3] = byte(extLen + 1)
	b[4] = byte(extLen)

	i := 5
	for _, sv := range e.Versions {
		b[i] = byte(sv >> 8)
		b[i+1] = byte(sv)
		i += 2
	}
	return e.Len(), io.EOF
}

func (e *SupportedVersionsExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	var versList cryptobyte.String
	if !extData.ReadUint8LengthPrefixed(&versList) || versList.Empty() {
		return 0, errors.New("unable to read supported versions extension data")
	}
	supportedVersions := []uint16{}
	for !versList.Empty() {
		var vers uint16
		if !versList.ReadUint16(&vers) {
			return 0, errors.New("unable to read supported versions extension data")
		}
		supportedVersions = append(supportedVersions, unGREASEUint16(vers))
	}
	e.Versions = supportedVersions
	return fullLen, nil
}

func (e *SupportedVersionsExtension) UnmarshalJSON(b []byte) error {
	var supportedVersions struct {
		Versions []string `json:"versions"`
	}
	if err := json.Unmarshal(b, &supportedVersions); err != nil {
		return err
	}

	for _, version := range supportedVersions.Versions {
		switch version {
		case "GREASE":
			e.Versions = append(e.Versions, GREASE_PLACEHOLDER)
		case "TLS 1.3":
			e.Versions = append(e.Versions, VersionTLS13)
		case "TLS 1.2":
			e.Versions = append(e.Versions, VersionTLS12)
		case "TLS 1.1":
			e.Versions = append(e.Versions, VersionTLS11)
		case "TLS 1.0":
			e.Versions = append(e.Versions, VersionTLS10)
		case "SSL 3.0":
			return fmt.Errorf("SSL 3.0 is deprecated")
		default:
			return fmt.Errorf("unknown version %s", version)
		}
	}
	return nil
}

type CookieExtension struct {
	Cookie []byte
}

func (e *CookieExtension) writeToUConn(uc *UConn) error {
	return nil
}

func (e *CookieExtension) Len() int {
	return 4 + len(e.Cookie)
}

func (e *CookieExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(extensionCookie >> 8)
	b[1] = byte(extensionCookie)
	b[2] = byte(len(e.Cookie) >> 8)
	b[3] = byte(len(e.Cookie))
	if len(e.Cookie) > 0 {
		copy(b[4:], e.Cookie)
	}
	return e.Len(), io.EOF
}

func (e *CookieExtension) UnmarshalJSON(data []byte) error {
	var cookie struct {
		Cookie []uint8 `json:"cookie"`
	}
	if err := json.Unmarshal(data, &cookie); err != nil {
		return err
	}
	e.Cookie = []byte(cookie.Cookie)
	return nil
}

type NPNExtension struct {
	NextProtos []string
}

func (e *NPNExtension) writeToUConn(uc *UConn) error {
	uc.config.NextProtos = e.NextProtos
	uc.HandshakeState.Hello.NextProtoNeg = true
	return nil
}

func (e *NPNExtension) Len() int {
	return 4
}

func (e *NPNExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(extensionNextProtoNeg >> 8)
	b[1] = byte(extensionNextProtoNeg & 0xff)
	return e.Len(), io.EOF
}

func (e *NPNExtension) Write(_ []byte) (int, error) {
	return 0, nil
}

func (e *NPNExtension) UnmarshalJSON(_ []byte) error {
	return nil
}

type RenegotiationInfoExtension struct {
	Renegotiation RenegotiationSupport

}

func (e *RenegotiationInfoExtension) Len() int {
	return 5
}

func (e *RenegotiationInfoExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	extBodyLen := 1

	b[0] = byte(extensionRenegotiationInfo >> 8)
	b[1] = byte(extensionRenegotiationInfo & 0xff)
	b[2] = byte(extBodyLen >> 8)
	b[3] = byte(extBodyLen)

	return e.Len(), io.EOF
}

func (e *RenegotiationInfoExtension) UnmarshalJSON(_ []byte) error {
	e.Renegotiation = RenegotiateOnceAsClient
	return nil
}

func (e *RenegotiationInfoExtension) Write(_ []byte) (int, error) {
	e.Renegotiation = RenegotiateOnceAsClient
	return 0, nil
}

func (e *RenegotiationInfoExtension) writeToUConn(uc *UConn) error {
	uc.config.Renegotiation = e.Renegotiation
	switch e.Renegotiation {
	case RenegotiateOnceAsClient:
		fallthrough
	case RenegotiateFreelyAsClient:
		uc.HandshakeState.Hello.SecureRenegotiationSupported = true
	case RenegotiateNever:
	default:
	}
	return nil
}


type FakeChannelIDExtension struct {
	OldExtensionID bool
}

func (e *FakeChannelIDExtension) writeToUConn(uc *UConn) error {
	return nil
}

func (e *FakeChannelIDExtension) Len() int {
	return 4
}

func (e *FakeChannelIDExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	extensionID := fakeExtensionChannelID
	if e.OldExtensionID {
		extensionID = fakeOldExtensionChannelID
	}
	b[0] = byte(extensionID >> 8)
	b[1] = byte(extensionID & 0xff)
	return e.Len(), io.EOF
}

func (e *FakeChannelIDExtension) Write(_ []byte) (int, error) {
	return 0, nil
}

func (e *FakeChannelIDExtension) UnmarshalJSON(_ []byte) error {
	return nil
}

type FakeRecordSizeLimitExtension struct {
	Limit uint16
}

func (e *FakeRecordSizeLimitExtension) writeToUConn(uc *UConn) error {
	return nil
}

func (e *FakeRecordSizeLimitExtension) Len() int {
	return 6
}

func (e *FakeRecordSizeLimitExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(fakeRecordSizeLimit >> 8)
	b[1] = byte(fakeRecordSizeLimit & 0xff)

	b[2] = byte(0)
	b[3] = byte(2)

	b[4] = byte(e.Limit >> 8)
	b[5] = byte(e.Limit & 0xff)
	return e.Len(), io.EOF
}

func (e *FakeRecordSizeLimitExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	if !extData.ReadUint16(&e.Limit) {
		return 0, errors.New("unable to read record size limit extension data")
	}
	return fullLen, nil
}

func (e *FakeRecordSizeLimitExtension) UnmarshalJSON(data []byte) error {
	var limitAccepter struct {
		Limit uint16 `json:"record_size_limit"`
	}
	if err := json.Unmarshal(data, &limitAccepter); err != nil {
		return err
	}

	e.Limit = limitAccepter.Limit
	return nil
}

type DelegatedCredentialsExtension = FakeDelegatedCredentialsExtension

type FakeTokenBindingExtension struct {
	MajorVersion, MinorVersion uint8
	KeyParameters              []uint8
}

func (e *FakeTokenBindingExtension) writeToUConn(uc *UConn) error {
	return nil
}

func (e *FakeTokenBindingExtension) Len() int {
	return 2 + 2 + 2 + 1 + len(e.KeyParameters)
}

func (e *FakeTokenBindingExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	dataLen := e.Len() - 4
	b[0] = byte(fakeExtensionTokenBinding >> 8)
	b[1] = byte(fakeExtensionTokenBinding & 0xff)
	b[2] = byte(dataLen >> 8)
	b[3] = byte(dataLen & 0xff)
	b[4] = e.MajorVersion
	b[5] = e.MinorVersion
	b[6] = byte(len(e.KeyParameters))
	if len(e.KeyParameters) > 0 {
		copy(b[7:], e.KeyParameters)
	}
	return e.Len(), io.EOF
}

func (e *FakeTokenBindingExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	var keyParameters cryptobyte.String
	if !extData.ReadUint8(&e.MajorVersion) ||
		!extData.ReadUint8(&e.MinorVersion) ||
		!extData.ReadUint8LengthPrefixed(&keyParameters) {
		return 0, errors.New("unable to read token binding extension data")
	}
	e.KeyParameters = keyParameters
	return fullLen, nil
}

func (e *FakeTokenBindingExtension) UnmarshalJSON(data []byte) error {
	var tokenBindingAccepter struct {
		TB_ProtocolVersion struct {
			Major uint8 `json:"major"`
			Minor uint8 `json:"minor"`
		} `json:"token_binding_version"`
		TokenBindingKeyParameters []string `json:"key_parameters_list"`
	}
	if err := json.Unmarshal(data, &tokenBindingAccepter); err != nil {
		return err
	}

	e.MajorVersion = tokenBindingAccepter.TB_ProtocolVersion.Major
	e.MinorVersion = tokenBindingAccepter.TB_ProtocolVersion.Minor
	for _, param := range tokenBindingAccepter.TokenBindingKeyParameters {
		switch param {
		case "rsa2048_pkcs1.5":
			e.KeyParameters = append(e.KeyParameters, 0)
		case "rsa2048_pss":
			e.KeyParameters = append(e.KeyParameters, 1)
		case "ecdsap256":
			e.KeyParameters = append(e.KeyParameters, 2)
		default:
			return fmt.Errorf("unknown token binding key parameter: %s", param)
		}
	}
	return nil
}


type FakeDelegatedCredentialsExtension struct {
	SupportedSignatureAlgorithms []SignatureScheme
}

func (e *FakeDelegatedCredentialsExtension) writeToUConn(uc *UConn) error {
	return nil
}

func (e *FakeDelegatedCredentialsExtension) Len() int {
	return 6 + 2*len(e.SupportedSignatureAlgorithms)
}

func (e *FakeDelegatedCredentialsExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(fakeExtensionDelegatedCredentials >> 8)
	b[1] = byte(fakeExtensionDelegatedCredentials)
	b[2] = byte((2 + 2*len(e.SupportedSignatureAlgorithms)) >> 8)
	b[3] = byte((2 + 2*len(e.SupportedSignatureAlgorithms)))
	b[4] = byte((2 * len(e.SupportedSignatureAlgorithms)) >> 8)
	b[5] = byte((2 * len(e.SupportedSignatureAlgorithms)))
	for i, sigAndHash := range e.SupportedSignatureAlgorithms {
		b[6+2*i] = byte(sigAndHash >> 8)
		b[7+2*i] = byte(sigAndHash)
	}
	return e.Len(), io.EOF
}

func (e *FakeDelegatedCredentialsExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	var supportedAlgs cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&supportedAlgs) || supportedAlgs.Empty() {
		return 0, errors.New("unable to read signature algorithms extension data")
	}
	supportedSignatureAlgorithms := []SignatureScheme{}
	for !supportedAlgs.Empty() {
		var sigAndAlg uint16
		if !supportedAlgs.ReadUint16(&sigAndAlg) {
			return 0, errors.New("unable to read signature algorithms extension data")
		}
		supportedSignatureAlgorithms = append(
			supportedSignatureAlgorithms, SignatureScheme(sigAndAlg))
	}
	e.SupportedSignatureAlgorithms = supportedSignatureAlgorithms
	return fullLen, nil
}

func (e *FakeDelegatedCredentialsExtension) UnmarshalJSON(data []byte) error {
	var signatureAlgorithms struct {
		Algorithms []string `json:"supported_signature_algorithms"`
	}
	if err := json.Unmarshal(data, &signatureAlgorithms); err != nil {
		return err
	}

	for _, sigScheme := range signatureAlgorithms.Algorithms {
		if sigScheme == "GREASE" {
			e.SupportedSignatureAlgorithms = append(e.SupportedSignatureAlgorithms, GREASE_PLACEHOLDER)
			continue
		}

		if scheme, ok := godicttls.DictSignatureSchemeNameIndexed[sigScheme]; ok {
			e.SupportedSignatureAlgorithms = append(e.SupportedSignatureAlgorithms, SignatureScheme(scheme))
		} else {
			return fmt.Errorf("unknown delegated credentials signature scheme: %s", sigScheme)
		}
	}
	return nil
}

type FakePreSharedKeyExtension struct {
	PskIdentities []PskIdentity `json:"identities"`
	PskBinders    [][]byte      `json:"binders"`
}

func (e *FakePreSharedKeyExtension) writeToUConn(uc *UConn) error {
	if uc.config.ClientSessionCache == nil {
		return nil
	}
	if session, ok := uc.config.ClientSessionCache.Get(uc.clientSessionCacheKey()); !ok || session == nil {
		return nil
	}
	uc.HandshakeState.Hello.PskIdentities = e.PskIdentities
	uc.HandshakeState.Hello.PskBinders = e.PskBinders
	return nil
}

func (e *FakePreSharedKeyExtension) Len() int {
	length := 4
	length += 2
	for _, identity := range e.PskIdentities {
		length += 2 + len(identity.Label) + 4
	}
	length += 2
	for _, binder := range e.PskBinders {
		length += len(binder)
	}
	return length
}

func (e *FakePreSharedKeyExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(extensionPreSharedKey >> 8)
	b[1] = byte(extensionPreSharedKey)
	b[2] = byte((e.Len() - 4) >> 8)
	b[3] = byte(e.Len() - 4)

	identitiesLength := 0
	for _, identity := range e.PskIdentities {
		identitiesLength += 2 + len(identity.Label) + 4
	}
	b[4] = byte(identitiesLength >> 8)
	b[5] = byte(identitiesLength)

	offset := 6
	for _, identity := range e.PskIdentities {
		b[offset] = byte(len(identity.Label) >> 8)
		b[offset+1] = byte(len(identity.Label))
		offset += 2
		copy(b[offset:], identity.Label)
		offset += len(identity.Label)
		b[offset] = byte(identity.ObfuscatedTicketAge >> 24)
		b[offset+1] = byte(identity.ObfuscatedTicketAge >> 16)
		b[offset+2] = byte(identity.ObfuscatedTicketAge >> 8)
		b[offset+3] = byte(identity.ObfuscatedTicketAge)
		offset += 4
	}

	bindersLength := 0
	for _, binder := range e.PskBinders {
		bindersLength += len(binder)
	}
	b[offset] = byte(bindersLength >> 8)
	b[offset+1] = byte(bindersLength)
	offset += 2

	for _, binder := range e.PskBinders {
		copy(b[offset:], binder)
		offset += len(binder)
	}

	return e.Len(), io.EOF
}

func (e *FakePreSharedKeyExtension) Write(b []byte) (n int, err error) {
	fullLen := len(b)
	s := cryptobyte.String(b)

	var identitiesLength uint16
	if !s.ReadUint16(&identitiesLength) {
		return 0, errors.New("tls: invalid PSK extension")
	}

	for identitiesLength > 0 {
		var identityLength uint16
		if !s.ReadUint16(&identityLength) {
			return 0, errors.New("tls: invalid PSK extension")
		}
		identitiesLength -= 2

		if identityLength > identitiesLength {
			return 0, errors.New("tls: invalid PSK extension")
		}

		var identity []byte
		if !s.ReadBytes(&identity, int(identityLength)) {
			return 0, errors.New("tls: invalid PSK extension")
		}

		identitiesLength -= identityLength

		var obfuscatedTicketAge uint32
		if !s.ReadUint32(&obfuscatedTicketAge) {
			return 0, errors.New("tls: invalid PSK extension")
		}

		e.PskIdentities = append(e.PskIdentities, PskIdentity{
			Label:               identity,
			ObfuscatedTicketAge: obfuscatedTicketAge,
		})

		identitiesLength -= 4
	}

	var bindersLength uint16
	if !s.ReadUint16(&bindersLength) {
		return 0, errors.New("tls: invalid PSK extension")
	}

	for bindersLength > 0 {
		var binderLength uint8
		if !s.ReadUint8(&binderLength) {
			return 0, errors.New("tls: invalid PSK extension")
		}
		bindersLength -= 1

		if uint16(binderLength) > bindersLength {
			return 0, errors.New("tls: invalid PSK extension")
		}

		var binder []byte
		if !s.ReadBytes(&binder, int(binderLength)) {
			return 0, errors.New("tls: invalid PSK extension")
		}

		e.PskBinders = append(e.PskBinders, binder)

		bindersLength -= uint16(binderLength)
	}

	return fullLen, nil
}

func (e *FakePreSharedKeyExtension) UnmarshalJSON(data []byte) error {
	var pskAccepter struct {
		PskIdentities []PskIdentity `json:"identities"`
		PskBinders    [][]byte      `json:"binders"`
	}

	if err := json.Unmarshal(data, &pskAccepter); err != nil {
		return err
	}

	e.PskIdentities = pskAccepter.PskIdentities
	e.PskBinders = pskAccepter.PskBinders
	return nil
}
