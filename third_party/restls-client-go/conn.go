// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.


package tls

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Conn struct {
	conn        net.Conn
	isClient    bool
	handshakeFn func(context.Context) error
	quic        *quicState

	isHandshakeComplete atomic.Bool
	handshakeMutex sync.Mutex
	handshakeErr   error
	vers           uint16
	haveVers       bool
	config         *Config
	handshakes       int
	extMasterSecret  bool
	didResume        bool
	cipherSuite      uint16
	ocspResponse     []byte
	scts             [][]byte
	peerCertificates []*x509.Certificate
	activeCertHandles []*activeCert
	verifiedChains [][]*x509.Certificate
	serverName string
	secureRenegotiation bool
	ekm func(label string, context []byte, length int) ([]byte, error)
	resumptionSecret []byte

	ticketKeys []ticketKey

	clientFinishedIsFirst bool

	closeNotifyErr error
	closeNotifySent bool

	clientFinished [12]byte
	serverFinished [12]byte

	clientProtocol string

	utls utlsConnExtraFields

	in, out   halfConn
	rawInput  bytes.Buffer
	input     bytes.Reader
	hand      bytes.Buffer
	buffering bool
	sendBuf   []byte

	bytesSent   int64
	packetsSent int64

	retryCount int

	activeCall atomic.Int32

	tmp [16]byte

	eagerEcdheKey         []*ecdh.PrivateKey
	serverRandom          []byte
	restlsAuthed          bool
	restlsToClientCounter uint64
	restlsToServerCounter uint64
	restlsSendBuf         []byte
	restlsWritePending    atomic.Bool
	restls12WithGCM       bool

	restlsToClientRealRecordCounter uint64
	restls12GCMServerDisableCtr     bool
}

// Access to net.Conn methods.
// Cannot just embed net.Conn because that would
// export the struct field too.

func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) NetConn() net.Conn {
	return c.conn
}

type halfConn struct {
	sync.Mutex

	err     error
	version uint16
	cipher  any
	mac     hash.Hash
	seq     [8]byte

	scratchBuf [13]byte

	nextCipher any
	nextMac    hash.Hash

	restlsPlugin RestlsPlugin

	level         QUICEncryptionLevel
	trafficSecret []byte
}

type permanentError struct {
	err net.Error
}

func (e *permanentError) Error() string   { return e.err.Error() }
func (e *permanentError) Unwrap() error   { return e.err }
func (e *permanentError) Timeout() bool   { return e.err.Timeout() }
func (e *permanentError) Temporary() bool { return false }

func (hc *halfConn) setErrorLocked(err error) error {
	if e, ok := err.(net.Error); ok {
		hc.err = &permanentError{err: e}
	} else {
		hc.err = err
	}
	return hc.err
}

func (hc *halfConn) prepareCipherSpec(version uint16, cipher any, mac hash.Hash, backupCipher ...any) {
	hc.version = version
	hc.nextCipher = cipher
	hc.nextMac = mac
	hc.restlsPlugin.setBackupCipher(backupCipher...)
}

func (hc *halfConn) changeCipherSpec() error {
	if hc.nextCipher == nil || hc.version == VersionTLS13 {
		return alertInternalError
	}
	hc.cipher = hc.nextCipher
	hc.mac = hc.nextMac
	hc.nextCipher = nil
	hc.nextMac = nil
	for i := range hc.seq {
		hc.seq[i] = 0
	}
	hc.restlsPlugin.changeCipher()
	return nil
}

func (hc *halfConn) setTrafficSecret(suite *cipherSuiteTLS13, level QUICEncryptionLevel, secret []byte) {
	hc.trafficSecret = secret
	hc.level = level
	key, iv := suite.trafficKey(secret)
	hc.cipher = suite.aead(key, iv)
	hc.restlsPlugin.setBackupCipher(suite.aead(key, iv))
	hc.restlsPlugin.changeCipher()
	for i := range hc.seq {
		hc.seq[i] = 0
	}
}

func (hc *halfConn) incSeq() {
	for i := 7; i >= 0; i-- {
		hc.seq[i]++
		if hc.seq[i] != 0 {
			return
		}
	}

	panic("TLS: sequence number wraparound")
}

func (hc *halfConn) explicitNonceLen() int {
	if hc.cipher == nil {
		return 0
	}

	switch c := hc.cipher.(type) {
	case cipher.Stream:
		return 0
	case aead:
		return c.explicitNonceLen()
	case cbcMode:
		if hc.version >= VersionTLS11 {
			return c.BlockSize()
		}
		return 0
	default:
		panic("unknown cipher type")
	}
}

func extractPadding(payload []byte) (toRemove int, good byte) {
	if len(payload) < 1 {
		return 0, 0
	}

	paddingLen := payload[len(payload)-1]
	t := uint(len(payload)-1) - uint(paddingLen)
	good = byte(int32(^t) >> 31)

	toCheck := 256
	if toCheck > len(payload) {
		toCheck = len(payload)
	}

	for i := 0; i < toCheck; i++ {
		t := uint(paddingLen) - uint(i)
		mask := byte(int32(^t) >> 31)
		b := payload[len(payload)-1-i]
		good &^= mask&paddingLen ^ mask&b
	}

	good &= good << 4
	good &= good << 2
	good &= good << 1
	good = uint8(int8(good) >> 7)

	paddingLen &= good

	toRemove = int(paddingLen) + 1
	return
}

func roundUp(a, b int) int {
	return a + (b-a%b)%b
}

type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

func (hc *halfConn) decrypt(record []byte) ([]byte, recordType, error) {
	var plaintext []byte
	typ := recordType(record[0])
	payload := record[recordHeaderLen:]

	if hc.version == VersionTLS13 && typ == recordTypeChangeCipherSpec {
		return payload, typ, nil
	}

	paddingGood := byte(255)
	paddingLen := 0

	explicitNonceLen := hc.explicitNonceLen()

	if hc.cipher != nil {
		switch c := hc.cipher.(type) {
		case cipher.Stream:
			c.XORKeyStream(payload, payload)
		case aead:
			if len(payload) < explicitNonceLen {
				return nil, 0, alertBadRecordMAC
			}
			nonce := payload[:explicitNonceLen]
			if len(nonce) == 0 {
				nonce = hc.seq[:]
			}
			payload = payload[explicitNonceLen:]

			var additionalData []byte
			if hc.version == VersionTLS13 {
				additionalData = record[:recordHeaderLen]
			} else {
				additionalData = append(hc.scratchBuf[:0], hc.seq[:]...)
				additionalData = append(additionalData, record[:3]...)
				n := len(payload) - c.Overhead()
				additionalData = append(additionalData, byte(n>>8), byte(n))
			}

			var err error
			plaintext, err = c.Open(payload[:0], nonce, payload, additionalData)
			if err != nil {
				return nil, 0, alertBadRecordMAC
			}
		case cbcMode:
			blockSize := c.BlockSize()
			minPayload := explicitNonceLen + roundUp(hc.mac.Size()+1, blockSize)
			if len(payload)%blockSize != 0 || len(payload) < minPayload {
				return nil, 0, alertBadRecordMAC
			}

			if explicitNonceLen > 0 {
				c.SetIV(payload[:explicitNonceLen])
				payload = payload[explicitNonceLen:]
			}
			c.CryptBlocks(payload, payload)

			paddingLen, paddingGood = extractPadding(payload)
		default:
			panic("unknown cipher type")
		}

		if hc.version == VersionTLS13 {
			if typ != recordTypeApplicationData {
				return nil, 0, alertUnexpectedMessage
			}
			if len(plaintext) > maxPlaintext+1 {
				return nil, 0, alertRecordOverflow
			}
			for i := len(plaintext) - 1; i >= 0; i-- {
				if plaintext[i] != 0 {
					typ = recordType(plaintext[i])
					plaintext = plaintext[:i]
					break
				}
				if i == 0 {
					return nil, 0, alertUnexpectedMessage
				}
			}
		}
	} else {
		plaintext = payload
	}

	if hc.mac != nil {
		macSize := hc.mac.Size()
		if len(payload) < macSize {
			return nil, 0, alertBadRecordMAC
		}

		n := len(payload) - macSize - paddingLen
		n = subtle.ConstantTimeSelect(int(uint32(n)>>31), 0, n)
		record[3] = byte(n >> 8)
		record[4] = byte(n)
		remoteMAC := payload[n : n+macSize]
		localMAC := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload[:n], payload[n+macSize:])

		macAndPaddingGood := subtle.ConstantTimeCompare(localMAC, remoteMAC) & int(paddingGood)
		if macAndPaddingGood != 1 {
			return nil, 0, alertBadRecordMAC
		}

		plaintext = payload[:n]
	}

	hc.incSeq()
	return plaintext, typ, nil
}

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

func (hc *halfConn) encrypt(record, payload []byte, rand io.Reader) ([]byte, error) {
	if hc.cipher == nil {
		return append(record, payload...), nil
	}

	var explicitNonce []byte
	if explicitNonceLen := hc.explicitNonceLen(); explicitNonceLen > 0 {
		record, explicitNonce = sliceForAppend(record, explicitNonceLen)
		if _, isCBC := hc.cipher.(cbcMode); !isCBC && explicitNonceLen < 16 {
			copy(explicitNonce, hc.seq[:])
		} else {
			if _, err := io.ReadFull(rand, explicitNonce); err != nil {
				return nil, err
			}
		}
	}

	var dst []byte
	switch c := hc.cipher.(type) {
	case cipher.Stream:
		mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload, nil)
		record, dst = sliceForAppend(record, len(payload)+len(mac))
		c.XORKeyStream(dst[:len(payload)], payload)
		c.XORKeyStream(dst[len(payload):], mac)
	case aead:
		nonce := explicitNonce
		if len(nonce) == 0 {
			nonce = hc.seq[:]
		}

		if hc.version == VersionTLS13 {
			record = append(record, payload...)

			record = append(record, record[0])
			record[0] = byte(recordTypeApplicationData)

			n := len(payload) + 1 + c.Overhead()
			record[3] = byte(n >> 8)
			record[4] = byte(n)

			record = c.Seal(record[:recordHeaderLen],
				nonce, record[recordHeaderLen:], record[:recordHeaderLen])
		} else {
			additionalData := append(hc.scratchBuf[:0], hc.seq[:]...)
			additionalData = append(additionalData, record[:recordHeaderLen]...)
			record = c.Seal(record, nonce, payload, additionalData)
		}
	case cbcMode:
		mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload, nil)
		blockSize := c.BlockSize()
		plaintextLen := len(payload) + len(mac)
		paddingLen := blockSize - plaintextLen%blockSize
		record, dst = sliceForAppend(record, plaintextLen+paddingLen)
		copy(dst, payload)
		copy(dst[len(payload):], mac)
		for i := plaintextLen; i < len(dst); i++ {
			dst[i] = byte(paddingLen - 1)
		}
		if len(explicitNonce) > 0 {
			c.SetIV(explicitNonce)
		}
		c.CryptBlocks(dst, dst)
	default:
		panic("unknown cipher type")
	}

	n := len(record) - recordHeaderLen
	record[3] = byte(n >> 8)
	record[4] = byte(n)
	hc.incSeq()

	return record, nil
}

type RecordHeaderError struct {
	Msg string
	RecordHeader [5]byte
	Conn net.Conn
}

func (e RecordHeaderError) Error() string { return "tls: " + e.Msg }

func (c *Conn) newRecordHeaderError(conn net.Conn, msg string) (err RecordHeaderError) {
	err.Msg = msg
	err.Conn = conn
	copy(err.RecordHeader[:], c.rawInput.Bytes())
	return err
}

func (c *Conn) readRecord() error {
	return c.readRecordOrCCS(false)
}

func (c *Conn) readChangeCipherSpec() error {
	return c.readRecordOrCCS(true)
}

func xorWithMac(record []byte, mac []byte) {
	lenXor := len(mac)
	if len(record) < lenXor {
		lenXor = len(record)
	}
	for i := 0; i < lenXor; i += 1 {
		record[i] = record[i] ^ mac[i]
	}
}

func (c *Conn) extractRestlsAppData(record []byte) ([]byte, restlsCommand, error) {
	if recordType(record[0]) != recordTypeApplicationData {
		debugf(c, "recordType(record[0]) != recordTypeApplicationData\n")
		return nil, nil, alertUnexpectedMessage
	}
	if len(record) < restlsAppDataOffset {
		debugf(c, "len(record) < restlsAppDataOffset\n")
		return nil, nil, alertBadRecordMAC
	}

	header := record[:recordHeaderLen]
	if c.restls12WithGCM && !c.restls12GCMServerDisableCtr {
		if len(record) < recordHeaderLen+8+restlsAppDataAuthHeaderLength {
			return nil, nil, alertBadRecordMAC
		}
		nonce := binary.BigEndian.Uint64(record[recordHeaderLen:])
		if nonce != c.restlsToClientCounter+1 {
			debugf(c, "nonce != c.restlsToClientCounter+1\n")
			return nil, nil, alertBadRecordMAC
		} else {
			header = record[:recordHeaderLen+8]
			record = record[recordHeaderLen+8:]
		}
	} else {
		record = record[recordHeaderLen:]
	}

	hmacAuth := c.restlsAuthHeaderHash(true)
	hmacAuth.Write(header)
	hmacAuth.Write(record[restlsAppDataLenOffset:])
	authMac := hmacAuth.Sum(nil)[:restlsAppDataMACLength]
	for i, m := range authMac {
		if m != record[i] {
			debugf(c, "extractRestlsAppData: bad authMac, expect %v, actual %v, to_client: %d\n", authMac, record[:+restlsAppDataMACLength], c.restlsToClientCounter)
			return nil, nil, alertBadRecordMAC
		}
	}
	hmacMask := c.restlsAuthHeaderHash(true)
	sampleSize := 32
	if sampleSize > len(record[restlsAppDataOffset:]) {
		sampleSize = len(record[restlsAppDataOffset:])
	}
	hmacMask.Write(record[restlsAppDataOffset : restlsAppDataOffset+sampleSize])
	mask := hmacMask.Sum(nil)[:restlsMaskLength]
	xorWithMac(record[restlsAppDataLenOffset:], mask)
	dataLen := int(binary.BigEndian.Uint16(record[restlsAppDataLenOffset:]))
	command, err := parseCommand(record[restlsAppDataLenOffset+2:])
	if err != nil {
		return nil, nil, alertBadRecordMAC
	}
	if dataLen > len(record)-restlsAppDataOffset {
		return nil, nil, alertBadRecordMAC
	}
	data := record[restlsAppDataOffset : restlsAppDataOffset+dataLen]
	debugf(c, "extractRestlsAppData: lengthMask: %v, recordLen: %v, dataLen: %v, authMac: %v, to_client: %d\n", mask, len(record), dataLen, authMac, c.restlsToClientCounter)
	return data, command, nil
}

func (c *Conn) handleRestlsCommand(command restlsCommand, sent bool) {
	if command == nil {
		return
	}
	switch command := command.(type) {
	case ActResponse:
		if sent {
			if command == 0 {
				return
			}
			command -= 1
		}
		for i := 0; i < int(command); i++ {
			c.Write(restlsRandomResponseMagic)
		}
	case ActNoop:
		return
	default:
		panic("invalid command")
	}
}

func (c *Conn) readRecordOrCCS(expectChangeCipherSpec bool) error {
	if c.in.err != nil {
		return c.in.err
	}
	handshakeComplete := c.isHandshakeComplete.Load()

	if c.input.Len() != 0 {
		return c.in.setErrorLocked(errors.New("tls: internal error: attempted to read record with pending application data"))
	}
	c.input.Reset(nil)

	if c.quic != nil {
		return c.in.setErrorLocked(errors.New("tls: internal error: attempted to read record with QUIC transport"))
	}

	if err := c.readFromUntil(c.conn, recordHeaderLen); err != nil {
		if err == io.ErrUnexpectedEOF && c.rawInput.Len() == 0 {
			err = io.EOF
		}
		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			c.in.setErrorLocked(err)
		}
		return err
	}
	hdr := c.rawInput.Bytes()[:recordHeaderLen]
	typ := recordType(hdr[0])

	if !handshakeComplete && typ == 0x80 {
		c.sendAlert(alertProtocolVersion)
		return c.in.setErrorLocked(c.newRecordHeaderError(nil, "unsupported SSLv2 handshake received"))
	}

	vers := uint16(hdr[1])<<8 | uint16(hdr[2])
	expectedVers := c.vers
	if expectedVers == VersionTLS13 {
		expectedVers = VersionTLS12
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	if c.haveVers && vers != expectedVers {
		c.sendAlert(alertProtocolVersion)
		msg := fmt.Sprintf("received record with version %x when expecting version %x", vers, expectedVers)
		return c.in.setErrorLocked(c.newRecordHeaderError(nil, msg))
	}
	if !c.haveVers {
		if (typ != recordTypeAlert && typ != recordTypeHandshake) || vers >= 0x1000 {
			return c.in.setErrorLocked(c.newRecordHeaderError(c.conn, "first record does not look like a TLS handshake"))
		}
	}
	if c.vers == VersionTLS13 && n > maxCiphertextTLS13 || n > maxCiphertext {
		c.sendAlert(alertRecordOverflow)
		msg := fmt.Sprintf("oversized record received with length %d", n)
		return c.in.setErrorLocked(c.newRecordHeaderError(nil, msg))
	}
	if err := c.readFromUntil(c.conn, recordHeaderLen+n); err != nil {
		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			c.in.setErrorLocked(err)
		}
		return err
	}

	record := c.rawInput.Next(recordHeaderLen + n)
	var data []byte
	var err error
	var command restlsCommand = ActNoop{}
	if backupCipher := c.in.restlsPlugin.expectServerAuth(typ); backupCipher != nil {
		hmac := RestlsHmac(c.config.RestlsSecret)
		hmac.Write(c.serverRandom)
		serverRandomMac := hmac.Sum(nil)
		recordCopy := append([]byte(nil), record...)
		if c.restls12WithGCM && len(recordCopy) >= recordHeaderLen+8 && binary.BigEndian.Uint64(recordCopy[recordHeaderLen:recordHeaderLen+8]) == 0 {
			debugf(c, "restls12WithGCM record: %v\n", recordCopy)
			xorWithMac(recordCopy[recordHeaderLen+8:], serverRandomMac[:restlsHandshakeMACLength])
			debugf(c, "restls12WithGCM record (recovered)): %v\n", recordCopy)
		} else {
			debugf(c, "restls12GCMServerDisableCtr\n")
			c.restls12GCMServerDisableCtr = true
			xorWithMac(recordCopy[recordHeaderLen:], serverRandomMac[:restlsHandshakeMACLength])
		}

		data, typ, err = c.in.decrypt(recordCopy)
		if err != nil {
			debugf(c, "restls: readRecordOrCCS auth failed, use backup cipher; serverRandomMac %v, %v\n", serverRandomMac, err)
			c.in.cipher = backupCipher
			data, typ, err = c.in.decrypt(record)
		} else {
			debugf(c, "restls: readRecordOrCCS authed\n")
			c.restlsAuthed = true
		}
		c.in.nextCipher = nil
		debugf(c, "c.handleRestlsCommand returned\n")
	} else if handshakeComplete && c.restlsAuthed {
		if typ == recordTypeAlert {
			data = []byte{02, 20}
		} else {
			data, command, err = c.extractRestlsAppData(record)
		}
		if err != nil {
			if c.restls12WithGCM && !c.restls12GCMServerDisableCtr {
				c.restlsToClientRealRecordCounter += 1
				binary.BigEndian.PutUint64(record[recordHeaderLen:], c.restlsToClientRealRecordCounter)
			}
			data, typ, err = c.in.decrypt(record)
			debugf(c, "message from tls: %v %v %v\n", typ, data, err)
			if typ == recordTypeApplicationData {
				data = nil
			}
			c.restlsToClientCounter += 1
		} else {
			n := 0
			if c.restlsWritePending.Swap(false) {
				debugf(c, "restls unblock writers, len %d\n", len(data))
				n, err = c.Write([]byte{})
				if err != nil {
					fmt.Printf("n, err = c.Write([]byte{}) %v\n", err)
					err = alertInternalError
				}
			}
			c.restlsToClientCounter += 1
			c.handleRestlsCommand(command, n > 0)
		}
		debugf(c, "c.handleRestlsCommand returned\n")
	} else {
		data, typ, err = c.in.decrypt(record)
	}
	if err != nil {
		return c.in.setErrorLocked(c.sendAlert(err.(alert)))
	}
	if len(data) > maxPlaintext {
		return c.in.setErrorLocked(c.sendAlert(alertRecordOverflow))
	}

	if c.in.cipher == nil && typ == recordTypeApplicationData {
		return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}

	if typ != recordTypeAlert && typ != recordTypeChangeCipherSpec && len(data) > 0 {
		c.retryCount = 0
	}

	if c.vers == VersionTLS13 && typ != recordTypeHandshake && c.hand.Len() > 0 {
		return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}

	switch typ {
	default:
		return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))

	case recordTypeAlert:
		if c.quic != nil {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		if len(data) != 2 {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		if alert(data[1]) == alertCloseNotify {
			return c.in.setErrorLocked(io.EOF)
		}
		if c.vers == VersionTLS13 {
			return c.in.setErrorLocked(&net.OpError{Op: "remote error", Err: alert(data[1])})
		}
		switch data[0] {
		case alertLevelWarning:
			return c.retryReadRecord(expectChangeCipherSpec)
		case alertLevelError:
			return c.in.setErrorLocked(&net.OpError{Op: "remote error", Err: alert(data[1])})
		default:
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}

	case recordTypeChangeCipherSpec:
		if len(data) != 1 || data[0] != 1 {
			return c.in.setErrorLocked(c.sendAlert(alertDecodeError))
		}
		if c.hand.Len() > 0 {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		if c.vers == VersionTLS13 && !handshakeComplete {
			return c.retryReadRecord(expectChangeCipherSpec)
		}
		if !expectChangeCipherSpec {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		if err := c.in.changeCipherSpec(); err != nil {
			return c.in.setErrorLocked(c.sendAlert(err.(alert)))
		}

	case recordTypeApplicationData:
		if !handshakeComplete || expectChangeCipherSpec {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		if len(data) == 0 {
			return c.retryReadRecord(expectChangeCipherSpec)
		}
		c.input.Reset(data)

	case recordTypeHandshake:
		if len(data) == 0 || expectChangeCipherSpec {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		c.hand.Write(data)
	}

	return nil
}

func (c *Conn) retryReadRecord(expectChangeCipherSpec bool) error {
	c.retryCount++
	if c.retryCount > maxUselessRecords {
		c.sendAlert(alertUnexpectedMessage)
		return c.in.setErrorLocked(errors.New("tls: too many ignored records"))
	}
	return c.readRecordOrCCS(expectChangeCipherSpec)
}

type atLeastReader struct {
	R io.Reader
	N int64
}

func (r *atLeastReader) Read(p []byte) (int, error) {
	if r.N <= 0 {
		return 0, io.EOF
	}
	n, err := r.R.Read(p)
	r.N -= int64(n)
	if r.N > 0 && err == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	if r.N <= 0 && err == nil {
		return n, io.EOF
	}
	return n, err
}

func (c *Conn) readFromUntil(r io.Reader, n int) error {
	if c.rawInput.Len() >= n {
		return nil
	}
	needs := n - c.rawInput.Len()
	c.rawInput.Grow(needs + bytes.MinRead)
	_, err := c.rawInput.ReadFrom(&atLeastReader{r, int64(needs)})
	return err
}

func (c *Conn) sendAlertLocked(err alert) error {
	if c.quic != nil {
		return c.out.setErrorLocked(&net.OpError{Op: "local error", Err: err})
	}

	switch err {
	case alertNoRenegotiation, alertCloseNotify:
		c.tmp[0] = alertLevelWarning
	default:
		c.tmp[0] = alertLevelError
	}
	c.tmp[1] = byte(err)

	_, writeErr := c.writeRecordLocked(recordTypeAlert, c.tmp[0:2])
	if err == alertCloseNotify {
		return writeErr
	}

	return c.out.setErrorLocked(&net.OpError{Op: "local error", Err: err})
}

func (c *Conn) sendAlert(err alert) error {
	c.out.Lock()
	defer c.out.Unlock()
	return c.sendAlertLocked(err)
}

const (
	tcpMSSEstimate = 1208

	recordSizeBoostThreshold = 128 * 1024
)

func (c *Conn) maxPayloadSizeForWrite(typ recordType) int {
	if c.config.DynamicRecordSizingDisabled || typ != recordTypeApplicationData {
		return maxPlaintext
	}

	if c.bytesSent >= recordSizeBoostThreshold {
		return maxPlaintext
	}

	payloadBytes := tcpMSSEstimate - recordHeaderLen - c.out.explicitNonceLen()
	if c.out.cipher != nil {
		switch ciph := c.out.cipher.(type) {
		case cipher.Stream:
			payloadBytes -= c.out.mac.Size()
		case cipher.AEAD:
			payloadBytes -= ciph.Overhead()
		case cbcMode:
			blockSize := ciph.BlockSize()
			payloadBytes = (payloadBytes & ^(blockSize - 1)) - 1
			payloadBytes -= c.out.mac.Size()
		default:
			panic("unknown cipher type")
		}
	}
	if c.vers == VersionTLS13 {
		payloadBytes--
	}

	pkt := c.packetsSent
	c.packetsSent++
	if pkt > 1000 {
		return maxPlaintext
	}

	n := payloadBytes * int(pkt+1)
	if n > maxPlaintext {
		n = maxPlaintext
	}
	return n
}

func (c *Conn) write(data []byte) (int, error) {
	if c.buffering {
		c.sendBuf = append(c.sendBuf, data...)
		return len(data), nil
	}

	n, err := c.conn.Write(data)
	c.bytesSent += int64(n)
	return n, err
}

func (c *Conn) flush() (int, error) {
	if len(c.sendBuf) == 0 {
		return 0, nil
	}

	n, err := c.conn.Write(c.sendBuf)
	c.bytesSent += int64(n)
	c.sendBuf = nil
	c.buffering = false
	return n, err
}

var outBufPool = sync.Pool{
	New: func() any {
		return new([]byte)
	},
}

func (c *Conn) writeRecordLocked(typ recordType, data []byte) (int, error) {
	if c.quic != nil {
		if typ != recordTypeHandshake {
			return 0, errors.New("tls: internal error: sending non-handshake message to QUIC transport")
		}
		c.quicWriteCryptoData(c.out.level, data)
		if !c.buffering {
			if _, err := c.flush(); err != nil {
				return 0, err
			}
		}
		return len(data), nil
	}

	outBufPtr := outBufPool.Get().(*[]byte)
	outBuf := *outBufPtr
	defer func() {
		*outBufPtr = outBuf
		outBufPool.Put(outBufPtr)
	}()

	var n int
	for len(data) > 0 {
		m := len(data)
		if maxPayload := c.maxPayloadSizeForWrite(typ); m > maxPayload {
			m = maxPayload
		}

		_, outBuf = sliceForAppend(outBuf[:0], recordHeaderLen)
		outBuf[0] = byte(typ)
		vers := c.vers
		if vers == 0 {
			vers = VersionTLS10
		} else if vers == VersionTLS13 {
			vers = VersionTLS12
		}
		outBuf[1] = byte(vers >> 8)
		outBuf[2] = byte(vers)
		outBuf[3] = byte(m >> 8)
		outBuf[4] = byte(m)

		var err error
		outBuf, err = c.out.encrypt(outBuf, data[:m], c.config.rand())
		if err != nil {
			return n, err
		}
		c.out.restlsPlugin.captureClientFinished(outBuf)
		if _, err := c.write(outBuf); err != nil {
			return n, err
		}
		n += m
		data = data[m:]
	}

	if typ == recordTypeChangeCipherSpec && c.vers != VersionTLS13 {
		if err := c.out.changeCipherSpec(); err != nil {
			return n, c.sendAlertLocked(err.(alert))
		}
	}

	return n, nil
}

func (c *Conn) writeHandshakeRecord(msg handshakeMessage, transcript transcriptHash) (int, error) {
	c.out.Lock()
	defer c.out.Unlock()

	data, err := msg.marshal()
	if err != nil {
		return 0, err
	}
	if transcript != nil {
		transcript.Write(data)
	}

	return c.writeRecordLocked(recordTypeHandshake, data)
}

func (c *Conn) writeChangeCipherRecord() error {
	c.out.Lock()
	defer c.out.Unlock()
	_, err := c.writeRecordLocked(recordTypeChangeCipherSpec, []byte{1})
	return err
}

func (c *Conn) readHandshakeBytes(n int) error {
	if c.quic != nil {
		return c.quicReadHandshakeBytes(n)
	}
	for c.hand.Len() < n {
		if err := c.readRecord(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) readHandshake(transcript transcriptHash) (any, error) {
	if err := c.readHandshakeBytes(4); err != nil {
		return nil, err
	}
	data := c.hand.Bytes()
	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if n > maxHandshake {
		c.sendAlertLocked(alertInternalError)
		return nil, c.in.setErrorLocked(fmt.Errorf("tls: handshake message of length %d bytes exceeds maximum of %d bytes", n, maxHandshake))
	}
	if err := c.readHandshakeBytes(4 + n); err != nil {
		return nil, err
	}
	data = c.hand.Next(4 + n)
	return c.unmarshalHandshakeMessage(data, transcript)
}

func (c *Conn) unmarshalHandshakeMessage(data []byte, transcript transcriptHash) (handshakeMessage, error) {
	var m handshakeMessage
	switch data[0] {
	case typeHelloRequest:
		m = new(helloRequestMsg)
	case typeClientHello:
		m = new(clientHelloMsg)
	case typeServerHello:
		m = new(serverHelloMsg)
	case typeNewSessionTicket:
		if c.vers == VersionTLS13 {
			m = new(newSessionTicketMsgTLS13)
		} else {
			m = new(newSessionTicketMsg)
		}
	case typeCertificate:
		if c.vers == VersionTLS13 {
			m = new(certificateMsgTLS13)
		} else {
			m = new(certificateMsg)
		}
	case typeCertificateRequest:
		if c.vers == VersionTLS13 {
			m = new(certificateRequestMsgTLS13)
		} else {
			m = &certificateRequestMsg{
				hasSignatureAlgorithm: c.vers >= VersionTLS12,
			}
		}
	case typeCertificateStatus:
		m = new(certificateStatusMsg)
	case typeServerKeyExchange:
		m = new(serverKeyExchangeMsg)
	case typeServerHelloDone:
		m = new(serverHelloDoneMsg)
	case typeClientKeyExchange:
		m = new(clientKeyExchangeMsg)
	case typeCertificateVerify:
		m = &certificateVerifyMsg{
			hasSignatureAlgorithm: c.vers >= VersionTLS12,
		}
	case typeFinished:
		m = new(finishedMsg)
	case typeEndOfEarlyData:
		m = new(endOfEarlyDataMsg)
	case typeKeyUpdate:
		m = new(keyUpdateMsg)
	default:
		var err error
		m, err = c.utlsHandshakeMessageType(data[0])
		if err == nil {
			break
		}
		return nil, c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}

	data = append([]byte(nil), data...)

	if !m.unmarshal(data) {
		return nil, c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}

	if transcript != nil {
		transcript.Write(data)
	}

	return m, nil
}

var (
	errShutdown = errors.New("tls: protocol is shutdown")
)

func (c *Conn) restlsAuthHeaderHash(isToClient bool) hash.Hash {
	hmac := RestlsHmac(c.config.RestlsSecret)
	hmac.Write(c.serverRandom)
	counterBytes := make([]byte, 8)
	if isToClient {
		hmac.Write([]byte("server-to-client"))
		binary.BigEndian.PutUint64(counterBytes, c.restlsToClientCounter)
	} else {
		hmac.Write([]byte("client-to-server"))
		binary.BigEndian.PutUint64(counterBytes, c.restlsToServerCounter)
	}
	hmac.Write(counterBytes)
	return hmac
}

func (c *Conn) writePadding(paddingLen int, outBuf []byte) ([]byte, error) {
	outBuf, padding := sliceForAppend(outBuf, paddingLen)
	_, err := rand.Read(padding)
	if err != nil {
		return nil, err
	}
	return outBuf, nil
}

func (c *Conn) write0x17AuthHeader(paddingLen int, dataLen int, command restlsCommand, outBuf []byte) error {
	restlsHeaderOffset := len(outBuf) - paddingLen - dataLen - restlsAppDataAuthHeaderLength
	header := outBuf[:restlsHeaderOffset]
	outBuf = outBuf[restlsHeaderOffset:]
	sampleSize := 32
	if sampleSize > len(outBuf[restlsAppDataOffset:]) {
		sampleSize = len(outBuf[restlsAppDataOffset:])
	}
	hmacMask := c.restlsAuthHeaderHash(false)
	_, err := hmacMask.Write(outBuf[restlsAppDataOffset : restlsAppDataOffset+sampleSize])
	if err != nil {
		return err
	}
	mask := hmacMask.Sum(nil)[:restlsMaskLength]
	dataLenBytes := outBuf[restlsAppDataLenOffset : restlsAppDataLenOffset+2]
	binary.BigEndian.PutUint16(dataLenBytes, uint16(dataLen))
	commandBytes := command.toBytes()
	copy(outBuf[restlsAppDataLenOffset+2:], commandBytes[:])
	xorWithMac(outBuf[restlsAppDataLenOffset:], mask)
	hmacAuth := c.restlsAuthHeaderHash(false)
	if clientFinished := c.out.restlsPlugin.takeClientFinished(); clientFinished != nil {
		debugf(c, "writing clientFinished %v\n", clientFinished)
		hmacAuth.Write(clientFinished)
	}
	hmacAuth.Write(header)
	hmacAuth.Write(outBuf[restlsAppDataLenOffset:])
	authMac := hmacAuth.Sum(nil)[:restlsAppDataMACLength]
	debugf(c, "lengthMask: %v, authMac: %v, to_server: %d\n", mask, authMac, c.restlsToServerCounter)
	copy(outBuf[:restlsAppDataMACLength], authMac)
	return nil
}

func (c *Conn) actAccordingToScript(data []byte) (int, int, int, restlsCommand) {
	paddingLen := 0
	dataLen := len(data)
	var command restlsCommand = ActNoop{}
	if c.restlsToServerCounter < uint64(len(c.config.RestlsScript)) {
		line := c.config.RestlsScript[c.restlsToServerCounter]
		dataLen = line.targetLen.Len()
		command = line.command
	}
	if dataLen == 0 {
		paddingLen = 19 + rand.Intn(100)
	}
	if len(data) < dataLen {
		paddingLen = dataLen - len(data)
		dataLen = len(data)
	}
	headerLen := restlsAppDataAuthHeaderLength
	if c.restls12WithGCM {
		headerLen += 8
	}
	payloadLen := dataLen + paddingLen + headerLen
	if payloadLen > maxPlaintext {
		payloadLen = maxPlaintext
	}
	dataLen = payloadLen - headerLen - paddingLen
	if dataLen < 0 {
		panic("target length is too large")
	}
	return payloadLen, dataLen, paddingLen, command
}

func (c *Conn) writeRestlsApplicationRecord(dataNew []byte) (int, error) {
	outBufPtr := outBufPool.Get().(*[]byte)
	outBuf := *outBufPtr
	defer func() {
		*outBufPtr = outBuf
		outBufPool.Put(outBufPtr)
	}()
	fakeResponse := false
	if bytes.Equal(dataNew, restlsRandomResponseMagic) {
		debugf(c, "writeRestls writing random response\n")
		fakeResponse = true
		dataNew = []byte{}
		c.restlsWritePending.Store(false)
	}

	if c.restlsWritePending.Load() {
		c.restlsSendBuf = append(c.restlsSendBuf, dataNew...)
		return len(dataNew), nil
	}

	var data []byte
	if len(c.restlsSendBuf) > 0 {
		c.restlsSendBuf = append(c.restlsSendBuf, dataNew...)
		data = c.restlsSendBuf
	} else {
		data = dataNew
	}

	var n int
	for len(data) > 0 || fakeResponse {
		payloadLen, dataLen, paddingLen, command := c.actAccordingToScript(data)
		debugf(c, "writeRestls payloadLen %d, dataLen %d, paddingLen %d, command %v, dataSize %d\n", payloadLen, dataLen, paddingLen, command, len(data))
		if payloadLen == 0 {
			return 0, nil
		}
		headersLength := recordHeaderLen + restlsAppDataAuthHeaderLength
		if c.restls12WithGCM {
			headersLength += 8
		}
		_, outBuf = sliceForAppend(outBuf[:0], headersLength)
		outBuf[0] = byte(recordTypeApplicationData)
		vers := VersionTLS12
		outBuf[1] = byte(vers >> 8)
		outBuf[2] = byte(vers)
		outBuf[3] = byte(payloadLen >> 8)
		outBuf[4] = byte(payloadLen)

		if c.restls12WithGCM {
			binary.BigEndian.PutUint64(outBuf[recordHeaderLen:], c.restlsToServerCounter+1)
		}
		outBuf = append(outBuf, data[:dataLen]...)
		var err error
		if outBuf, err = c.writePadding(paddingLen, outBuf); err != nil {
			debugf(c, "writePadding failed %v", err)
			return n, err
		}
		if err = c.write0x17AuthHeader(paddingLen, dataLen, command, outBuf); err != nil {
			debugf(c, "write0x17AuthHeader failed %v", err)
			return n, err
		}
		if command.needInterrupt() && !fakeResponse {
			c.restlsWritePending.Store(true)
		}
		if _, err = c.write(outBuf); err != nil {
			debugf(c, "writeRestls c.write failed %v", err)
			return n, err
		}
		c.restlsToServerCounter += 1
		n += payloadLen
		data = data[dataLen:]
		if command.needInterrupt() && !fakeResponse {
			debugf(c, "restls write blocked, remaining %d\n", len(data))
			break
		}
		fakeResponse = false
	}

	if len(data) > 0 {
		if len(c.restlsSendBuf) < len(data) {
			if len(c.restlsSendBuf) > 0 {
				panic("unexpected situation")
			}
			c.restlsSendBuf = append(c.restlsSendBuf, data...)
		} else {
			copy(c.restlsSendBuf, data)
		}
	}
	c.restlsSendBuf = c.restlsSendBuf[:len(data)]

	return len(dataNew), nil
}

func (c *Conn) Write(b []byte) (int, error) {
	for {
		x := c.activeCall.Load()
		if x&1 != 0 {
			return 0, net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x+2) {
			break
		}
	}
	defer c.activeCall.Add(-2)

	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.out.Lock()
	defer c.out.Unlock()

	if err := c.out.err; err != nil {
		return 0, err
	}

	if !c.isHandshakeComplete.Load() {
		return 0, alertInternalError
	}

	if c.closeNotifySent {
		return 0, errShutdown
	}


	var m int
	if len(b) > 1 && c.vers == VersionTLS10 {
		if _, ok := c.out.cipher.(cipher.BlockMode); ok {
			n, err := c.writeRecordLocked(recordTypeApplicationData, b[:1])
			if err != nil {
				return n, c.out.setErrorLocked(err)
			}
			m, b = 1, b[1:]
		}
	}

	debugf(c, "c.restlsAuthed %v\n", c.restlsAuthed)
	if c.restlsAuthed {
		n, err := c.writeRestlsApplicationRecord(b)
		return n, c.out.setErrorLocked(err)
	}

	n, err := c.writeRecordLocked(recordTypeApplicationData, b)
	return n + m, c.out.setErrorLocked(err)
}

func (c *Conn) handleRenegotiation() error {
	if c.vers == VersionTLS13 {
		return errors.New("tls: internal error: unexpected renegotiation")
	}

	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	helloReq, ok := msg.(*helloRequestMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(helloReq, msg)
	}

	if !c.isClient {
		return c.sendAlert(alertNoRenegotiation)
	}

	switch c.config.Renegotiation {
	case RenegotiateNever:
		return c.sendAlert(alertNoRenegotiation)
	case RenegotiateOnceAsClient:
		if c.handshakes > 1 {
			return c.sendAlert(alertNoRenegotiation)
		}
	case RenegotiateFreelyAsClient:
	default:
		c.sendAlert(alertInternalError)
		return errors.New("tls: unknown Renegotiation value")
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	c.isHandshakeComplete.Store(false)
	if c.handshakeErr = c.clientHandshake(context.Background()); c.handshakeErr == nil {
		c.handshakes++
	}
	return c.handshakeErr
}

func (c *Conn) handlePostHandshakeMessage() error {
	if c.vers != VersionTLS13 {
		return c.handleRenegotiation()
	}

	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	c.retryCount++
	if c.retryCount > maxUselessRecords {
		c.sendAlert(alertUnexpectedMessage)
		return c.in.setErrorLocked(errors.New("tls: too many non-advancing records"))
	}

	switch msg := msg.(type) {
	case *newSessionTicketMsgTLS13:
		return c.handleNewSessionTicket(msg)
	case *keyUpdateMsg:
		return c.handleKeyUpdate(msg)
	}
	c.sendAlert(alertUnexpectedMessage)
	return fmt.Errorf("tls: received unexpected handshake message of type %T", msg)
}

func (c *Conn) handleKeyUpdate(keyUpdate *keyUpdateMsg) error {
	if c.quic != nil {
		c.sendAlert(alertUnexpectedMessage)
		return c.in.setErrorLocked(errors.New("tls: received unexpected key update message"))
	}

	cipherSuite := cipherSuiteTLS13ByID(c.cipherSuite)
	if cipherSuite == nil {
		return c.in.setErrorLocked(c.sendAlert(alertInternalError))
	}

	newSecret := cipherSuite.nextTrafficSecret(c.in.trafficSecret)
	c.in.setTrafficSecret(cipherSuite, QUICEncryptionLevelInitial, newSecret)

	if keyUpdate.updateRequested {
		c.out.Lock()
		defer c.out.Unlock()

		msg := &keyUpdateMsg{}
		msgBytes, err := msg.marshal()
		if err != nil {
			return err
		}
		_, err = c.writeRecordLocked(recordTypeHandshake, msgBytes)
		if err != nil {
			c.out.setErrorLocked(err)
			return nil
		}

		newSecret := cipherSuite.nextTrafficSecret(c.out.trafficSecret)
		c.out.setTrafficSecret(cipherSuite, QUICEncryptionLevelInitial, newSecret)
	}

	return nil
}

func (c *Conn) Read(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}

	c.in.Lock()
	defer c.in.Unlock()

	for c.input.Len() == 0 {
		if err := c.readRecord(); err != nil {
			return 0, err
		}
		for c.hand.Len() > 0 {
			if err := c.handlePostHandshakeMessage(); err != nil {
				return 0, err
			}
		}
	}

	n, _ := c.input.Read(b)

	if n != 0 && c.input.Len() == 0 && c.rawInput.Len() > 0 &&
		recordType(c.rawInput.Bytes()[0]) == recordTypeAlert {
		if err := c.readRecord(); err != nil {
			return n, err
		}
	}

	return n, nil
}

func (c *Conn) Close() error {
	var x int32
	for {
		x = c.activeCall.Load()
		if x&1 != 0 {
			return net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x|1) {
			break
		}
	}
	if x != 0 {
		return c.conn.Close()
	}

	var alertErr error
	if c.isHandshakeComplete.Load() {
		if err := c.closeNotify(); err != nil {
			alertErr = fmt.Errorf("tls: failed to send closeNotify alert (but connection was closed anyway): %w", err)
		}
	}

	if err := c.conn.Close(); err != nil {
		return err
	}
	return alertErr
}

var errEarlyCloseWrite = errors.New("tls: CloseWrite called before handshake complete")

func (c *Conn) CloseWrite() error {
	if !c.isHandshakeComplete.Load() {
		return errEarlyCloseWrite
	}

	return c.closeNotify()
}

func (c *Conn) closeNotify() error {
	c.out.Lock()
	defer c.out.Unlock()

	if !c.closeNotifySent {
		c.SetWriteDeadline(time.Now().Add(time.Second * 5))
		c.closeNotifyErr = c.sendAlertLocked(alertCloseNotify)
		c.closeNotifySent = true
		c.SetWriteDeadline(time.Now())
	}
	return c.closeNotifyErr
}

func (c *Conn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

func (c *Conn) HandshakeContext(ctx context.Context) error {
	return c.handshakeContext(ctx)
}

func (c *Conn) handshakeContext(ctx context.Context) (ret error) {
	if c.isHandshakeComplete.Load() {
		return nil
	}

	handshakeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if c.quic != nil {
		c.quic.cancelc = handshakeCtx.Done()
		c.quic.cancel = cancel
	} else if ctx.Done() != nil {
		done := make(chan struct{})
		interruptRes := make(chan error, 1)
		defer func() {
			close(done)
			if ctxErr := <-interruptRes; ctxErr != nil {
				ret = ctxErr
			}
		}()
		go func() {
			select {
			case <-handshakeCtx.Done():
				_ = c.conn.Close()
				interruptRes <- handshakeCtx.Err()
			case <-done:
				interruptRes <- nil
			}
		}()
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if err := c.handshakeErr; err != nil {
		return err
	}
	if c.isHandshakeComplete.Load() {
		return nil
	}

	c.in.Lock()
	defer c.in.Unlock()

	c.handshakeErr = c.handshakeFn(handshakeCtx)
	if c.handshakeErr == nil {
		c.handshakes++
	} else {
		c.flush()
	}

	if c.handshakeErr == nil && !c.isHandshakeComplete.Load() {
		c.handshakeErr = errors.New("tls: internal error: handshake should have had a result")
	}
	if c.handshakeErr != nil && c.isHandshakeComplete.Load() {
		panic("tls: internal error: handshake returned an error but is marked successful")
	}

	if c.quic != nil {
		if c.handshakeErr == nil {
			c.quicHandshakeComplete()
			c.quicSetReadSecret(QUICEncryptionLevelApplication, c.cipherSuite, c.in.trafficSecret)
		} else {
			var a alert
			c.out.Lock()
			if !errors.As(c.out.err, &a) {
				a = alertInternalError
			}
			c.out.Unlock()
			c.handshakeErr = fmt.Errorf("%w%.0w", c.handshakeErr, AlertError(a))
		}
		close(c.quic.blockedc)
		close(c.quic.signalc)
	}

	return c.handshakeErr
}

func (c *Conn) ConnectionState() ConnectionState {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	return c.connectionStateLocked()
}

func (c *Conn) connectionStateLocked() ConnectionState {
	var state ConnectionState
	state.HandshakeComplete = c.isHandshakeComplete.Load()
	state.Version = c.vers
	state.NegotiatedProtocol = c.clientProtocol
	state.DidResume = c.didResume
	state.NegotiatedProtocolIsMutual = true
	state.ServerName = c.serverName
	state.CipherSuite = c.cipherSuite
	state.PeerCertificates = c.peerCertificates
	state.VerifiedChains = c.verifiedChains
	state.SignedCertificateTimestamps = c.scts
	state.OCSPResponse = c.ocspResponse
	if (!c.didResume || c.extMasterSecret) && c.vers != VersionTLS13 {
		if c.clientFinishedIsFirst {
			state.TLSUnique = c.clientFinished[:]
		} else {
			state.TLSUnique = c.serverFinished[:]
		}
	}
	if c.config.Renegotiation != RenegotiateNever {
		state.ekm = noExportedKeyingMaterial
	} else {
		state.ekm = c.ekm
	}
	c.utlsConnectionStateLocked(&state)
	return state
}

func (c *Conn) OCSPResponse() []byte {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	return c.ocspResponse
}

func (c *Conn) VerifyHostname(host string) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	if !c.isClient {
		return errors.New("tls: VerifyHostname called on TLS server connection")
	}
	if !c.isHandshakeComplete.Load() {
		return errors.New("tls: handshake has not yet been performed")
	}
	if len(c.verifiedChains) == 0 {
		return errors.New("tls: handshake did not verify certificate chain")
	}
	return c.peerCertificates[0].VerifyHostname(host)
}
