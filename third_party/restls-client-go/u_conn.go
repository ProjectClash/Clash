// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"strconv"
)

type UConn struct {
	*Conn

	Extensions    []TLSExtension
	ClientHelloID ClientHelloID

	ClientHelloBuilt bool
	HandshakeState   PubClientHandshakeState

	GetSessionID func(ticket []byte) [32]byte

	greaseSeed [ssl_grease_last_index]uint16

	omitSNIExtension bool

	certCompressionAlgs []CertCompressionAlgo
}

func UClient(conn net.Conn, config *Config, clientHelloID ClientHelloID) *UConn {
	if config == nil {
		config = &Config{}
	}
	tlsConn := Conn{conn: conn, config: config, isClient: true}
	handshakeState := PubClientHandshakeState{C: &tlsConn, Hello: &PubClientHelloMsg{}}
	uconn := UConn{Conn: &tlsConn, ClientHelloID: clientHelloID, HandshakeState: handshakeState}
	uconn.HandshakeState.uconn = &uconn
	uconn.handshakeFn = uconn.clientHandshake
	initRestlsPlugin(&uconn.in.restlsPlugin, &uconn.out.restlsPlugin)
	return &uconn
}

func (uconn *UConn) BuildHandshakeState() error {
	if uconn.ClientHelloID == HelloGolang {
		panic("Golang ClientHello is disabled")
		if uconn.ClientHelloBuilt {
			return nil
		}

		hello, ecdheKey, err := uconn.makeClientHello()
		if err != nil {
			return err
		}

		uconn.HandshakeState.Hello = hello.getPublicPtr()
		uconn.HandshakeState.State13.EcdheKey = ecdheKey
		uconn.HandshakeState.C = uconn.Conn
	} else {
		if !uconn.ClientHelloBuilt {
			err := uconn.applyPresetByID(uconn.ClientHelloID)
			if err != nil {
				return err
			}
			if uconn.omitSNIExtension {
				uconn.removeSNIExtension()
			}
		}

		err := uconn.ApplyConfig()
		if err != nil {
			return err
		}
		err = uconn.MarshalClientHello()
		if err != nil {
			return err
		}
	}
	uconn.ClientHelloBuilt = true
	return nil
}

func (uconn *UConn) SetSessionState(session *ClientSessionState) error {
	var sessionTicket []uint8
	if session != nil {
		sessionTicket = session.ticket
		uconn.HandshakeState.Session = session.session
	}
	uconn.HandshakeState.Hello.TicketSupported = true
	uconn.HandshakeState.Hello.SessionTicket = sessionTicket

	for _, ext := range uconn.Extensions {
		st, ok := ext.(*SessionTicketExtension)
		if !ok {
			continue
		}
		st.Session = session
		if session != nil {
			if len(session.SessionTicket()) > 0 {
				if uconn.GetSessionID != nil {
					sid := uconn.GetSessionID(session.SessionTicket())
					uconn.HandshakeState.Hello.SessionId = sid[:]
					return nil
				}
			}
			var sessionID [32]byte
			_, err := io.ReadFull(uconn.config.rand(), sessionID[:])
			if err != nil {
				return err
			}
			uconn.HandshakeState.Hello.SessionId = sessionID[:]
		}
		return nil
	}
	return nil
}

func (uconn *UConn) SetSessionCache(cache ClientSessionCache) {
	uconn.config.ClientSessionCache = cache
	uconn.HandshakeState.Hello.TicketSupported = true
}

func (uconn *UConn) SetClientRandom(r []byte) error {
	if len(r) != 32 {
		return errors.New("Incorrect client random length! Expected: 32, got: " + strconv.Itoa(len(r)))
	} else {
		uconn.HandshakeState.Hello.Random = make([]byte, 32)
		copy(uconn.HandshakeState.Hello.Random, r)
		return nil
	}
}

func (uconn *UConn) SetSNI(sni string) {
	hname := hostnameInSNI(sni)
	uconn.config.ServerName = hname
	for _, ext := range uconn.Extensions {
		sniExt, ok := ext.(*SNIExtension)
		if ok {
			sniExt.ServerName = hname
		}
	}
}

func (uconn *UConn) RemoveSNIExtension() error {
	if uconn.ClientHelloID == HelloGolang {
		return fmt.Errorf("cannot call RemoveSNIExtension on a UConn with a HelloGolang ClientHelloID")
	}
	uconn.omitSNIExtension = true
	return nil
}

func (uconn *UConn) removeSNIExtension() {
	filteredExts := make([]TLSExtension, 0, len(uconn.Extensions))
	for _, e := range uconn.Extensions {
		if _, ok := e.(*SNIExtension); !ok {
			filteredExts = append(filteredExts, e)
		}
	}
	uconn.Extensions = filteredExts
}

func (c *UConn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

func (c *UConn) HandshakeContext(ctx context.Context) error {
	return c.handshakeContext(ctx)
}

func (c *UConn) handshakeContext(ctx context.Context) (ret error) {
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

	if c.isClient {
		err := c.BuildHandshakeState()
		if err != nil {
			return err
		}
	}
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

func (c *UConn) Write(b []byte) (int, error) {
	for {
		x := c.activeCall.Load()
		if x&1 != 0 {
			return 0, net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x+2) {
			defer c.activeCall.Add(-2)
			break
		}
	}

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
	if len(b) > 1 && c.vers <= VersionTLS10 {
		if _, ok := c.out.cipher.(cipher.BlockMode); ok {
			n, err := c.writeRecordLocked(recordTypeApplicationData, b[:1])
			if err != nil {
				return n, c.out.setErrorLocked(err)
			}
			m, b = 1, b[1:]
		}
	}

	if c.restlsAuthed {
		n, err := c.writeRestlsApplicationRecord(b)
		return n, c.out.setErrorLocked(err)
	}

	n, err := c.writeRecordLocked(recordTypeApplicationData, b)
	return n + m, c.out.setErrorLocked(err)
}

func (c *UConn) clientHandshake(ctx context.Context) (err error) {
	hello := c.HandshakeState.Hello.getPrivatePtr()
	defer func() { c.HandshakeState.Hello = hello.getPublicPtr() }()

	sessionIsAlreadySet := c.HandshakeState.Session != nil


	if c.config == nil {
		c.config = defaultConfig()
	}

	c.didResume = false

	if len(c.config.ServerName) == 0 && !c.config.InsecureSkipVerify && len(c.config.InsecureServerNameToVerify) == 0 {
		return errors.New("tls: at least one of ServerName, InsecureSkipVerify or InsecureServerNameToVerify must be specified in the tls.Config")
	}

	nextProtosLength := 0
	for _, proto := range c.config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}

	if nextProtosLength > 0xffff {
		return errors.New("tls: NextProtos values too large")
	}

	if c.handshakes > 0 {
		hello.secureRenegotiation = c.clientFinished[:]
	}

	debugf(c.Conn, "hello.keyShares(private) %v\n", hello.keyShares)
	supportTLS13 := AnyTrue(hello.supportedVersions, func(v uint16) bool {
		return v == VersionTLS13
	})
	if c.config.VersionHint == TLS13Hint && supportTLS13 {
		debugf(c.Conn, "u_conn generateSessionIDForTLS13\n")
		c.generateSessionIDForTLS13(hello)
	}

	session, earlySecret, binderKey, err := c.loadSession(hello)
	if err != nil {
		return err
	}
	if session != nil {
		c.HandshakeState.Session = session
		debugf(c.Conn, "session loaded\n")
		defer func() {
			if err != nil {
				if cacheKey := c.clientSessionCacheKey(); cacheKey != "" {
					c.config.ClientSessionCache.Put(cacheKey, nil)
				}
			}
		}()
	}

	if c.config.VersionHint == TLS12Hint || c.config.VersionHint == TLS13Hint && !supportTLS13 {
		debugf(c.Conn, "c.generateSessionIDForTLS12\n")
		if err := c.generateSessionIDForTLS12(hello); err != nil {
			return err
		}
	}
	if len(hello.sessionTicket) > 0 {
		hello.raw = nil
		if _, err := hello.marshal(); err != nil {
			return err
		}
	} else {
		debugf(c.Conn, "%v, %v, %v\n", c.HandshakeState.Hello.SessionId, hello.sessionId, hello.raw[39:39+32])
		hello.raw = append([]byte(nil), hello.raw...)
		copy(hello.raw[39:], hello.sessionId)
	}

	cacheKey := c.clientSessionCacheKey()
	if c.config.ClientSessionCache != nil && c.config.VersionHint == 0 {
		cs, ok := c.config.ClientSessionCache.Get(cacheKey)
		if !sessionIsAlreadySet && ok {
			err = c.SetSessionState(cs)
			if err != nil {
				return
			}
		}
	}

	if _, err := c.writeHandshakeRecord(hello, nil); err != nil {
		return err
	}

	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}

	if err := c.pickTLSVersion(serverHello); err != nil {
		return err
	}

	c.serverRandom = serverHello.random

	if c.vers == VersionTLS13 {
		hs13 := c.HandshakeState.toPrivate13()
		hs13.serverHello = serverHello
		hs13.hello = hello
		if !sessionIsAlreadySet {
			hs13.earlySecret = earlySecret
			hs13.binderKey = binderKey
		}
		hs13.ctx = ctx
		err = hs13.handshake()
		if handshakeState := hs13.toPublic13(); handshakeState != nil {
			c.HandshakeState = *handshakeState
		}
		return err
	}

	hs12 := c.HandshakeState.toPrivate12()
	hs12.serverHello = serverHello
	hs12.hello = hello
	hs12.ctx = ctx
	err = hs12.handshake()
	if handshakeState := hs12.toPublic12(); handshakeState != nil {
		c.HandshakeState = *handshakeState
	}
	if err != nil {
		return err
	}

	if cacheKey != "" && hs12.session != nil && session != hs12.session {
		hs12cs := &ClientSessionState{
			ticket:  hs12.ticket,
			session: hs12.session,
		}

		c.config.ClientSessionCache.Put(cacheKey, hs12cs)
	}
	return nil
}

func (uconn *UConn) ApplyConfig() error {
	for _, ext := range uconn.Extensions {
		err := ext.writeToUConn(uconn)
		if err != nil {
			return err
		}
	}
	return nil
}

func (uconn *UConn) MarshalClientHello() error {
	hello := uconn.HandshakeState.Hello
	headerLength := 2 + 32 + 1 + len(hello.SessionId) +
		2 + len(hello.CipherSuites)*2 +
		1 + len(hello.CompressionMethods)

	extensionsLen := 0
	var paddingExt *UtlsPaddingExtension
	for _, ext := range uconn.Extensions {
		if pe, ok := ext.(*UtlsPaddingExtension); !ok {
			extensionsLen += ext.Len()
		} else {
			if paddingExt == nil {
				paddingExt = pe
			} else {
				return errors.New("multiple padding extensions!")
			}
		}
	}

	if paddingExt != nil {
		paddingExt.Update(headerLength + 4 + extensionsLen + 2)
		extensionsLen += paddingExt.Len()
	}

	helloLen := headerLength
	if len(uconn.Extensions) > 0 {
		helloLen += 2 + extensionsLen
	}

	helloBuffer := bytes.Buffer{}
	bufferedWriter := bufio.NewWriterSize(&helloBuffer, helloLen+4)

	binary.Write(bufferedWriter, binary.BigEndian, typeClientHello)
	helloLenBytes := []byte{byte(helloLen >> 16), byte(helloLen >> 8), byte(helloLen)}
	binary.Write(bufferedWriter, binary.BigEndian, helloLenBytes)
	binary.Write(bufferedWriter, binary.BigEndian, hello.Vers)

	binary.Write(bufferedWriter, binary.BigEndian, hello.Random)

	binary.Write(bufferedWriter, binary.BigEndian, uint8(len(hello.SessionId)))
	binary.Write(bufferedWriter, binary.BigEndian, hello.SessionId)

	binary.Write(bufferedWriter, binary.BigEndian, uint16(len(hello.CipherSuites)<<1))
	for _, suite := range hello.CipherSuites {
		binary.Write(bufferedWriter, binary.BigEndian, suite)
	}

	binary.Write(bufferedWriter, binary.BigEndian, uint8(len(hello.CompressionMethods)))
	binary.Write(bufferedWriter, binary.BigEndian, hello.CompressionMethods)

	if len(uconn.Extensions) > 0 {
		binary.Write(bufferedWriter, binary.BigEndian, uint16(extensionsLen))
		for _, ext := range uconn.Extensions {
			bufferedWriter.ReadFrom(ext)
		}
	}

	err := bufferedWriter.Flush()
	if err != nil {
		return err
	}

	if helloBuffer.Len() != 4+helloLen {
		return errors.New("utls: unexpected ClientHello length. Expected: " + strconv.Itoa(4+helloLen) +
			". Got: " + strconv.Itoa(helloBuffer.Len()))
	}

	hello.Raw = helloBuffer.Bytes()
	return nil
}

func (uconn *UConn) GetOutKeystream(length int) ([]byte, error) {
	zeros := make([]byte, length)

	if outCipher, ok := uconn.out.cipher.(cipher.AEAD); ok {
		return outCipher.Seal(nil, uconn.out.seq[:], zeros, nil), nil
	}
	return nil, errors.New("could not convert OutCipher to cipher.AEAD")
}

func (uconn *UConn) SetTLSVers(minTLSVers, maxTLSVers uint16, specExtensions []TLSExtension) error {
	if minTLSVers == 0 && maxTLSVers == 0 {
		supportedVersionsExtensionsPresent := 0
		for _, e := range specExtensions {
			switch ext := e.(type) {
			case *SupportedVersionsExtension:
				findVersionsInSupportedVersionsExtensions := func(versions []uint16) (uint16, uint16) {
					minVers := uint16(0)
					maxVers := uint16(0)
					for _, vers := range versions {
						if isGREASEUint16(vers) {
							continue
						}
						if maxVers < vers || maxVers == 0 {
							maxVers = vers
						}
						if minVers > vers || minVers == 0 {
							minVers = vers
						}
					}
					return minVers, maxVers
				}

				supportedVersionsExtensionsPresent += 1
				minTLSVers, maxTLSVers = findVersionsInSupportedVersionsExtensions(ext.Versions)
				if minTLSVers == 0 && maxTLSVers == 0 {
					return fmt.Errorf("SupportedVersions extension has invalid Versions field")
				}
			}
		}
		switch supportedVersionsExtensionsPresent {
		case 0:
			minTLSVers = VersionTLS10
			maxTLSVers = VersionTLS12
		case 1:
		default:
			return fmt.Errorf("uconn.Extensions contains %v separate SupportedVersions extensions",
				supportedVersionsExtensionsPresent)
		}
	}

	if minTLSVers < VersionTLS10 || minTLSVers > VersionTLS13 {
		return fmt.Errorf("uTLS does not support 0x%X as min version", minTLSVers)
	}

	if maxTLSVers < VersionTLS10 || maxTLSVers > VersionTLS13 {
		return fmt.Errorf("uTLS does not support 0x%X as max version", maxTLSVers)
	}

	if uconn.config.ForceTLS12 {
		if maxTLSVers > VersionTLS12 {
			maxTLSVers = VersionTLS12
		}
		if minTLSVers > maxTLSVers {
			return fmt.Errorf("uTLS configured minimum version 0x%X is greater than maximum version 0x%X", minTLSVers, maxTLSVers)
		}
		for _, e := range specExtensions {
			ext, ok := e.(*SupportedVersionsExtension)
			if !ok {
				continue
			}
			versions := ext.Versions[:0]
			hasVersion := false
			for _, vers := range ext.Versions {
				if isGREASEUint16(vers) {
					versions = append(versions, vers)
					continue
				}
				if vers >= minTLSVers && vers <= maxTLSVers {
					versions = append(versions, vers)
					hasVersion = true
				}
			}
			if !hasVersion {
				versions = append(versions, makeSupportedVersions(minTLSVers, maxTLSVers)...)
			}
			ext.Versions = versions
		}
	}

	uconn.HandshakeState.Hello.SupportedVersions = makeSupportedVersions(minTLSVers, maxTLSVers)
	uconn.config.MinVersion = minTLSVers
	uconn.config.MaxVersion = maxTLSVers

	return nil
}

func (uconn *UConn) SetUnderlyingConn(c net.Conn) {
	uconn.Conn.conn = c
}

func (uconn *UConn) GetUnderlyingConn() net.Conn {
	return uconn.Conn.conn
}

func MakeConnWithCompleteHandshake(tcpConn net.Conn, version uint16, cipherSuite uint16, masterSecret []byte, clientRandom []byte, serverRandom []byte, isClient bool) *Conn {
	tlsConn := &Conn{conn: tcpConn, config: &Config{}, isClient: isClient}
	cs := cipherSuiteByID(cipherSuite)
	if cs != nil {
		clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
			keysFromMasterSecret(version, cs, masterSecret, clientRandom, serverRandom,
				cs.macLen, cs.keyLen, cs.ivLen)

		var clientCipher, serverCipher interface{}
		var clientHash, serverHash hash.Hash
		if cs.cipher != nil {
			clientCipher = cs.cipher(clientKey, clientIV, true)
			clientHash = cs.mac(clientMAC)
			serverCipher = cs.cipher(serverKey, serverIV, false)
			serverHash = cs.mac(serverMAC)
		} else {
			clientCipher = cs.aead(clientKey, clientIV)
			serverCipher = cs.aead(serverKey, serverIV)
		}

		if isClient {
			tlsConn.in.prepareCipherSpec(version, serverCipher, serverHash)
			tlsConn.out.prepareCipherSpec(version, clientCipher, clientHash)
		} else {
			tlsConn.in.prepareCipherSpec(version, clientCipher, clientHash)
			tlsConn.out.prepareCipherSpec(version, serverCipher, serverHash)
		}

		tlsConn.isHandshakeComplete.Store(true)
		tlsConn.cipherSuite = cipherSuite
		tlsConn.haveVers = true
		tlsConn.vers = version

		tlsConn.in.changeCipherSpec()
		tlsConn.out.changeCipherSpec()

		tlsConn.in.incSeq()
		tlsConn.out.incSeq()

		return tlsConn
	} else {
		return nil
	}
}

func makeSupportedVersions(minVers, maxVers uint16) []uint16 {
	a := make([]uint16, maxVers-minVers+1)
	for i := range a {
		a[i] = maxVers - uint16(i)
	}
	return a
}

func (c *Conn) utlsHandshakeMessageType(msgType byte) (handshakeMessage, error) {
	switch msgType {
	case utlsTypeCompressedCertificate:
		return new(utlsCompressedCertificateMsg), nil
	case utlsTypeEncryptedExtensions:
		if c.isClient {
			return new(encryptedExtensionsMsg), nil
		} else {
			return new(utlsClientEncryptedExtensionsMsg), nil
		}
	default:
		return nil, c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}
}

func (c *Conn) utlsConnectionStateLocked(state *ConnectionState) {
	state.PeerApplicationSettings = c.utls.peerApplicationSettings
}

type utlsConnExtraFields struct {
	hasApplicationSettings   bool
	peerApplicationSettings  []byte
	localApplicationSettings []byte
}
