// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"errors"
	"fmt"
)

type QUICEncryptionLevel int

const (
	QUICEncryptionLevelInitial = QUICEncryptionLevel(iota)
	QUICEncryptionLevelEarly
	QUICEncryptionLevelHandshake
	QUICEncryptionLevelApplication
)

func (l QUICEncryptionLevel) String() string {
	switch l {
	case QUICEncryptionLevelInitial:
		return "Initial"
	case QUICEncryptionLevelEarly:
		return "Early"
	case QUICEncryptionLevelHandshake:
		return "Handshake"
	case QUICEncryptionLevelApplication:
		return "Application"
	default:
		return fmt.Sprintf("QUICEncryptionLevel(%v)", int(l))
	}
}

type QUICConn struct {
	conn *Conn

	sessionTicketSent bool
}

type QUICConfig struct {
	TLSConfig *Config
}

type QUICEventKind int

const (
	QUICNoEvent QUICEventKind = iota

	QUICSetReadSecret
	QUICSetWriteSecret

	QUICWriteData

	QUICTransportParameters

	QUICTransportParametersRequired

	QUICRejectedEarlyData

	QUICHandshakeDone
)

type QUICEvent struct {
	Kind QUICEventKind

	Level QUICEncryptionLevel

	Data []byte

	Suite uint16
}

type quicState struct {
	events    []QUICEvent
	nextEvent int

	eventArr [8]QUICEvent

	started  bool
	signalc  chan struct{}
	blockedc chan struct{}
	cancelc  <-chan struct{}
	cancel   context.CancelFunc

	readbuf []byte

	transportParams []byte
}

func QUICClient(config *QUICConfig) *QUICConn {
	return newQUICConn(Client(nil, config.TLSConfig))
}

func QUICServer(config *QUICConfig) *QUICConn {
	return newQUICConn(Server(nil, config.TLSConfig))
}

func newQUICConn(conn *Conn) *QUICConn {
	conn.quic = &quicState{
		signalc:  make(chan struct{}),
		blockedc: make(chan struct{}),
	}
	conn.quic.events = conn.quic.eventArr[:0]
	return &QUICConn{
		conn: conn,
	}
}

func (q *QUICConn) Start(ctx context.Context) error {
	if q.conn.quic.started {
		return quicError(errors.New("tls: Start called more than once"))
	}
	q.conn.quic.started = true
	if q.conn.config.MinVersion < VersionTLS13 {
		return quicError(errors.New("tls: Config MinVersion must be at least TLS 1.13"))
	}
	go q.conn.HandshakeContext(ctx)
	if _, ok := <-q.conn.quic.blockedc; !ok {
		return q.conn.handshakeErr
	}
	return nil
}

func (q *QUICConn) NextEvent() QUICEvent {
	qs := q.conn.quic
	if last := qs.nextEvent - 1; last >= 0 && len(qs.events[last].Data) > 0 {
		qs.events[last].Data[0] = 0
	}
	if qs.nextEvent >= len(qs.events) {
		qs.events = qs.events[:0]
		qs.nextEvent = 0
		return QUICEvent{Kind: QUICNoEvent}
	}
	e := qs.events[qs.nextEvent]
	qs.events[qs.nextEvent] = QUICEvent{}
	qs.nextEvent++
	return e
}

func (q *QUICConn) Close() error {
	if q.conn.quic.cancel == nil {
		return nil
	}
	q.conn.quic.cancel()
	for range q.conn.quic.blockedc {
	}
	return q.conn.handshakeErr
}

func (q *QUICConn) HandleData(level QUICEncryptionLevel, data []byte) error {
	c := q.conn
	if c.in.level != level {
		return quicError(c.in.setErrorLocked(errors.New("tls: handshake data received at wrong level")))
	}
	c.quic.readbuf = data
	<-c.quic.signalc
	_, ok := <-c.quic.blockedc
	if ok {
		return nil
	}
	c.hand.Write(c.quic.readbuf)
	c.quic.readbuf = nil
	for q.conn.hand.Len() >= 4 && q.conn.handshakeErr == nil {
		b := q.conn.hand.Bytes()
		n := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
		if 4+n < len(b) {
			return nil
		}
		if err := q.conn.handlePostHandshakeMessage(); err != nil {
			return quicError(err)
		}
	}
	if q.conn.handshakeErr != nil {
		return quicError(q.conn.handshakeErr)
	}
	return nil
}

type QUICSessionTicketOptions struct {
	EarlyData bool
}

func (q *QUICConn) SendSessionTicket(opts QUICSessionTicketOptions) error {
	c := q.conn
	if !c.isHandshakeComplete.Load() {
		return quicError(errors.New("tls: SendSessionTicket called before handshake completed"))
	}
	if c.isClient {
		return quicError(errors.New("tls: SendSessionTicket called on the client"))
	}
	if q.sessionTicketSent {
		return quicError(errors.New("tls: SendSessionTicket called multiple times"))
	}
	q.sessionTicketSent = true
	return quicError(c.sendSessionTicket(opts.EarlyData))
}

func (q *QUICConn) ConnectionState() ConnectionState {
	return q.conn.ConnectionState()
}

func (q *QUICConn) SetTransportParameters(params []byte) {
	if params == nil {
		params = []byte{}
	}
	q.conn.quic.transportParams = params
	if q.conn.quic.started {
		<-q.conn.quic.signalc
		<-q.conn.quic.blockedc
	}
}

func quicError(err error) error {
	if err == nil {
		return nil
	}
	var ae AlertError
	if errors.As(err, &ae) {
		return err
	}
	var a alert
	if !errors.As(err, &a) {
		a = alertInternalError
	}
	return fmt.Errorf("%w%.0w", err, AlertError(a))
}

func (c *Conn) quicReadHandshakeBytes(n int) error {
	for c.hand.Len() < n {
		if err := c.quicWaitForSignal(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) quicSetReadSecret(level QUICEncryptionLevel, suite uint16, secret []byte) {
	c.quic.events = append(c.quic.events, QUICEvent{
		Kind:  QUICSetReadSecret,
		Level: level,
		Suite: suite,
		Data:  secret,
	})
}

func (c *Conn) quicSetWriteSecret(level QUICEncryptionLevel, suite uint16, secret []byte) {
	c.quic.events = append(c.quic.events, QUICEvent{
		Kind:  QUICSetWriteSecret,
		Level: level,
		Suite: suite,
		Data:  secret,
	})
}

func (c *Conn) quicWriteCryptoData(level QUICEncryptionLevel, data []byte) {
	var last *QUICEvent
	if len(c.quic.events) > 0 {
		last = &c.quic.events[len(c.quic.events)-1]
	}
	if last == nil || last.Kind != QUICWriteData || last.Level != level {
		c.quic.events = append(c.quic.events, QUICEvent{
			Kind:  QUICWriteData,
			Level: level,
		})
		last = &c.quic.events[len(c.quic.events)-1]
	}
	last.Data = append(last.Data, data...)
}

func (c *Conn) quicSetTransportParameters(params []byte) {
	c.quic.events = append(c.quic.events, QUICEvent{
		Kind: QUICTransportParameters,
		Data: params,
	})
}

func (c *Conn) quicGetTransportParameters() ([]byte, error) {
	if c.quic.transportParams == nil {
		c.quic.events = append(c.quic.events, QUICEvent{
			Kind: QUICTransportParametersRequired,
		})
	}
	for c.quic.transportParams == nil {
		if err := c.quicWaitForSignal(); err != nil {
			return nil, err
		}
	}
	return c.quic.transportParams, nil
}

func (c *Conn) quicHandshakeComplete() {
	c.quic.events = append(c.quic.events, QUICEvent{
		Kind: QUICHandshakeDone,
	})
}

func (c *Conn) quicRejectedEarlyData() {
	c.quic.events = append(c.quic.events, QUICEvent{
		Kind: QUICRejectedEarlyData,
	})
}

func (c *Conn) quicWaitForSignal() error {
	c.handshakeMutex.Unlock()
	defer c.handshakeMutex.Lock()
	select {
	case c.quic.blockedc <- struct{}{}:
	case <-c.quic.cancelc:
		return c.sendAlertLocked(alertCloseNotify)
	}
	select {
	case c.quic.signalc <- struct{}{}:
		c.hand.Write(c.quic.readbuf)
		c.quic.readbuf = nil
	case <-c.quic.cancelc:
		return c.sendAlertLocked(alertCloseNotify)
	}
	return nil
}
