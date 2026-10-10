// Copyright 2023 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"errors"
)

type UQUICConn struct {
	conn *UConn

	sessionTicketSent bool
}

func UQUICClient(config *QUICConfig, clientHelloID ClientHelloID) *UQUICConn {
	return newUQUICConn(UClient(nil, config.TLSConfig, clientHelloID))
}

func newUQUICConn(uconn *UConn) *UQUICConn {
	uconn.quic = &quicState{
		signalc:  make(chan struct{}),
		blockedc: make(chan struct{}),
	}
	uconn.quic.events = uconn.quic.eventArr[:0]
	return &UQUICConn{
		conn: uconn,
	}
}

func (q *UQUICConn) Start(ctx context.Context) error {
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

func (q *UQUICConn) ApplyPreset(p *ClientHelloSpec) error {
	return q.conn.ApplyPreset(p)
}

func (q *UQUICConn) NextEvent() QUICEvent {
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

func (q *UQUICConn) Close() error {
	if q.conn.quic.cancel == nil {
		return nil
	}
	q.conn.quic.cancel()
	for range q.conn.quic.blockedc {
	}
	return q.conn.handshakeErr
}

func (q *UQUICConn) HandleData(level QUICEncryptionLevel, data []byte) error {
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

func (q *UQUICConn) SendSessionTicket(earlyData bool) error {
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
	return quicError(c.sendSessionTicket(earlyData))
}

func (q *UQUICConn) ConnectionState() ConnectionState {
	return q.conn.ConnectionState()
}

func (q *UQUICConn) SetTransportParameters(params []byte) {
	if params == nil {
		params = []byte{}
	}
	q.conn.quic.transportParams = params


	if q.conn.quic.started {
		<-q.conn.quic.signalc
		<-q.conn.quic.blockedc
	}
}

func (uc *UConn) QUICSetReadSecret(level QUICEncryptionLevel, suite uint16, secret []byte) {
	uc.quic.events = append(uc.quic.events, QUICEvent{
		Kind:  QUICSetReadSecret,
		Level: level,
		Suite: suite,
		Data:  secret,
	})
}

func (uc *UConn) QUICSetWriteSecret(level QUICEncryptionLevel, suite uint16, secret []byte) {
	uc.quic.events = append(uc.quic.events, QUICEvent{
		Kind:  QUICSetWriteSecret,
		Level: level,
		Suite: suite,
		Data:  secret,
	})
}

func (uc *UConn) QUICGetTransportParameters() ([]byte, error) {
	if uc.quic.transportParams == nil {
		uc.quic.events = append(uc.quic.events, QUICEvent{
			Kind: QUICTransportParametersRequired,
		})
	}
	for uc.quic.transportParams == nil {
		if err := uc.quicWaitForSignal(); err != nil {
			return nil, err
		}
	}
	return uc.quic.transportParams, nil
}
