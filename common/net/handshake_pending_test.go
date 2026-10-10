package net

import "testing"

type plainHandshakeReporter struct{}

func (plainHandshakeReporter) HandshakeSuccess() error { return nil }

type deferredReporter struct{ pending bool }

func (d deferredReporter) HandshakeSuccess() error      { return nil }
func (d deferredReporter) HandshakeFailure(error) error { return nil }
func (d deferredReporter) HandshakeDeferred() bool      { return d.pending }

type protocolHandshakeConn struct{ reported int }

func (c *protocolHandshakeConn) HandshakeSuccess() error      { c.reported++; return nil }
func (c *protocolHandshakeConn) HandshakeFailure(error) error { c.reported++; return nil }

func TestReportDeferredHandshakeTouchesNothingElse(t *testing.T) {
	other := &protocolHandshakeConn{}
	if err := ReportDeferredHandshake(other, nil); err != nil {
		t.Fatal(err)
	}
	if err := ReportDeferredHandshake(other, errUnreachable{}); err != nil {
		t.Fatal(err)
	}
	if other.reported != 0 {
		t.Fatalf("a connection that merely speaks its own protocol handshake must be left alone, reported=%d", other.reported)
	}
	if err := ReportDeferredHandshake(struct{}{}, nil); err != nil {
		t.Fatal(err)
	}

	deferred := &recordingDeferredConn{}
	if err := ReportDeferredHandshake(deferred, nil); err != nil {
		t.Fatal(err)
	}
	if deferred.success != 1 || deferred.failure != 0 {
		t.Fatalf("a deferred connection must hear the verdict, success=%d failure=%d", deferred.success, deferred.failure)
	}
	if err := ReportDeferredHandshake(deferred, errUnreachable{}); err != nil {
		t.Fatal(err)
	}
	if deferred.failure != 1 {
		t.Fatalf("a failed dial must reach it too, failure=%d", deferred.failure)
	}
}

type errUnreachable struct{}

func (errUnreachable) Error() string { return "no route" }

type recordingDeferredConn struct {
	success int
	failure int
}

func (c *recordingDeferredConn) HandshakeDeferred() bool      { return true }
func (c *recordingDeferredConn) HandshakeSuccess() error      { c.success++; return nil }
func (c *recordingDeferredConn) HandshakeFailure(error) error { c.failure++; return nil }

func TestHandshakePendingOnlyMatchesADeferredConnection(t *testing.T) {
	if HandshakePending(plainHandshakeReporter{}) {
		t.Fatal("implementing HandshakeSuccess is not the same as holding a handshake back")
	}
	if HandshakePending(struct{}{}) {
		t.Fatal("an ordinary connection is never pending")
	}
	if !HandshakePending(deferredReporter{pending: true}) {
		t.Fatal("a connection still holding its handshake back must be reported as pending")
	}
	if HandshakePending(deferredReporter{pending: false}) {
		t.Fatal("once the flow is decided nothing is pending any more")
	}
}

type lazyTransport struct{ connected bool }

func (l lazyTransport) TransportPending() bool { return !l.connected }

type wrapsTransport struct{ inner any }

func (w wrapsTransport) Upstream() any { return w.inner }

func TestTransportPendingSeesThroughWhatWrapsTheTransport(t *testing.T) {
	if !TransportPending(wrapsTransport{wrapsTransport{lazyTransport{}}}) {
		t.Fatal("an unconnected transport under two wrappers is still unconnected")
	}
	if TransportPending(wrapsTransport{lazyTransport{connected: true}}) {
		t.Fatal("once it has connected nothing is pending")
	}
	if TransportPending(struct{}{}) {
		t.Fatal("an ordinary connection has connected by the time it is returned")
	}
}
