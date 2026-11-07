package clash

import (
	"net"
	"testing"

	"github.com/ProjectClash/Clash/tunnel/statistic"
	"github.com/metacubex/sing/common"
)

func TestTheGoStackConnectionOffersWhatSheddingReads(t *testing.T) {
	inner := &sheddableConn{queued: 4096}
	wrapped := &goStreamConn{Conn: inner}

	reporter, ok := common.Cast[statistic.QueuedSendReporter](net.Conn(wrapped))
	if !ok {
		t.Fatal("the bytes the go stack holds for the app cannot be read through goStreamConn")
	}
	if queued, known := reporter.QueuedSendBytes(); !known || queued != 4096 {
		t.Fatalf("queued=%d known=%v, want 4096 and true", queued, known)
	}

	linger, ok := common.Cast[interface{ SetLinger(int) error }](net.Conn(wrapped))
	if !ok {
		t.Fatal("a shed close cannot set the go stack connection's linger, so it closes gracefully")
	}
	_ = linger.SetLinger(0)
	if inner.linger != 0 || !inner.lingerSet {
		t.Fatalf("SetLinger(0) did not reach the go stack connection (linger=%d set=%v)", inner.linger, inner.lingerSet)
	}
}

type sheddableConn struct {
	net.Conn
	queued    int
	linger    int
	lingerSet bool
}

func (c *sheddableConn) QueuedSendBytes() (int, bool) { return c.queued, true }
func (c *sheddableConn) SetLinger(sec int) error {
	c.linger, c.lingerSet = sec, true
	return nil
}
