package sing

import (
	"sync"
	"testing"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
)

type reportingWriter struct{ reported int }

func (w *reportingWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (w *reportingWriter) ReportUnreachable() error { w.reported++; return nil }

type plainWriter struct{}

func (plainWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

func TestAPacketReportsUnreachableThroughItsWriter(t *testing.T) {
	stackWriter := &reportingWriter{}
	writer := bufio.NewNetPacketWriter(stackWriter)
	p := &packet{writer: &writer, mutex: &sync.Mutex{}, buff: buf.New()}
	p.Drop()
	if err := p.ReportUnreachable(); err != nil {
		t.Fatal(err)
	}
	if stackWriter.reported != 1 {
		t.Fatalf("the stack's writer must hear the report, reported=%d", stackWriter.reported)
	}
}

func TestAPacketFromAnInboundWithoutICMPReportsNothing(t *testing.T) {
	writer := bufio.NewNetPacketWriter(plainWriter{})
	p := &packet{writer: &writer, mutex: &sync.Mutex{}, buff: buf.New()}
	if err := p.ReportUnreachable(); err != nil {
		t.Fatal(err)
	}
	var closed network.NetPacketWriter
	p = &packet{writer: &closed, mutex: &sync.Mutex{}, buff: buf.New()}
	if err := p.ReportUnreachable(); err != nil {
		t.Fatal("a writer that is already gone has nothing to report through, which is not an error")
	}
}
