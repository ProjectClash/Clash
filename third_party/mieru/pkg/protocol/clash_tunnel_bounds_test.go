package protocol

import (
	"bytes"
	"context"
	"io"
	mrand "math/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
)


const (
	clashTestLimit = 256 << 10
	clashTestHang = 30 * time.Second
)

func clashTestBody(size int) []byte {
	body := make([]byte, size)
	mrand.New(mrand.NewSource(20261111)).Read(body)
	return body
}

func clashTestServe(conn net.Conn, body []byte, sent *atomic.Int64) {
	defer conn.Close()
	var request [1]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return
	}
	switch request[0] {
	case 'd', 'c':
		for offset := 0; offset < len(body); offset += maxPDU {
			end := offset + maxPDU
			if end > len(body) {
				end = len(body)
			}
			n, err := conn.Write(body[offset:end])
			sent.Add(int64(n))
			if err != nil {
				return
			}
		}
		if request[0] == 'd' {
			_, _ = io.Copy(io.Discard, conn)
		}
	case 'e':
		_, _ = io.Copy(conn, conn)
	}
}

func clashTestPair(t *testing.T, transport common.TransportProtocol, body []byte) (client *Mux, sent *atomic.Int64) {
	t.Helper()
	return clashTestPairSharing(t, transport, body, 0)
}

func clashTestPairSharing(t *testing.T, transport common.TransportProtocol, body []byte, factor int) (client *Mux, sent *atomic.Int64) {
	t.Helper()
	var address net.Addr
	switch transport {
	case common.StreamTransport:
		port, err := common.UnusedTCPPort()
		if err != nil {
			t.Fatal(err)
		}
		address = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	case common.PacketTransport:
		port, err := common.UnusedUDPPort()
		if err != nil {
			t.Fatal(err)
		}
		address = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	}
	server := NewMux(false).
		SetServerUsers(users).
		SetEndpoints([]UnderlayProperties{NewUnderlayProperties(1400, transport, address, nil)})
	if err := server.Start(); err != nil {
		t.Fatalf("the server's Start: %v", err)
	}
	sent = new(atomic.Int64)
	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				return
			}
			go clashTestServe(conn, body, sent)
		}
	}()
	client = NewMux(true).
		SetClientUserNamePassword("xiaochitang", cipher.HashPassword([]byte("kuiranbudong"), []byte("xiaochitang"))).
		SetClientMultiplexFactor(factor).
		SetEndpoints([]UnderlayProperties{NewUnderlayProperties(1400, transport, nil, address)})
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, sent
}

func clashTestAsk(t *testing.T, client *Mux, request byte) *Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), clashTestHang)
	defer cancel()
	conn, err := client.DialContext(ctx)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write([]byte{request}); err != nil {
		t.Fatalf("the request byte: %v", err)
	}
	return conn.(*Session)
}

func clashTestHeld(s *Session) int {
	return len(s.recvChan)*maxPDU + clashTestQueued(s)
}

func clashTestQueued(s *Session) int {
	queued := len(s.unreadBuf)
	s.recvQueue.Ascend(func(seg *segment) bool {
		queued += len(seg.payload)
		return true
	})
	return queued
}

func clashTestSettled(t *testing.T, s *Session, done func(held int) bool) int {
	t.Helper()
	deadline := time.Now().Add(clashTestHang)
	last, since := -1, time.Now()
	for time.Now().Before(deadline) {
		held := clashTestHeld(s)
		if held != last {
			last, since = held, time.Now()
		} else if time.Since(since) >= 500*time.Millisecond && done(held) {
			return held
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("what the session holds never settled where it should: %d bytes at the end", last)
	return last
}

type clashTestReader struct {
	session *Session
	piece   int
}

func (r clashTestReader) Read(b []byte) (int, error) {
	if r.piece > 0 && len(b) > r.piece {
		b = b[:r.piece]
	}
	_ = r.session.SetReadDeadline(time.Now().Add(clashTestHang))
	return r.session.Read(b)
}

func clashTestSet[T any](t *testing.T, set func(T) T, value T) {
	t.Helper()
	previous := set(value)
	t.Cleanup(func() { set(previous) })
}

func TestAStreamSessionNobodyReadsHoldsNoMoreThanTheLimit(t *testing.T) {
	body := clashTestBody(8 << 20)
	for _, c := range []struct {
		name  string
		limit int64
	}{
		{"with the limit", clashTestLimit},
		{"as shipped", 0},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			clashTestSet(t, SetStreamReceiveByteLimit, c.limit)
			client, sent := clashTestPair(t, common.StreamTransport, body)
			session := clashTestAsk(t, client, 'd')

			if c.limit == 0 {
				held := clashTestSettled(t, session, func(int) bool { return sent.Load() == int64(len(body)) })
				if held != len(body) {
					t.Fatalf("as shipped the session holds all %d bytes sent: it holds %d", len(body), held)
				}
			} else {
				held := clashTestSettled(t, session, func(held int) bool { return int64(held) >= c.limit })
				if int64(held) > c.limit+maxPDU {
					t.Fatalf("the session holds %d bytes, more than the limit %d and one segment", held, c.limit)
				}
				if tally := session.ReceiveQueuedBytes(); tally != int64(held) {
					t.Fatalf("the session's tally says %d bytes, its queues hold %d", tally, held)
				}
			}

			got := make([]byte, len(body))
			if _, err := io.ReadFull(clashTestReader{session: session, piece: 1000}, got); err != nil {
				t.Fatalf("reading what was sent: %v", err)
			}
			if !bytes.Equal(got, body) {
				t.Fatal("what was read is not what was sent")
			}
			if tally := session.ReceiveQueuedBytes(); tally != 0 {
				t.Fatalf("everything was read and the tally says %d bytes are queued", tally)
			}
		})
	}
}

func TestOneByteIsNotHeldBackUnderTheLimit(t *testing.T) {
	clashTestSet(t, SetStreamReceiveByteLimit, int64(clashTestLimit))
	client, _ := clashTestPair(t, common.StreamTransport, nil)
	session := clashTestAsk(t, client, 'e')
	var one [1]byte
	for i := 0; i < 50; i++ {
		if _, err := session.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(clashTestReader{session: session}, one[:]); err != nil || one[0] != byte(i) {
			t.Fatalf("byte %d came back as %d (%v)", i, one[0], err)
		}
	}
}

func TestWhatAPeerSentBeforeItClosedIsReadToTheEnd(t *testing.T) {
	for _, c := range []struct {
		name string
		size int
		closesUnread bool
	}{
		{"under the limit", clashTestLimit / 2, true},
		{"exactly the limit", clashTestLimit, true},
		{"over the limit", 2 << 20, false},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			body := clashTestBody(c.size)
			clashTestSet(t, SetStreamReceiveByteLimit, int64(clashTestLimit))
			clashTestSet(t, SetReleaseOnApplicationClose, true)
			client, _ := clashTestPair(t, common.StreamTransport, body)
			session := clashTestAsk(t, client, 'c')
			if c.closesUnread {
				select {
				case <-session.closedChan:
				case <-time.After(clashTestHang):
					t.Fatalf("the peer closed after %d bytes and the session, holding %d, never heard", c.size, clashTestHeld(session))
				}
				if queued := clashTestQueued(session); queued != c.size {
					t.Fatalf("closed by its peer, the session has %d of the %d bytes sent in its queue", queued, c.size)
				}
			} else {
				clashTestSettled(t, session, func(held int) bool { return held >= clashTestLimit })
			}

			got, err := io.ReadAll(clashTestReader{session: session, piece: 1000})
			if err != nil {
				t.Fatalf("reading to the peer's close: %v", err)
			}
			if !bytes.Equal(got, body) {
				t.Fatalf("read %d bytes of the %d sent before the close, or not the same ones", len(got), len(body))
			}
		})
	}
}

func TestTheApplicationsSecondCloseDropsWhatWasQueued(t *testing.T) {
	body := clashTestBody(2 << 20)
	for _, c := range []struct {
		name    string
		release bool
		limit   int64
	}{
		{"released, at the limit", true, clashTestLimit},
		{"released, everything queued", true, 0},
		{"as shipped", false, 0},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			clashTestSet(t, SetStreamReceiveByteLimit, c.limit)
			clashTestSet(t, SetReleaseOnApplicationClose, c.release)
			client, sent := clashTestPair(t, common.StreamTransport, body)
			session := clashTestAsk(t, client, 'd')
			if c.limit > 0 {
				clashTestSettled(t, session, func(held int) bool { return int64(held) >= c.limit })
			} else {
				clashTestSettled(t, session, func(int) bool { return sent.Load() == int64(len(body)) })
			}
			before := clashTestQueued(session)

			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			if queued := clashTestQueued(session); queued != before {
				t.Fatalf("closed once by its application, the session has %d of the %d bytes that were queued", queued, before)
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			queued := clashTestQueued(session)
			switch {
			case c.release && (queued != 0 || session.ReceiveQueuedBytes() != 0):
				t.Fatalf("closed again by its application, the session still has %d bytes queued and tallies %d", queued, session.ReceiveQueuedBytes())
			case !c.release && queued != before:
				t.Fatalf("as shipped a closed session keeps its queue: %d bytes before, %d after", before, queued)
			}
		})
	}
}

func TestWhatWasQueuedAtTheFirstCloseIsStillReadToTheEnd(t *testing.T) {
	const size = 100000
	body := clashTestBody(size)
	clashTestSet(t, SetStreamReceiveByteLimit, int64(clashTestLimit))
	clashTestSet(t, SetReleaseOnApplicationClose, true)
	client, sent := clashTestPair(t, common.StreamTransport, body)
	session := clashTestAsk(t, client, 'd')
	clashTestSettled(t, session, func(int) bool { return sent.Load() == size })
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(clashTestReader{session: session, piece: 1000})
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("after the first close, %d of the %d bytes queued were read (%v)", len(got), size, err)
	}
	_ = session.Close()
	if queued := clashTestQueued(session); queued != 0 || session.ReceiveQueuedBytes() != 0 {
		t.Fatalf("read to the end and closed, the session has %d bytes queued and tallies %d", queued, session.ReceiveQueuedBytes())
	}
}

func clashTestInputFails(s *Session) {
	if s.inputHasErr.CompareAndSwap(false, true) {
		close(s.inputErr)
	}
}

func clashTestEnds(t *testing.T, s *Session) (closed, broken int) {
	t.Helper()
	for i := 0; i < 100; i++ {
		_ = s.SetReadDeadline(time.Now().Add(clashTestHang))
		n, err := s.Read(make([]byte, 16))
		switch {
		case n == 0 && err == io.EOF:
			closed++
		case n == 0 && err == io.ErrUnexpectedEOF:
			broken++
		default:
			t.Fatalf("a read at the end: %d bytes, %v", n, err)
		}
	}
	return closed, broken
}

func TestASessionItsApplicationClosedEndsAsClosedWhateverItsInputMeetsAfterwards(t *testing.T) {
	const size = 100000
	body := clashTestBody(size)
	closedSession := func(t *testing.T, failsBeforeClose bool) *Session {
		client, sent := clashTestPair(t, common.StreamTransport, body)
		session := clashTestAsk(t, client, 'd')
		clashTestSettled(t, session, func(int) bool { return sent.Load() == size })
		if failsBeforeClose {
			clashTestInputFails(session)
		}
		if err := session.Close(); err != nil {
			t.Fatal(err)
		}
		clashTestInputFails(session)
		return session
	}
	t.Run("an input error after the close", func(t *testing.T) {
		clashTestSet(t, SetStreamReceiveByteLimit, int64(clashTestLimit))
		clashTestSet(t, SetReleaseOnApplicationClose, true)
		session := closedSession(t, false)
		got, err := io.ReadAll(clashTestReader{session: session, piece: 1000})
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("after the close and the input error, %d of the %d bytes queued were read (%v)", len(got), size, err)
		}
		if closed, broken := clashTestEnds(t, session); broken != 0 {
			t.Fatalf("of 100 reads at the end, %d ended the session as closed and %d as broken", closed, broken)
		}
	})
	t.Run("an input error before the close", func(t *testing.T) {
		clashTestSet(t, SetStreamReceiveByteLimit, int64(clashTestLimit))
		clashTestSet(t, SetReleaseOnApplicationClose, true)
		session := closedSession(t, true)
		for len(session.unreadBuf) > 0 || session.recvQueue.Len() > 0 {
			_ = session.SetReadDeadline(time.Now().Add(clashTestHang))
			if _, err := session.Read(make([]byte, maxPDU)); err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				t.Fatal(err)
			}
		}
		if closed, broken := clashTestEnds(t, session); broken == 0 {
			t.Fatalf("an input error from before the close is no longer told: %d reads ended as closed, %d as broken", closed, broken)
		}
	})
	t.Run("closed by its peer before its application", func(t *testing.T) {
		clashTestSet(t, SetStreamReceiveByteLimit, int64(clashTestLimit))
		clashTestSet(t, SetReleaseOnApplicationClose, true)
		client, sent := clashTestPair(t, common.StreamTransport, body)
		session := clashTestAsk(t, client, 'd')
		clashTestSettled(t, session, func(int) bool { return sent.Load() == size })
		_ = session.closeWithError(nil)
		if err := session.Close(); err != nil {
			t.Fatal(err)
		}
		clashTestInputFails(session)
		for len(session.unreadBuf) > 0 || session.recvQueue.Len() > 0 {
			_ = session.SetReadDeadline(time.Now().Add(clashTestHang))
			if _, err := session.Read(make([]byte, maxPDU)); err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				t.Fatal(err)
			}
		}
		if closed, broken := clashTestEnds(t, session); broken == 0 {
			t.Fatalf("a session its application did not close ends as shipped: %d reads ended as closed, %d as broken", closed, broken)
		}
	})
	t.Run("as shipped", func(t *testing.T) {
		clashTestSet(t, SetStreamReceiveByteLimit, int64(0))
		clashTestSet(t, SetReleaseOnApplicationClose, false)
		session := closedSession(t, false)
		for len(session.unreadBuf) > 0 || session.recvQueue.Len() > 0 {
			_ = session.SetReadDeadline(time.Now().Add(clashTestHang))
			if _, err := session.Read(make([]byte, maxPDU)); err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				t.Fatal(err)
			}
		}
		if closed, broken := clashTestEnds(t, session); broken == 0 || closed == 0 {
			t.Fatalf("as shipped a read at the end picks between the two: %d ended as closed, %d as broken", closed, broken)
		}
	})
}

func TestAClientRecordsNoSegmentItReceives(t *testing.T) {
	for _, c := range []struct {
		transport common.TransportProtocol
		name      string
		cache     interface {
			Clear()
			Sizes() (int, int)
		}
		segments int
		clientsShare int
	}{
		{common.StreamTransport, "stream", streamReplayCache, 64, 2 * 64},
		{common.PacketTransport, "packet", packetReplayCache, 256, 256 * maxPDU / 1400},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			segments := c.segments
			body := clashTestBody(segments * maxPDU)
			download := func(skip bool) (recorded int) {
				previousSkip := SetClientSkipsReplayCache(skip)
				defer SetClientSkipsReplayCache(previousSkip)
				client, _ := clashTestPair(t, c.transport, body)
				c.cache.Clear()
				session := clashTestAsk(t, client, 'c')
				got, err := io.ReadAll(clashTestReader{session: session})
				if err != nil || !bytes.Equal(got, body) {
					t.Fatalf("the download: %d bytes of %d (%v)", len(got), len(body), err)
				}
				current, previous := c.cache.Sizes()
				return current + previous
			}
			shipped, skipped := download(false), download(true)
			if skipped == 0 {
				t.Fatal("skipped, the server recorded nothing either")
			}
			if shipped-skipped < c.clientsShare/2 {
				t.Fatalf("%d records as shipped and %d skipped: the client's own share, at least %d, is still recorded",
					shipped, skipped, c.clientsShare)
			}
			if c.transport == common.StreamTransport && skipped >= segments {
				t.Fatalf("skipped, a stream download of %d segments left %d records: the server was sent a request and a close", segments, skipped)
			}
		})
	}
}

func TestBothTransportsCarryAConversationWithEverySwitchOn(t *testing.T) {
	clashTestSet(t, SetStreamReceiveByteLimit, int64(clashTestLimit))
	clashTestSet(t, SetReleaseOnApplicationClose, true)
	clashTestSet(t, SetClientSkipsReplayCache, true)
	for _, transport := range []common.TransportProtocol{common.StreamTransport, common.PacketTransport} {
		transport := transport
		t.Run(map[common.TransportProtocol]string{common.StreamTransport: "stream", common.PacketTransport: "packet"}[transport], func(t *testing.T) {
			client, _ := clashTestPair(t, transport, nil)
			session := clashTestAsk(t, client, 'e')
			random := mrand.New(mrand.NewSource(7))
			for i := 0; i < 40; i++ {
				payload := make([]byte, random.Intn(3*maxPDU)+1)
				random.Read(payload)
				if _, err := session.Write(payload); err != nil {
					t.Fatalf("round %d: %v", i, err)
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(clashTestReader{session: session}, got); err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("round %d: %d bytes did not come back as sent (%v)", i, len(payload), err)
				}
			}
		})
	}
}

func TestEachSwitchAnswersWhatItWas(t *testing.T) {
	if was := SetStreamReceiveByteLimit(1234); was != 0 {
		t.Fatalf("the limit as shipped is none, it was %d", was)
	}
	if was := SetStreamReceiveByteLimit(0); was != 1234 || StreamReceiveByteLimit() != 0 {
		t.Fatalf("the limit was %d, and is now %d", was, StreamReceiveByteLimit())
	}
	if was := SetStreamReceiveByteLimit(-5); was != 0 || StreamReceiveByteLimit() != 0 {
		t.Fatalf("a negative limit is none: it was %d and is %d", was, StreamReceiveByteLimit())
	}
	if SetClientSkipsReplayCache(true) || !SetClientSkipsReplayCache(false) || ClientSkipsReplayCache() {
		t.Fatal("the replay switch did not answer what it was")
	}
	if SetReleaseOnApplicationClose(true) || !SetReleaseOnApplicationClose(false) || ReleaseOnApplicationClose() {
		t.Fatal("the release switch did not answer what it was")
	}
}

func TestTheProcessCountsWhatItsStreamSessionsHold(t *testing.T) {
	clashTestSet(t, SetReleaseOnApplicationClose, true)
	count := func(want int64, wantSessions int) {
		t.Helper()
		deadline := time.Now().Add(clashTestHang)
		for {
			bytes, sessions := StreamReceiveQueued()
			if bytes == want && sessions == wantSessions {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("the process counts %d bytes in %d sessions, want %d in %d", bytes, sessions, want, wantSessions)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	count(0, 0)

	const size = 100000
	client, sent := clashTestPair(t, common.StreamTransport, clashTestBody(size))
	first, second := clashTestAsk(t, client, 'd'), clashTestAsk(t, client, 'd')
	clashTestSettled(t, second, func(int) bool { return sent.Load() == 2*size })
	count(2*size, 4)

	_ = first.Close()
	count(size, 2)
	_ = second.Close()
	count(0, 0)
}

func TestTheLimitNeverHoldsBackASessionSharingTheUnderlay(t *testing.T) {
	body := clashTestBody(2 << 20)
	clashTestSet(t, SetStreamReceiveByteLimit, int64(clashTestLimit))
	client, sent := clashTestPairSharing(t, common.StreamTransport, body, 3)
	unread := clashTestAsk(t, client, 'd')
	var sharing *Session
	for attempt := 0; attempt < 64 && sharing == nil; attempt++ {
		candidate := clashTestAsk(t, client, 'e')
		if candidate.conn == unread.conn {
			sharing = candidate
		} else {
			_ = candidate.Close()
		}
	}
	if sharing == nil {
		t.Fatal("no session came to share the underlay in 64 dials")
	}
	var one [1]byte
	for i := 0; i < 20; i++ {
		if _, err := sharing.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(clashTestReader{session: sharing}, one[:]); err != nil || one[0] != byte(i) {
			t.Fatalf("beside an unread session, byte %d came back as %d (%v)", i, one[0], err)
		}
	}
	held := clashTestSettled(t, unread, func(int) bool { return sent.Load() == int64(len(body)) })
	if held != len(body) {
		t.Fatalf("a session sharing its underlay queues as shipped, all %d bytes: it holds %d", len(body), held)
	}
}

func TestASessionAloneOnItsUnderlayTakesItAlongWhenItsApplicationCloses(t *testing.T) {
	for _, c := range []struct {
		name      string
		transport common.TransportProtocol
		release   bool
		factor    int
		closes    bool
	}{
		{"alone, released", common.StreamTransport, true, 0, true},
		{"alone, as shipped", common.StreamTransport, false, 0, false},
		{"sharing, released", common.StreamTransport, true, 1, false},
		{"alone on the packet transport, released", common.PacketTransport, true, 0, false},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			clashTestSet(t, SetReleaseOnApplicationClose, c.release)
			client, _ := clashTestPairSharing(t, c.transport, nil, c.factor)
			session := clashTestAsk(t, client, 'e')
			var one [1]byte
			if _, err := session.Write([]byte{7}); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(clashTestReader{session: session}, one[:]); err != nil {
				t.Fatal(err)
			}
			underlay := session.conn
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			wait := 500 * time.Millisecond
			if c.closes {
				wait = clashTestHang
			}
			closed := false
			select {
			case <-underlay.Done():
				closed = true
			case <-time.After(wait):
			}
			if closed != c.closes {
				t.Fatalf("after its application closed the session, the underlay closed: %v, want %v", closed, c.closes)
			}
			if !c.closes {
				return
			}
			stream := underlay.(*StreamUnderlay)
			for deadline := time.Now().Add(clashTestHang); ; time.Sleep(10 * time.Millisecond) {
				if err := stream.conn.SetWriteDeadline(time.Time{}); err != nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the underlay is done and its connection is still open")
				}
			}
		})
	}
}

func clashTestLoneSession(transport common.TransportProtocol) *Session {
	session := NewSession(1, true, 1400, nil, nil)
	session.transportProtocol = transport
	session.bounds.alone = true
	return session
}

func TestAReaderWaitingAtTheLimitIsLetGoByAClose(t *testing.T) {
	for _, c := range []struct {
		name string
		end  func(session *Session, underlay *baseUnderlay)
	}{
		{"the application's close", func(session *Session, _ *baseUnderlay) { _ = session.Close() }},
		{"the underlay's close", func(_ *Session, underlay *baseUnderlay) { _ = underlay.Close() }},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			clashTestSet(t, SetStreamReceiveByteLimit, int64(1000))
			underlay := newBaseUnderlay(true, 1400, nil)
			session := clashTestLoneSession(common.StreamTransport)
			if !underlay.deliverSegmentToSession(session, testDataSegment(1, 1, make([]byte, 1000), common.StreamTransport)) {
				t.Fatal("the segment that reaches the limit was refused")
			}
			done := make(chan bool, 1)
			go func() {
				done <- underlay.deliverSegmentToSession(session, testDataSegment(1, 2, []byte("x"), common.StreamTransport))
			}()
			select {
			case delivered := <-done:
				t.Fatalf("at the limit the next segment did not wait: delivered %v", delivered)
			case <-time.After(100 * time.Millisecond):
			}
			c.end(session, underlay)
			select {
			case delivered := <-done:
				if delivered {
					t.Fatal("the segment that was waiting was delivered after the close")
				}
			case <-time.After(clashTestHang):
				t.Fatal("the reader is still waiting after the close")
			}
		})
	}
}

func TestNothingIsQueuedForASessionItsApplicationClosed(t *testing.T) {
	clashTestSet(t, SetReleaseOnApplicationClose, true)
	underlay := newBaseUnderlay(true, 1400, nil)
	session := clashTestLoneSession(common.StreamTransport)
	_ = session.Close()
	_ = session.Close()
	for i := 0; i < 200; i++ {
		if underlay.deliverSegmentToSession(session, testDataSegment(1, uint32(i+1), []byte("payload"), common.StreamTransport)) {
			t.Fatalf("segment %d was queued for a session its application had closed", i)
		}
	}
	if len(session.recvChan) != 0 || session.ReceiveQueuedBytes() != 0 {
		t.Fatalf("the closed session holds %d segments and tallies %d bytes", len(session.recvChan), session.ReceiveQueuedBytes())
	}
}

func TestTheLimitLeavesAPacketSessionAlone(t *testing.T) {
	clashTestSet(t, SetStreamReceiveByteLimit, int64(1))
	session := clashTestLoneSession(common.PacketTransport)
	finished := make(chan string, 1)
	go func() {
		never := make(chan struct{})
		for i := 0; i < 1000; i++ {
			if !session.admitForApplication(testDataSegment(1, uint32(i+1), make([]byte, 1000), common.PacketTransport), never) {
				finished <- "a datagram was refused"
				return
			}
		}
		session.taken(1000)
		finished <- ""
	}()
	select {
	case problem := <-finished:
		if problem != "" {
			t.Fatal(problem)
		}
	case <-time.After(clashTestHang):
		t.Fatal("a packet session waited at the stream limit")
	}
	if tally := session.bounds.queued.Load(); tally != 0 {
		t.Fatalf("a packet session is tallied: %d bytes", tally)
	}
}

func TestTheModulesOwnClosesKeepWhatWasQueued(t *testing.T) {
	payload := []byte("what arrived before the close")
	for _, c := range []struct {
		name string
		end  func(underlay *StreamUnderlay, session *Session) error
	}{
		{"the underlay removes the session", func(underlay *StreamUnderlay, session *Session) error {
			_ = session.closeWithError(nil)
			return underlay.baseUnderlay.RemoveSession(session)
		}},
		{"the underlay closes", func(underlay *StreamUnderlay, _ *Session) error { return underlay.baseUnderlay.Close() }},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			clashTestSet(t, SetReleaseOnApplicationClose, true)
			underlay := &StreamUnderlay{baseUnderlay: *newBaseUnderlay(true, 1400, nil)}
			session := NewSession(1, true, 1400, nil, nil)
			session.transportProtocol = common.StreamTransport
			if err := underlay.baseUnderlay.AddSession(session, nil); err != nil {
				t.Fatal(err)
			}
			for seq := uint32(1); seq <= 3; seq++ {
				if !session.recvQueue.Insert(testDataSegment(1, seq, payload, common.StreamTransport)) {
					t.Fatal("the queue refused a segment")
				}
			}
			if err := c.end(underlay, session); err != nil {
				t.Fatal(err)
			}
			if queued := clashTestQueued(session); queued != 3*len(payload) {
				t.Fatalf("the session has %d of the %d bytes that were queued", queued, 3*len(payload))
			}
			got := make([]byte, 3*len(payload))
			if _, err := io.ReadFull(clashTestReader{session: session}, got); err != nil || !bytes.Equal(got, bytes.Repeat(payload, 3)) {
				t.Fatalf("what was queued did not read back (%v)", err)
			}
		})
	}
}

func TestAReadInFlightReturnsWhenTheApplicationCloses(t *testing.T) {
	clashTestSet(t, SetReleaseOnApplicationClose, true)
	client, _ := clashTestPair(t, common.StreamTransport, nil)
	session := clashTestAsk(t, client, 'e')
	result := make(chan error, 1)
	go func() {
		var buffer [16]byte
		_, err := session.Read(buffer[:])
		result <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("the Read returned data nobody sent")
		}
	case <-time.After(clashTestHang):
		t.Fatal("the Read is still waiting after the application's close")
	}
}

func TestWhatASessionDoesNotQueueNeitherWaitsNorCounts(t *testing.T) {
	clashTestSet(t, SetStreamReceiveByteLimit, int64(1000))
	session := clashTestLoneSession(common.StreamTransport)
	never := make(chan struct{})
	if !session.admitForApplication(testDataSegment(1, 1, make([]byte, 1000), common.StreamTransport), never) {
		t.Fatal("the segment that reaches the limit was refused")
	}
	closing := testSessionSegment(closeSessionRequest, 1, common.StreamTransport)
	closing.payload = []byte("a close with payload")
	ack := testDataSegment(1, 2, []byte("an acknowledgement with payload"), common.StreamTransport)
	ack.metadata.(*dataAckStruct).protocol = uint8(ackServerToClient)
	finished := make(chan bool, 1)
	go func() {
		finished <- session.admitForApplication(closing, never) && session.admitForApplication(ack, never)
	}()
	select {
	case admitted := <-finished:
		if !admitted {
			t.Fatal("a segment the session does not queue was refused")
		}
	case <-time.After(clashTestHang):
		t.Fatal("a segment the session does not queue waited at the limit")
	}
	if tally := session.bounds.queued.Load(); tally != 1000 {
		t.Fatalf("the tally is %d after a data segment of 1000 bytes, a close and an acknowledgement", tally)
	}
}

func TestAClosedPacketSessionIsHandedNothingMore(t *testing.T) {
	for _, c := range []struct {
		name      string
		on        bool
		transport common.TransportProtocol
		end       func(session *Session)
		nothing   bool
	}{
		{"closed by the module", true, common.PacketTransport, func(session *Session) { _ = session.closeWithError(nil) }, true},
		{"closed by its application", true, common.PacketTransport, func(session *Session) { _ = session.Close() }, true},
		{"as shipped", false, common.PacketTransport, func(session *Session) { _ = session.closeWithError(nil) }, false},
		{"a stream session closed by the module", true, common.StreamTransport, func(session *Session) { _ = session.closeWithError(nil) }, false},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			clashTestSet(t, SetReleaseOnApplicationClose, c.on)
			underlay := newBaseUnderlay(true, 1400, nil)
			session := clashTestLoneSession(c.transport)
			c.end(session)
			handed := 0
			for i := 0; i < 2000; i++ {
				if underlay.deliverSegmentToSession(session, testDataSegment(1, uint32(i), []byte("payload"), c.transport)) {
					handed++
				}
			}
			if c.nothing && (handed != 0 || len(session.recvChan) != 0) {
				t.Fatalf("the closed session was handed %d segments and holds %d in its channel", handed, len(session.recvChan))
			}
			if !c.nothing && len(session.recvChan) != segmentChanCapacity {
				t.Fatalf("as shipped the closed session's channel holds %d segments, and this test expects it full: %d", len(session.recvChan), segmentChanCapacity)
			}
		})
	}
}

func TestAPacketSessionsInputLoopLeavesNothingInItsChannel(t *testing.T) {
	for _, c := range []struct {
		name      string
		on        bool
		transport common.TransportProtocol
		left      int
	}{
		{"a packet session", true, common.PacketTransport, 0},
		{"a stream session", true, common.StreamTransport, 100},
		{"a packet session as shipped", false, common.PacketTransport, 100},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			clashTestSet(t, SetReleaseOnApplicationClose, c.on)
			session := clashTestLoneSession(c.transport)
			returned := session.listed()
			for i := 0; i < 100; i++ {
				session.recvChan <- testDataSegment(1, uint32(i), []byte("payload"), c.transport)
			}
			returned()
			if len(session.recvChan) != c.left {
				t.Fatalf("the channel holds %d segments once the input loop has returned, want %d", len(session.recvChan), c.left)
			}
		})
	}
}

func TestAnOpenPacketSessionIsHandedItsSegments(t *testing.T) {
	clashTestSet(t, SetReleaseOnApplicationClose, true)
	underlay := newBaseUnderlay(true, 1400, nil)
	session := clashTestLoneSession(common.PacketTransport)
	for i := 0; i < 100; i++ {
		if !underlay.deliverSegmentToSession(session, testDataSegment(1, uint32(i), []byte("payload"), common.PacketTransport)) {
			t.Fatalf("segment %d was refused to an open session", i)
		}
	}
	if len(session.recvChan) != 100 {
		t.Fatalf("the open session's channel holds %d of the 100 segments", len(session.recvChan))
	}
}

func TestAPacketSessionWhoseInputLoopReturnedIsHandedNothingMore(t *testing.T) {
	for _, c := range []struct {
		name      string
		on        bool
		transport common.TransportProtocol
		nothing   bool
	}{
		{"a packet session", true, common.PacketTransport, true},
		{"a packet session as shipped", false, common.PacketTransport, false},
		{"a stream session", true, common.StreamTransport, false},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			clashTestSet(t, SetReleaseOnApplicationClose, c.on)
			underlay := newBaseUnderlay(true, 1400, nil)
			session := clashTestLoneSession(c.transport)
			session.listed()()
			handed := 0
			for i := 0; i < segmentChanCapacity; i++ {
				if underlay.deliverSegmentToSession(session, testDataSegment(1, uint32(i), []byte("payload"), c.transport)) {
					handed++
				}
			}
			if c.nothing && (handed != 0 || len(session.recvChan) != 0) {
				t.Fatalf("the session was handed %d segments after its input loop returned, and holds %d", handed, len(session.recvChan))
			}
			if !c.nothing && len(session.recvChan) != segmentChanCapacity {
				t.Fatalf("the session's channel holds %d segments, and this case expects it full as shipped: %d", len(session.recvChan), segmentChanCapacity)
			}
		})
	}
}
