package clash

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/common/atomic"
	"github.com/ProjectClash/Clash/common/utils"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/tunnel/statistic"
)

func eventTestInfo(host string, upload, download int64, start time.Time) *statistic.TrackerInfo {
	return &statistic.TrackerInfo{
		UUID: utils.NewUUIDV4(),
		Metadata: &C.Metadata{
			NetWork: C.TCP,
			Type:    C.TUN,
			SrcIP:   netip.MustParseAddr("198.18.0.1"),
			SrcPort: 50000,
			Host:    host,
			DstPort: 443,
		},
		UploadTotal:   atomic.NewInt64(upload),
		DownloadTotal: atomic.NewInt64(download),
		Start:         start,
		Chain:         C.Chain{"DIRECT"},
		Rule:          "Match",
	}
}

func decodeEventsMessage(t *testing.T, payload []byte) connectionEventsMessage {
	t.Helper()
	var message connectionEventsMessage
	if err := json.Unmarshal(payload, &message); err != nil {
		t.Fatalf("decode %s: %v", payload, err)
	}
	return message
}

func TestConnectionEventsOpenWithAResetCarryingEveryConnectionAsUpstreamWritesIt(t *testing.T) {
	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	later := eventTestInfo("b.example", 10, 20, base.Add(time.Second))
	earlier := eventTestInfo("a.example", 1, 2, base)
	tracker := newConnectionEventTracker()

	payload, ok := tracker.open([]*statistic.TrackerInfo{later, earlier})
	if !ok {
		t.Fatal("the opening message was not produced")
	}
	message := decodeEventsMessage(t, payload)
	if !message.Reset {
		t.Fatalf("the opening message is not marked reset: %s", payload)
	}
	if len(message.Events) != 2 {
		t.Fatalf("the opening message carries %d events, want 2: %s", len(message.Events), payload)
	}
	for index, want := range []*statistic.TrackerInfo{earlier, later} {
		event := message.Events[index]
		if event.Type != "new" || event.ID != want.UUID.String() {
			t.Fatalf("event %d = %s %s, want new %s (oldest first)", index, event.Type, event.ID, want.UUID)
		}
		upstream, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		if string(event.Connection) != string(upstream) {
			t.Fatalf("event %d connection differs from upstream's object:\n got %s\nwant %s", index, event.Connection, upstream)
		}
	}
}

func TestConnectionEventsOpenWithAResetEvenWhenThereAreNoConnections(t *testing.T) {
	payload, ok := newConnectionEventTracker().open(nil)
	if !ok {
		t.Fatal("the opening message was not produced")
	}
	if got := string(payload); got != `{"reset":true,"events":[]}` {
		t.Fatalf("opening an empty table wrote %s", got)
	}
}

func TestConnectionEventsSendOnlyWhatChangedSinceTheLastTick(t *testing.T) {
	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	idle := eventTestInfo("idle.example", 100, 200, base)
	busy := eventTestInfo("busy.example", 1000, 2000, base)
	tracker := newConnectionEventTracker()
	if _, ok := tracker.open([]*statistic.TrackerInfo{idle, busy}); !ok {
		t.Fatal("open")
	}

	if payload, ok := tracker.step([]*statistic.TrackerInfo{idle, busy}, base.Add(time.Second)); ok {
		t.Fatalf("a tick with no change wrote %s", payload)
	}

	busy.UploadTotal.Store(1500)
	busy.DownloadTotal.Store(2000)
	payload, ok := tracker.step([]*statistic.TrackerInfo{idle, busy}, base.Add(2*time.Second))
	if !ok {
		t.Fatal("a tick where bytes moved wrote nothing")
	}
	message := decodeEventsMessage(t, payload)
	if message.Reset || len(message.Events) != 1 {
		t.Fatalf("want one update and no reset, got %s", payload)
	}
	update := message.Events[0]
	if update.Type != "update" || update.ID != busy.UUID.String() || update.Connection != nil {
		t.Fatalf("want an update for the busy connection without its object, got %s", payload)
	}
	if update.Upload == nil || *update.Upload != 1500 || update.Download == nil || *update.Download != 2000 ||
		update.Up == nil || *update.Up != 500 || update.Down == nil || *update.Down != 0 {
		t.Fatalf("update totals/deltas wrong: %s", payload)
	}

	payload, ok = tracker.step([]*statistic.TrackerInfo{idle, busy}, base.Add(3*time.Second))
	if !ok {
		t.Fatal("the first quiet tick after traffic wrote nothing; the row's rate would never drop to zero")
	}
	message = decodeEventsMessage(t, payload)
	if len(message.Events) != 1 || message.Events[0].Type != "update" || message.Events[0].ID != busy.UUID.String() ||
		message.Events[0].Up == nil || *message.Events[0].Up != 0 || message.Events[0].Down == nil || *message.Events[0].Down != 0 {
		t.Fatalf("want one 0/0 update for the busy connection, got %s", payload)
	}
	if payload, ok := tracker.step([]*statistic.TrackerInfo{idle, busy}, base.Add(4*time.Second)); ok {
		t.Fatalf("a second quiet tick wrote %s", payload)
	}

	closedAt := base.Add(5 * time.Second)
	payload, ok = tracker.step([]*statistic.TrackerInfo{idle}, closedAt)
	if !ok {
		t.Fatal("a tick where a connection closed wrote nothing")
	}
	message = decodeEventsMessage(t, payload)
	if len(message.Events) != 1 || message.Events[0].Type != "closed" || message.Events[0].ID != busy.UUID.String() {
		t.Fatalf("want one closed for the busy connection, got %s", payload)
	}
	if message.Events[0].ClosedAt != closedAt.Format(time.RFC3339Nano) {
		t.Fatalf("closedAt = %q, want %q", message.Events[0].ClosedAt, closedAt.Format(time.RFC3339Nano))
	}

	if payload, ok := tracker.step([]*statistic.TrackerInfo{idle}, base.Add(6*time.Second)); ok {
		t.Fatalf("a closed connection was reported again: %s", payload)
	}
}

func TestConnectionEventsReportAConnectionThatAppearedAsNew(t *testing.T) {
	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	first := eventTestInfo("first.example", 0, 0, base)
	tracker := newConnectionEventTracker()
	if _, ok := tracker.open([]*statistic.TrackerInfo{first}); !ok {
		t.Fatal("open")
	}
	second := eventTestInfo("second.example", 7, 9, base.Add(time.Second))
	payload, ok := tracker.step([]*statistic.TrackerInfo{first, second}, base.Add(time.Second))
	if !ok {
		t.Fatal("a new connection wrote nothing")
	}
	message := decodeEventsMessage(t, payload)
	if len(message.Events) != 1 || message.Events[0].Type != "new" || message.Events[0].ID != second.UUID.String() {
		t.Fatalf("want one new, got %s", payload)
	}
	upstream, _ := json.Marshal(second)
	if string(message.Events[0].Connection) != string(upstream) {
		t.Fatalf("new connection object differs from upstream's:\n got %s\nwant %s", message.Events[0].Connection, upstream)
	}
	if payload, ok := tracker.step([]*statistic.TrackerInfo{first, second}, base.Add(2*time.Second)); ok {
		t.Fatalf("an unchanged new connection was reported again: %s", payload)
	}
}

func TestConnectionEventsRebaseWhenACounterGoesBackwards(t *testing.T) {
	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	info := eventTestInfo("reset.example", 1000, 1000, base)
	tracker := newConnectionEventTracker()
	tracker.open([]*statistic.TrackerInfo{info})
	info.UploadTotal.Store(10)
	if payload, ok := tracker.step([]*statistic.TrackerInfo{info}, base.Add(time.Second)); ok {
		message := decodeEventsMessage(t, payload)
		for _, event := range message.Events {
			if (event.Up != nil && *event.Up < 0) || (event.Down != nil && *event.Down < 0) {
				t.Fatalf("a negative delta crossed: %s", payload)
			}
		}
	}
	info.UploadTotal.Store(30)
	payload, ok := tracker.step([]*statistic.TrackerInfo{info}, base.Add(2*time.Second))
	if !ok {
		t.Fatal("traffic after the re-base wrote nothing")
	}
	message := decodeEventsMessage(t, payload)
	if len(message.Events) != 1 || message.Events[0].Up == nil || *message.Events[0].Up != 20 {
		t.Fatalf("want up 20 measured from the re-based counter, got %s", payload)
	}
}

func TestConnectionEventsApplyJoinsAndLeavesAsTheyHappen(t *testing.T) {
	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	tracker := newConnectionEventTracker()
	tracker.open(nil)

	info := eventTestInfo("live.example", 0, 0, base)
	joined := tracker.apply(connectionChange{joined: true, info: info, at: base})
	if joined == nil || joined.Type != "new" || joined.ID != info.UUID.String() || joined.Connection == nil {
		t.Fatalf("a join produced %+v, want a new event with the object", joined)
	}
	if again := tracker.apply(connectionChange{joined: true, info: info, at: base}); again != nil {
		t.Fatalf("a second join of the same connection produced %+v", again)
	}

	info.DownloadTotal.Store(777)
	closedAt := base.Add(time.Second)
	left := tracker.apply(connectionChange{joined: false, info: info, at: closedAt})
	if left == nil || left.Type != "closed" || left.ClosedAt != closedAt.Format(time.RFC3339Nano) {
		t.Fatalf("a leave produced %+v, want closed at %s", left, closedAt.Format(time.RFC3339Nano))
	}
	final, _ := json.Marshal(info)
	if string(left.Connection) != string(final) {
		t.Fatalf("the closed event does not carry the final object:\n got %s\nwant %s", left.Connection, final)
	}
	if again := tracker.apply(connectionChange{joined: false, info: info, at: closedAt}); again != nil {
		t.Fatalf("a second leave produced %+v", again)
	}
	if payload, ok := tracker.step(nil, closedAt); ok {
		t.Fatalf("the tick reported a connection the leave already closed: %s", payload)
	}
}

func TestConnectionEventsIgnoreAJoinThatArrivesAfterItsOwnLeave(t *testing.T) {
	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	tracker := newConnectionEventTracker()
	tracker.open(nil)
	info := eventTestInfo("gone.example", 0, 0, base)
	if event := tracker.apply(connectionChange{joined: false, info: info, at: base}); event != nil {
		t.Fatalf("a leave of an unseen connection produced %+v", event)
	}
	if event := tracker.apply(connectionChange{joined: true, info: info, at: base}); event != nil {
		t.Fatalf("the join that arrived after its own leave produced %+v -- a phantom row", event)
	}
	if payload, ok := tracker.step(nil, base.Add(time.Second)); ok {
		t.Fatalf("the tick reported the phantom: %s", payload)
	}
}

func TestConnectionEventsIgnoreALateJoinOfAConnectionAlreadyClosed(t *testing.T) {
	base := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	info := eventTestInfo("late-join.example", 0, 0, base)
	tracker := newConnectionEventTracker()
	tracker.open([]*statistic.TrackerInfo{info})
	if event := tracker.apply(connectionChange{joined: false, info: info, at: base}); event == nil || event.Type != "closed" {
		t.Fatalf("the leave of a connection in the opening message produced %+v, want closed", event)
	}
	if event := tracker.apply(connectionChange{joined: true, info: info, at: base}); event != nil {
		t.Fatalf("the late join of a closed connection produced %+v -- a phantom row", event)
	}
}

func TestConnectionEventsReleaseAPeerThatStoppedReading(t *testing.T) {
	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	path := shortClashSocketPath(t)
	if err := startControlPlane(controllerConfig(t, addr), path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	for _, shape := range []struct{ name, request string }{
		{"websocket", "GET /clash/v1/connections/events?interval=60000 HTTP/1.1\r\nHost: localhost\r\n" +
			"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n" +
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"},
		{"chunked", "GET /clash/v1/connections/events?interval=60000 HTTP/1.1\r\nHost: localhost\r\n\r\n"},
	} {
		t.Run(shape.name, func(t *testing.T) {
			connection, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer connection.Close()
			_ = connection.(*net.TCPConn).SetReadBuffer(4096)
			if _, err := connection.Write([]byte(shape.request)); err != nil {
				t.Fatalf("request: %v", err)
			}
			waitForSubscribers(t, 1)

			var trackers []routeTestTracker
			t.Cleanup(func() {
				for _, tracker := range trackers {
					_ = tracker.Close()
				}
			})
			for range 20000 {
				trackers = append(trackers, joinRouteTestTracker("flood.example"))
			}
			time.Sleep(200 * time.Millisecond)
			_ = connection.(*net.TCPConn).CloseWrite()
			waitForSubscribers(t, 0)
		})
	}
}

func waitForSubscribers(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		connectionChangeSubscribers.RLock()
		open := len(connectionChangeSubscribers.streams)
		connectionChangeSubscribers.RUnlock()
		if open == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d subscriber(s) registered, want %d", open, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestConnectionEventsRouteStreamsTheLiveTable(t *testing.T) {
	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	path := shortClashSocketPath(t)
	if err := startControlPlane(controllerConfig(t, addr), path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	if status := httpStatusLine(t, addr, "/clash/v1/connections/events?interval=50"); !strings.Contains(status, "400") {
		t.Fatalf("interval 50 answered %q, want 400", status)
	}

	tracked := joinRouteTestTracker("route.example")
	t.Cleanup(func() { _ = tracked.Close() })
	id := tracked.ID()

	connection, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial the controller: %v", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connection.Write([]byte("GET /clash/v1/connections/events?interval=60000 HTTP/1.1\r\nHost: localhost\r\n\r\n")); err != nil {
		t.Fatalf("request the stream: %v", err)
	}
	reader := bufio.NewReader(connection)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read the response head: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	next := func(what string) connectionEventsMessage {
		t.Helper()
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read %s: %v", what, err)
			}
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "{") {
				continue
			}
			return decodeEventsMessage(t, []byte(line))
		}
	}

	opening := next("the opening message")
	found := false
	for _, event := range opening.Events {
		found = found || (event.Type == "new" && event.ID == id)
	}
	if !opening.Reset || !found {
		t.Fatalf("the opening message is not a reset carrying the live connection %s: %+v", id, opening)
	}

	late := joinRouteTestTracker("late.example")
	t.Cleanup(func() { _ = late.Close() })
	joined := next("the join")
	if len(joined.Events) != 1 || joined.Events[0].Type != "new" || joined.Events[0].ID != late.ID() {
		t.Fatalf("want an immediate new for %s, got %+v", late.ID(), joined)
	}
	_ = late.Close()
	gone := next("the leave")
	if len(gone.Events) != 1 || gone.Events[0].Type != "closed" || gone.Events[0].ID != late.ID() {
		t.Fatalf("want an immediate closed for %s, got %+v", late.ID(), gone)
	}

	_ = connection.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		connectionChangeSubscribers.RLock()
		open := len(connectionChangeSubscribers.streams)
		connectionChangeSubscribers.RUnlock()
		if open == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d subscriber(s) still registered after the peer left", open)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestConnectionEventsCommandNeedsAWriterAndAsksTheRoute(t *testing.T) {
	options := &APIClientOptions{StatusInterval: 250}
	options.AddCommand(CommandConnectionEvents)
	client, err := NewAPIClientWithOptions("/tmp/does-not-exist.sock", newRecordingClashAPIHandler(), options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.streamSpecs(context.Background()); err == nil || !strings.Contains(err.Error(), "SetConnectionEventsWriter") {
		t.Fatalf("subscribing without a writer = %v, want an error naming SetConnectionEventsWriter", err)
	}

	writer := &recordingConnectionEventsWriter{}
	client.SetConnectionEventsWriter(writer)
	specs, err := client.streamSpecs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 || specs[0].path != "/clash/v1/connections/events?interval=250" {
		t.Fatalf("specs = %+v, want the events route at 250 ms", specs)
	}
	specs[0].write("{\"events\":[\"\xff\"]}")
	if got := writer.messages(); len(got) != 1 || !strings.Contains(got[0], "\uFFFD") {
		t.Fatalf("the writer got %q; every message crosses the bridge as valid UTF-8", got)
	}

	bad := &APIClientOptions{StatusInterval: 50}
	bad.AddCommand(CommandConnectionEvents)
	badClient, err := NewAPIClientWithOptions("/tmp/does-not-exist.sock", newRecordingClashAPIHandler(), bad)
	if err != nil {
		t.Fatal(err)
	}
	badClient.SetConnectionEventsWriter(writer)
	if _, err := badClient.streamSpecs(context.Background()); err == nil || !strings.Contains(err.Error(), "interval") {
		t.Fatalf("interval 50 = %v, want an interval error", err)
	}
}

type recordingConnectionEventsWriter struct {
	mu   sync.Mutex
	seen []string
}

func (w *recordingConnectionEventsWriter) WriteConnectionEvents(message string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seen = append(w.seen, message)
}

func (w *recordingConnectionEventsWriter) messages() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.seen...)
}

type routeTestTracker struct {
	statistic.Tracker
	info *statistic.TrackerInfo
}

func (t routeTestTracker) ID() string                   { return t.info.UUID.String() }
func (t routeTestTracker) Info() *statistic.TrackerInfo { return t.info }
func (t routeTestTracker) Close() error {
	statistic.DefaultManager.Leave(t)
	return nil
}

func joinRouteTestTracker(host string) routeTestTracker {
	tracker := routeTestTracker{info: eventTestInfo(host, 0, 0, time.Now())}
	statistic.DefaultManager.Join(tracker)
	return tracker
}

func httpStatusLine(t *testing.T, addr, target string) string {
	t.Helper()
	connection, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := connection.Write([]byte("GET " + target + " HTTP/1.1\r\nHost: localhost\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	return strings.TrimSpace(line)
}
