package clash

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/ProjectClash/Clash/hub/route"
	"github.com/ProjectClash/Clash/tunnel/statistic"
	"github.com/metacubex/chi"
	"github.com/metacubex/http"
)

const (
	connectionEventsDefaultInterval = 1000
	connectionEventsMinInterval     = 100
	connectionEventsMaxInterval     = 60_000
	connectionChangeBuffer          = 1024
)

type connectionEvent struct {
	Type       string          `json:"type"`
	ID         string          `json:"id"`
	Connection json.RawMessage `json:"connection,omitempty"`
	Upload     *int64          `json:"upload,omitempty"`
	Download   *int64          `json:"download,omitempty"`
	Up         *int64          `json:"up,omitempty"`
	Down       *int64          `json:"down,omitempty"`
	ClosedAt   string          `json:"closedAt,omitempty"`
}

type connectionEventsMessage struct {
	Reset  bool              `json:"reset,omitempty"`
	Events []connectionEvent `json:"events"`
}

type connectionSnapshot struct {
	upload     int64
	download   int64
	hadTraffic bool
}

type connectionChange struct {
	joined bool
	info   *statistic.TrackerInfo
	at     time.Time
}

type connectionEventTracker struct {
	seen     map[string]connectionSnapshot
	departed map[string]struct{}
}

func newConnectionEventTracker() *connectionEventTracker {
	return &connectionEventTracker{seen: map[string]connectionSnapshot{}, departed: map[string]struct{}{}}
}

func sortedByStart(infos []*statistic.TrackerInfo) []*statistic.TrackerInfo {
	sorted := make([]*statistic.TrackerInfo, 0, len(infos))
	for _, info := range infos {
		if info != nil {
			sorted = append(sorted, info)
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		if !sorted[i].Start.Equal(sorted[j].Start) {
			return sorted[i].Start.Before(sorted[j].Start)
		}
		return sorted[i].UUID.String() < sorted[j].UUID.String()
	})
	return sorted
}

func (t *connectionEventTracker) remember(info *statistic.TrackerInfo) (connectionEvent, bool) {
	baseline := connectionSnapshot{upload: info.UploadTotal.Load(), download: info.DownloadTotal.Load()}
	object, err := json.Marshal(info)
	if err != nil {
		return connectionEvent{}, false
	}
	id := info.UUID.String()
	t.seen[id] = baseline
	return connectionEvent{Type: "new", ID: id, Connection: object}, true
}

func (t *connectionEventTracker) open(infos []*statistic.TrackerInfo) ([]byte, bool) {
	t.seen = map[string]connectionSnapshot{}
	events := []connectionEvent{}
	for _, info := range sortedByStart(infos) {
		if event, ok := t.remember(info); ok {
			events = append(events, event)
		}
	}
	return encodeConnectionEvents(true, events)
}

func (t *connectionEventTracker) apply(change connectionChange) *connectionEvent {
	if change.info == nil {
		return nil
	}
	id := change.info.UUID.String()
	_, known := t.seen[id]
	if change.joined {
		if _, gone := t.departed[id]; known || gone {
			delete(t.departed, id)
			return nil
		}
		event, ok := t.remember(change.info)
		if !ok {
			return nil
		}
		return &event
	}
	t.departed[id] = struct{}{}
	if !known {
		return nil
	}
	delete(t.seen, id)
	event := connectionEvent{Type: "closed", ID: id, ClosedAt: change.at.Format(time.RFC3339Nano)}
	if object, err := json.Marshal(change.info); err == nil {
		event.Connection = object
	}
	return &event
}

func updateEvent(id string, upload, download, up, down int64) connectionEvent {
	return connectionEvent{Type: "update", ID: id, Upload: &upload, Download: &download, Up: &up, Down: &down}
}

func (t *connectionEventTracker) step(infos []*statistic.TrackerInfo, now time.Time) ([]byte, bool) {
	clear(t.departed)
	var events []connectionEvent
	live := make(map[string]struct{}, len(infos))
	for _, info := range sortedByStart(infos) {
		id := info.UUID.String()
		live[id] = struct{}{}
		snapshot, known := t.seen[id]
		if !known {
			if event, ok := t.remember(info); ok {
				events = append(events, event)
			}
			continue
		}
		upload, download := info.UploadTotal.Load(), info.DownloadTotal.Load()
		up, down := upload-snapshot.upload, download-snapshot.download
		switch {
		case up < 0 || down < 0:
			if snapshot.hadTraffic {
				events = append(events, updateEvent(id, upload, download, 0, 0))
			}
			t.seen[id] = connectionSnapshot{upload: upload, download: download}
		case up > 0 || down > 0:
			events = append(events, updateEvent(id, upload, download, up, down))
			t.seen[id] = connectionSnapshot{upload: upload, download: download, hadTraffic: true}
		case snapshot.hadTraffic:
			events = append(events, updateEvent(id, upload, download, 0, 0))
			t.seen[id] = connectionSnapshot{upload: upload, download: download}
		}
	}
	var gone []string
	for id := range t.seen {
		if _, ok := live[id]; !ok {
			gone = append(gone, id)
		}
	}
	sort.Strings(gone)
	for _, id := range gone {
		delete(t.seen, id)
		events = append(events, connectionEvent{Type: "closed", ID: id, ClosedAt: now.Format(time.RFC3339Nano)})
	}
	if len(events) == 0 {
		return nil, false
	}
	return encodeConnectionEvents(false, events)
}

func encodeConnectionEvents(reset bool, events []connectionEvent) ([]byte, bool) {
	payload, err := json.Marshal(connectionEventsMessage{Reset: reset, Events: events})
	if err != nil {
		return nil, false
	}
	return payload, true
}

var connectionChangeSubscribers = struct {
	sync.RWMutex
	next    int
	streams map[int]chan connectionChange
}{streams: map[int]chan connectionChange{}}

func publishConnectionChange(joined bool, tracker statistic.Tracker) {
	change := connectionChange{joined: joined, info: tracker.Info(), at: time.Now()}
	connectionChangeSubscribers.RLock()
	defer connectionChangeSubscribers.RUnlock()
	for _, stream := range connectionChangeSubscribers.streams {
		select {
		case stream <- change:
		default:
		}
	}
}

func subscribeConnectionChanges() (<-chan connectionChange, func()) {
	stream := make(chan connectionChange, connectionChangeBuffer)
	connectionChangeSubscribers.Lock()
	id := connectionChangeSubscribers.next
	connectionChangeSubscribers.next++
	connectionChangeSubscribers.streams[id] = stream
	if len(connectionChangeSubscribers.streams) == 1 {
		statistic.DefaultManager.SetConnectionObserver(publishConnectionChange)
	}
	connectionChangeSubscribers.Unlock()
	return stream, func() {
		connectionChangeSubscribers.Lock()
		defer connectionChangeSubscribers.Unlock()
		delete(connectionChangeSubscribers.streams, id)
		if len(connectionChangeSubscribers.streams) == 0 {
			statistic.DefaultManager.SetConnectionObserver(nil)
		}
	}
}

func liveConnectionInfos() []*statistic.TrackerInfo {
	var infos []*statistic.TrackerInfo
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		infos = append(infos, c.Info())
		return true
	})
	return infos
}

func init() {
	route.Register(func(router chi.Router) {
		for _, prefix := range privateRoutePrefixes {
			router.Get(prefix+"/connections/events", serveConnectionEvents)
		}
	})
}

func connectionEventsInterval(raw string) (int, error) {
	if raw == "" {
		return connectionEventsDefaultInterval, nil
	}
	interval, err := strconv.Atoi(raw)
	if err != nil || interval < connectionEventsMinInterval || interval > connectionEventsMaxInterval {
		return 0, fmt.Errorf("interval %q is outside %d...%d ms", raw, connectionEventsMinInterval, connectionEventsMaxInterval)
	}
	return interval, nil
}

func serveConnectionEvents(writer http.ResponseWriter, request *http.Request) {
	interval, err := connectionEventsInterval(request.URL.Query().Get("interval"))
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	if request.Header.Get("Upgrade") == "websocket" {
		connection, err := route.UpgradeWebSocket(request, writer)
		if err != nil {
			return
		}
		defer connection.Close()
		ctx, cancel := context.WithCancel(request.Context())
		defer cancel()
		go func() {
			_, _ = io.Copy(io.Discard, connection)
			cancel()
		}()
		go func() {
			<-ctx.Done()
			_ = connection.Close()
		}()
		runConnectionEvents(ctx, time.Duration(interval)*time.Millisecond, func(payload []byte) error {
			return route.WriteWebSocketText(connection, payload)
		})
		return
	}

	flusher, ok := writer.(http.Flusher)
	if !ok {
		http.Error(writer, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	controller := http.NewResponseController(writer)
	go func() {
		<-ctx.Done()
		_ = controller.SetWriteDeadline(time.Now())
	}()
	runConnectionEvents(ctx, time.Duration(interval)*time.Millisecond, func(payload []byte) error {
		if _, err := writer.Write(append(payload, '\n')); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	})
}

func runConnectionEvents(ctx context.Context, interval time.Duration, send func([]byte) error) {
	changes, release := subscribeConnectionChanges()
	defer release()

	tracker := newConnectionEventTracker()
	if payload, ok := tracker.open(liveConnectionInfos()); !ok || send(payload) != nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case change := <-changes:
			var events []connectionEvent
			if event := tracker.apply(change); event != nil {
				events = append(events, *event)
			}
		drain:
			for {
				select {
				case change = <-changes:
					if event := tracker.apply(change); event != nil {
						events = append(events, *event)
					}
				default:
					break drain
				}
			}
			if len(events) == 0 {
				continue
			}
			if payload, ok := encodeConnectionEvents(false, events); ok && send(payload) != nil {
				return
			}
		case now := <-ticker.C:
			if payload, ok := tracker.step(liveConnectionInfos(), now); ok && send(payload) != nil {
				return
			}
		}
	}
}
