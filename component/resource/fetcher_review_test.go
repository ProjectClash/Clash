package resource

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/common/utils"
)



func TestASideUpdateEndsTheDeferredFirstLoad(t *testing.T) {
	withDeferredFetch(t, 20*time.Millisecond, 60*time.Millisecond)
	vehicle := &scriptedVehicle{path: filepath.Join(t.TempDir(), "list"), failures: 1 << 20, payload: []byte("never")}
	fetcher, updates, mu := newDeferredFetcher(t, vehicle, 0)
	if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
		t.Fatalf("Initial err = %v", err)
	}
	waitFor(t, "the first failed attempt", 5*time.Second, func() bool { return vehicle.reads.Load() >= 1 })

	if _, _, err := fetcher.SideUpdate([]byte("from the app")); err != nil {
		t.Fatalf("SideUpdate: %v", err)
	}
	settled := vehicle.reads.Load() + 1
	time.Sleep(400 * time.Millisecond)
	if reads := vehicle.reads.Load(); reads > settled {
		t.Fatalf("the background first load kept downloading after a side update loaded the provider: reads went to %d (allowed %d)", reads, settled)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*updates) != 1 || (*updates)[0] != "from the app" {
		t.Fatalf("updates = %v, want exactly the side update", *updates)
	}
}

func TestBothPathsCompletingTheFirstLoadStartExactlyOnePullLoop(t *testing.T) {
	withDeferredFetch(t, 20*time.Millisecond, 60*time.Millisecond)
	const interval = 150 * time.Millisecond
	block := make(chan struct{})
	vehicle := &scriptedVehicle{path: filepath.Join(t.TempDir(), "list"), payload: []byte("same"), block: block}
	fetcher, _, _ := newDeferredFetcher(t, vehicle, interval)
	if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
		t.Fatalf("Initial err = %v", err)
	}
	waitFor(t, "the first attempt to enter Read", 5*time.Second, func() bool { return vehicle.reads.Load() == 1 })
	if _, _, err := fetcher.SideUpdate([]byte("same")); err != nil {
		t.Fatalf("SideUpdate: %v", err)
	}
	close(block)
	waitFor(t, "the in-flight attempt to return", 5*time.Second, func() bool { return vehicle.reads.Load() >= 2 })
	before := vehicle.reads.Load()
	const window = time.Second
	time.Sleep(window)
	ticks := vehicle.reads.Load() - before
	maxForOneLoop := int32(window/interval) + 2
	if ticks == 0 {
		t.Fatal("no pull loop is running after the first load completed")
	}
	if ticks > maxForOneLoop {
		t.Fatalf("%d reads in %s at interval %s: more than one pull loop is running (one loop: at most %d)", ticks, window, interval, maxForOneLoop)
	}
}

func TestASideUpdateStillHandsOverToThePullLoopWhenTheDownloadNeverSucceeds(t *testing.T) {
	withDeferredFetch(t, 20*time.Millisecond, 60*time.Millisecond)
	vehicle := &scriptedVehicle{path: filepath.Join(t.TempDir(), "list"), failures: 1 << 20, payload: []byte("never")}
	fetcher, _, _ := newDeferredFetcher(t, vehicle, 100*time.Millisecond)
	if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
		t.Fatalf("Initial err = %v", err)
	}
	waitFor(t, "the first failed attempt", 5*time.Second, func() bool { return vehicle.reads.Load() >= 1 })
	if _, _, err := fetcher.SideUpdate([]byte("from the app")); err != nil {
		t.Fatalf("SideUpdate: %v", err)
	}
	before := vehicle.reads.Load() + 1
	waitFor(t, "the pull loop's first refresh", 5*time.Second, func() bool { return vehicle.reads.Load() > before })
}

func TestASideUpdateBeforeTheFirstAttemptSpendsNoDownload(t *testing.T) {
	withDeferredFetch(t, 200*time.Millisecond, time.Second)
	vehicle := &scriptedVehicle{path: filepath.Join(t.TempDir(), "list"), failures: 1 << 20, block: make(chan struct{})}
	fetcher, _, _ := newDeferredFetcher(t, vehicle, 0)
	if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
		t.Fatalf("Initial err = %v", err)
	}
	waitFor(t, "the first attempt to enter Read", 5*time.Second, func() bool { return vehicle.reads.Load() == 1 })
	if _, _, err := fetcher.SideUpdate([]byte("from the app")); err != nil {
		t.Fatalf("SideUpdate: %v", err)
	}
	close(vehicle.block)
	time.Sleep(500 * time.Millisecond)
	if reads := vehicle.reads.Load(); reads != 1 {
		t.Fatalf("a second attempt was scheduled after the side update: reads = %d", reads)
	}
}


func TestUpdateAndSideUpdateDoNotRaceOnTheHash(t *testing.T) {
	withDeferredFetch(t, time.Millisecond, 5*time.Millisecond)
	vehicle := &scriptedVehicle{path: filepath.Join(t.TempDir(), "list"), payload: []byte("remote")}
	fetcher, _, _ := newDeferredFetcher(t, vehicle, 2*time.Millisecond)
	if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
		t.Fatalf("Initial err = %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _, _ = fetcher.SideUpdate([]byte(fmt.Sprintf("side-%d-%d", i, j)))
				_, _, _ = fetcher.Update()
			}
		}(i)
	}
	wg.Wait()
}


func withFirstLoadConcurrency(t *testing.T, n int) {
	t.Helper()
	prev := FirstLoadConcurrency()
	SetFirstLoadConcurrency(n)
	t.Cleanup(func() { SetFirstLoadConcurrency(prev) })
}

func TestDeferredFirstLoadsShareOneAdmission(t *testing.T) {
	withDeferredFetch(t, 20*time.Millisecond, 60*time.Millisecond)
	withFirstLoadConcurrency(t, 2)
	const providers = 6
	block := make(chan struct{})
	vehicles := make([]*scriptedVehicle, providers)
	for i := range vehicles {
		vehicles[i] = &scriptedVehicle{path: filepath.Join(t.TempDir(), fmt.Sprintf("list-%d", i)), payload: []byte("payload"), block: block}
		fetcher, _, _ := newDeferredFetcher(t, vehicles[i], 0)
		if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
			t.Fatalf("Initial %d err = %v", i, err)
		}
	}
	inFlight := func() int32 {
		var n int32
		for _, v := range vehicles {
			n += v.reads.Load()
		}
		return n
	}
	waitFor(t, "two downloads to start", 5*time.Second, func() bool { return inFlight() == 2 })
	time.Sleep(300 * time.Millisecond)
	if n := inFlight(); n != 2 {
		t.Fatalf("%d downloads in flight with an admission of 2; the bound does not cover the background first load", n)
	}
	close(block)
	waitFor(t, "every provider to load and write", 5*time.Second, func() bool {
		for _, v := range vehicles {
			if v.written.Load() != 1 {
				return false
			}
		}
		return true
	})
}

func TestCloseReleasesADeferredFirstLoadWaitingForAdmission(t *testing.T) {
	withDeferredFetch(t, 20*time.Millisecond, 60*time.Millisecond)
	withFirstLoadConcurrency(t, 1)
	block := make(chan struct{})
	type pair struct {
		vehicle *scriptedVehicle
		fetcher *Fetcher[string]
	}
	var pairs [2]pair
	for i := range pairs {
		vehicle := &scriptedVehicle{path: filepath.Join(t.TempDir(), fmt.Sprintf("list-%d", i)), payload: []byte("p"), block: block}
		fetcher, _, _ := newDeferredFetcher(t, vehicle, 0)
		if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
			t.Fatalf("Initial %d err = %v", i, err)
		}
		pairs[i] = pair{vehicle, fetcher}
	}
	waitFor(t, "one of the two to enter Read", 5*time.Second, func() bool {
		return pairs[0].vehicle.reads.Load()+pairs[1].vehicle.reads.Load() == 1
	})
	time.Sleep(100 * time.Millisecond)
	holder, waiter := pairs[0], pairs[1]
	if holder.vehicle.reads.Load() == 0 {
		holder, waiter = pairs[1], pairs[0]
	}
	if waiter.vehicle.reads.Load() != 0 {
		t.Fatal("both were admitted with an admission of 1")
	}
	_ = waiter.fetcher.Close()
	close(block)
	waitFor(t, "the holder to finish", 5*time.Second, func() bool { return holder.vehicle.written.Load() == 1 })
	time.Sleep(200 * time.Millisecond)
	if waiter.vehicle.reads.Load() != 0 {
		t.Fatal("a closed fetcher was admitted and downloaded anyway")
	}
}

func TestWithoutAnAdmissionDeferredFirstLoadsRunUnbounded(t *testing.T) {
	withDeferredFetch(t, 20*time.Millisecond, 60*time.Millisecond)
	withFirstLoadConcurrency(t, 0)
	const providers = 4
	block := make(chan struct{})
	vehicles := make([]*scriptedVehicle, providers)
	for i := range vehicles {
		vehicles[i] = &scriptedVehicle{path: filepath.Join(t.TempDir(), fmt.Sprintf("list-%d", i)), payload: []byte("payload"), block: block}
		fetcher, _, _ := newDeferredFetcher(t, vehicles[i], 0)
		if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
			t.Fatalf("Initial %d err = %v", i, err)
		}
	}
	waitFor(t, "every download to start at once (upstream's unbounded default)", 5*time.Second, func() bool {
		var n int32
		for _, v := range vehicles {
			n += v.reads.Load()
		}
		return n == providers
	})
}


func withDefaultRemoteSizeLimit(t *testing.T, limit int64) {
	t.Helper()
	prev := DefaultRemoteSizeLimit
	DefaultRemoteSizeLimit = limit
	t.Cleanup(func() { DefaultRemoteSizeLimit = prev })
}

func sizedServer(t *testing.T, body *atomic.Pointer[[]byte]) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(*body.Load())
	}))
	t.Cleanup(server.Close)
	return server
}

func TestADefaultedSizeLimitRefusesAnOversizedBodyInsteadOfTruncatingIt(t *testing.T) {
	withDefaultRemoteSizeLimit(t, 1024)
	var body atomic.Pointer[[]byte]
	over := []byte(strings.Repeat("x", 1025))
	body.Store(&over)
	server := sizedServer(t, &body)

	vehicle := NewHTTPVehicle(server.URL, filepath.Join(t.TempDir(), "list"), "", nil, 5*time.Second, 0)
	buf, hash, err := vehicle.Read(context.Background(), utils.HashType{})
	if err == nil {
		t.Fatalf("a %d-byte body under a %d-byte default cap was accepted: got %d bytes, no error", len(over), 1024, len(buf))
	}
	if !strings.Contains(err.Error(), "1024") {
		t.Fatalf("the error must name the cap so the reader can raise it: %v", err)
	}
	if hash.IsValid() {
		t.Fatal("no hash may be reported for a body that was refused")
	}

	exact := []byte(strings.Repeat("y", 1024))
	body.Store(&exact)
	buf, _, err = vehicle.Read(context.Background(), utils.HashType{})
	if err != nil || len(buf) != 1024 {
		t.Fatalf("a body exactly at the cap must load whole: len=%d err=%v", len(buf), err)
	}
}

func TestAnExplicitSizeLimitKeepsUpstreamsTruncation(t *testing.T) {
	withDefaultRemoteSizeLimit(t, 1024)
	var body atomic.Pointer[[]byte]
	over := []byte(strings.Repeat("x", 2000))
	body.Store(&over)
	server := sizedServer(t, &body)

	vehicle := NewHTTPVehicle(server.URL, filepath.Join(t.TempDir(), "list"), "", nil, 5*time.Second, 1500)
	buf, _, err := vehicle.Read(context.Background(), utils.HashType{})
	if err != nil || len(buf) != 1500 {
		t.Fatalf("explicit size-limit is upstream's truncating semantics: len=%d err=%v", len(buf), err)
	}
}

func TestAnOversizedRefreshKeepsTheContentAlreadyLoaded(t *testing.T) {
	withDefaultRemoteSizeLimit(t, 64)
	var body atomic.Pointer[[]byte]
	small := []byte("rule-a\nrule-b\n")
	body.Store(&small)
	server := sizedServer(t, &body)

	var mu sync.Mutex
	var updates []string
	parser := func(buf []byte) (string, error) { return string(buf), nil }
	vehicle := NewHTTPVehicle(server.URL, filepath.Join(t.TempDir(), "list"), "", nil, 5*time.Second, 0)
	fetcher := NewFetcher[string]("sized", 0, vehicle, nil, parser, func(s string) {
		mu.Lock()
		defer mu.Unlock()
		updates = append(updates, s)
	})
	t.Cleanup(func() { _ = fetcher.Close() })
	if _, _, err := fetcher.Update(); err != nil {
		t.Fatalf("first load: %v", err)
	}
	loadedHash := fetcher.hash

	over := []byte(strings.Repeat("z", 65))
	body.Store(&over)
	if _, _, err := fetcher.Update(); err == nil {
		t.Fatal("an oversized refresh reported success")
	}
	if !fetcher.hash.Equal(loadedHash) {
		t.Fatal("an oversized refresh replaced the hash of the content still in use")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(updates) != 1 {
		t.Fatalf("an oversized refresh reached onUpdate: %v", updates)
	}
}
