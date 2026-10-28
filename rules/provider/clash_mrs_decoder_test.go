package provider_test

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"testing"

	P "github.com/ProjectClash/Clash/constant/provider"
	RP "github.com/ProjectClash/Clash/rules/provider"

	"github.com/klauspost/compress/zstd"
)

func TestAnMrsIsDecodedInTheReadersGoroutineWithLessMemory(t *testing.T) {
	lines := make([]string, 0, 200_000)
	for i := 0; i < cap(lines); i++ {
		lines = append(lines, fmt.Sprintf("+.d%06d.example%d.com", i, i%97))
	}
	payload := mrsOf(t, P.Domain, lines)
	decode := func(open func(io.Reader) (*zstd.Decoder, error)) (goroutines int, allocated uint64) {
		t.Helper()
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		baseline := runtime.NumGoroutine()
		decoder, err := open(bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		var first [1]byte
		if _, err := io.ReadFull(decoder, first[:]); err != nil {
			t.Fatal(err)
		}
		goroutines = runtime.NumGoroutine() - baseline
		if _, err := io.Copy(io.Discard, decoder); err != nil {
			t.Fatal(err)
		}
		decoder.Close()
		runtime.ReadMemStats(&after)
		return goroutines, after.TotalAlloc - before.TotalAlloc
	}
	upstreamGoroutines, upstreamAllocated := decode(func(r io.Reader) (*zstd.Decoder, error) { return zstd.NewReader(r) })
	goroutines, allocated := decode(RP.ClashMrsReaderForTest)
	t.Logf("%d-byte MRS: %d goroutines and %d bytes allocated upstream, %d and %d here", len(payload), upstreamGoroutines, upstreamAllocated, goroutines, allocated)
	if goroutines != 0 {
		t.Errorf("decoding started %d goroutines; the reader's own goroutine is to do it", goroutines)
	}
	if runtime.GOMAXPROCS(0) > 1 && upstreamGoroutines == 0 {
		t.Errorf("zstd's defaults started no goroutines here either; the test no longer tells the two apart")
	}
	if allocated > upstreamAllocated {
		t.Errorf("decoding allocated %d bytes, more than the %d of zstd's defaults", allocated, upstreamAllocated)
	}
}
