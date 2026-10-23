package clash

import (
	"fmt"
	"os"

	"github.com/ProjectClash/Clash/common/clashsum"
	"runtime/debug"
	"runtime/metrics"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

func readOnlyBytes(s string) []byte {
	if s == "" {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func withDocumentAt[T any](path string, f func(text string) (T, error)) (T, error) {
	return withDocumentAtKeyed(path, func(text string, _ publishParseKey, _ bool) (T, error) { return f(text) })
}

func withDocumentAtKeyed[T any](path string, f func(text string, key publishParseKey, keyed bool) (T, error)) (T, error) {
	var zero T
	file, info, err := openRegularFile(path)
	if err != nil {
		return zero, err
	}
	defer file.Close()
	if info.Size() > maxRuleDocument {
		return zero, fmt.Errorf("clash: %s is not a document of at most %d bytes", path, int64(maxRuleDocument))
	}
	stamp, keyed := clashsum.StampOf(info)
	key := publishParseKey{path: path, stamp: stamp}
	if info.Size() == 0 {
		return f("", key, keyed)
	}
	data, err := syscall.Mmap(int(file.Fd()), 0, int(info.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return zero, err
	}
	defer syscall.Munmap(data)
	return f(unsafe.String(unsafe.SliceData(data), len(data)), key, keyed)
}

func openRegularFile(path string) (*os.File, os.FileInfo, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, nil, fmt.Errorf("clash: %s is not a regular file", path)
	}
	return file, info, nil
}

var compactHeap struct {
	mu       sync.Mutex
	depth    int
	previous int
	stop     chan struct{}
}

const compactHeapPercent = 20

var compactHeapFloor uint64 = 64 << 20

func withCompactHeap[T any](f func() (T, error)) (T, error) {
	defer enterCompactHeap()()
	return f()
}

func enterCompactHeap() func() {
	compactHeap.mu.Lock()
	if compactHeap.depth == 0 {
		previous := debug.SetGCPercent(compactHeapPercent)
		if previous >= 0 && previous < compactHeapPercent {
			debug.SetGCPercent(previous)
		} else {
			compactHeap.stop = make(chan struct{})
			followLiveHeap(compactHeap.stop)
		}
		compactHeap.previous = previous
	}
	compactHeap.depth++
	compactHeap.mu.Unlock()
	return func() {
		compactHeap.mu.Lock()
		if compactHeap.depth--; compactHeap.depth == 0 {
			if compactHeap.stop != nil {
				close(compactHeap.stop)
				compactHeap.stop = nil
			}
			debug.SetGCPercent(compactHeap.previous)
		}
		compactHeap.mu.Unlock()
	}
}

const followLiveHeapEvery = 5 * time.Millisecond

func followLiveHeap(stop chan struct{}) {
	sample := []metrics.Sample{{Name: "/gc/cycles/total:gc-cycles"}, {Name: "/gc/heap/live:bytes"}}
	follow := func() uint64 {
		metrics.Read(sample)
		percent := compactHeapPercent
		if sample[1].Value.Kind() == metrics.KindUint64 {
			if live := sample[1].Value.Uint64(); live < compactHeapFloor*100/compactHeapPercent {
				percent = int(compactHeapFloor * 100 / max(live, 1<<20))
			}
		}
		debug.SetGCPercent(percent)
		if sample[0].Value.Kind() == metrics.KindUint64 {
			return sample[0].Value.Uint64()
		}
		return 0
	}
	cycles := follow()
	go func() {
		tick := time.NewTicker(followLiveHeapEvery)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
			}
			metrics.Read(sample[:1])
			if sample[0].Value.Kind() != metrics.KindUint64 || sample[0].Value.Uint64() == cycles {
				continue
			}
			compactHeap.mu.Lock()
			select {
			case <-stop:
			default:
				cycles = follow()
			}
			compactHeap.mu.Unlock()
		}
	}()
}
