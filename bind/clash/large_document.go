package clash

import (
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"syscall"
	"unsafe"
)

func readOnlyBytes(s string) []byte {
	if s == "" {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func withDocumentAt[T any](path string, f func(text string) (T, error)) (T, error) {
	var zero T
	file, info, err := openRegularFile(path)
	if err != nil {
		return zero, err
	}
	defer file.Close()
	if info.Size() > maxRuleDocument {
		return zero, fmt.Errorf("clash: %s is not a document of at most %d bytes", path, int64(maxRuleDocument))
	}
	if info.Size() == 0 {
		return f("")
	}
	data, err := syscall.Mmap(int(file.Fd()), 0, int(info.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return zero, err
	}
	defer syscall.Munmap(data)
	return f(unsafe.String(unsafe.SliceData(data), len(data)))
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
}

const compactHeapPercent = 20

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
		}
		compactHeap.previous = previous
	}
	compactHeap.depth++
	compactHeap.mu.Unlock()
	return func() {
		compactHeap.mu.Lock()
		if compactHeap.depth--; compactHeap.depth == 0 {
			debug.SetGCPercent(compactHeap.previous)
		}
		compactHeap.mu.Unlock()
	}
}
