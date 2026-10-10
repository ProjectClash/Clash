package clash

import (
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/klauspost/compress/zstd"
)

var providerBuildGate sync.Mutex

var providerBuildReserved atomic.Int64

var buildMemoryReader = struct {
	sync.Mutex
	read            func() int64
	zeroIsExhausted bool
}{read: availableMemory, zeroIsExhausted: zeroHeadroomMeansExhausted}

func readBuildMemory() (available int64, zeroIsExhausted bool) {
	buildMemoryReader.Lock()
	read, zero := buildMemoryReader.read, buildMemoryReader.zeroIsExhausted
	buildMemoryReader.Unlock()
	return read(), zero
}

const (
	providerBuildFloorBytes         = 4 << 20
	providerBuildTextFactor         = 10.0
	providerBuildClassicalFactor    = 6.0
	providerBuildProxyPayloadFactor = 10.0
	providerBuildMRSFactor          = 4.0
)

func estimateProviderBuildBytes(kind, variant, behavior string, payloadBytes int, product []byte) int64 {
	n := float64(payloadBytes)
	switch {
	case kind == "proxy":
		return providerBuildFloorBytes + int64(n*providerBuildProxyPayloadFactor)
	case variant == "mrs" || (variant == "compiled" && product != nil):
		return mrsReadFloor(product) + int64(n*providerBuildMRSFactor)
	case variant == "compiled":
		return providerBuildFloorBytes + 2<<20 + int64(n*providerBuildTextFactor)
	case strings.EqualFold(strings.TrimSpace(behavior), "classical"):
		return providerBuildFloorBytes + int64(n*providerBuildClassicalFactor)
	default:
		return providerBuildFloorBytes + int64(n*providerBuildTextFactor)
	}
}

func mrsReadFloor(artifact []byte) int64 {
	const fallback = 12 << 20
	var header zstd.Header
	if len(artifact) == 0 || header.Decode(artifact) != nil || header.WindowSize == 0 {
		return fallback
	}
	return int64(header.WindowSize) + providerBuildFloorBytes
}

func judgeProviderBuild(needed int64) (fits bool, available int64) {
	available, zeroIsExhausted := readBuildMemory()
	if available == 0 && zeroIsExhausted {
		return false, 0
	}
	if available <= 0 {
		return true, available
	}
	debug.FreeOSMemory()
	available, zeroIsExhausted = readBuildMemory()
	if available == 0 && zeroIsExhausted {
		return false, 0
	}
	if available <= 0 {
		return true, available
	}
	return needed <= available, available
}
