package provider

import (
	"sync/atomic"

	"github.com/klauspost/compress/zstd"
)

var lowMemoryMrsEncoder atomic.Bool

func UseLowMemoryMrsEncoder() {
	lowMemoryMrsEncoder.Store(true)
}

func mrsEncoderOptions() []zstd.EOption {
	if !lowMemoryMrsEncoder.Load() {
		return nil
	}
	return []zstd.EOption{
		zstd.WithEncoderConcurrency(1),
		zstd.WithLowerEncoderMem(true),
		zstd.WithWindowSize(1 << 20),
	}
}
