package compiled

import (
	"io"

	"github.com/klauspost/compress/zstd"
)

func NewLowMemoryReader(r io.Reader, opts ...zstd.DOption) (*zstd.Decoder, error) {
	return zstd.NewReader(r, append([]zstd.DOption{
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderLowmem(true),
	}, opts...)...)
}
