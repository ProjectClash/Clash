package provider

import (
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/ProjectClash/Clash/component/geodata/compiled"
)

func clashMrsReader(r io.Reader) (*zstd.Decoder, error) {
	return compiled.NewLowMemoryReader(r)
}
