//go:build !unix

package provider

import (
	"io"
	"os"
)

func mapClassicalIndex(file *os.File, size int) ([]byte, error) {
	data := make([]byte, size)
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, err
	}
	return data, nil
}

func unmapClassicalIndex([]byte) {}
