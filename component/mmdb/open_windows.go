//go:build windows

package mmdb

import (
	"io"
	"os"

	"github.com/oschwald/maxminddb-golang"
)

func openDatabaseFile(path string) (*maxminddb.Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := checkDatabaseSize(path, info.Size()); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, info.Size()))
	if err != nil {
		return nil, err
	}
	return maxminddb.FromBytes(data)
}
