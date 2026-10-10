package mmdb

import (
	"fmt"
	"os"
)

const MaxDatabaseBytes int64 = 64 << 20

func checkDatabaseSize(path string, size int64) error {
	if size > MaxDatabaseBytes {
		return fmt.Errorf("mmdb: %s is %d bytes, larger than the %d MiB this opens", path, size, MaxDatabaseBytes>>20)
	}
	return nil
}

func statDatabaseSize(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return checkDatabaseSize(path, info.Size())
}
