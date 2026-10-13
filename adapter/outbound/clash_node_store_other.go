//go:build !unix

package outbound

import (
	"errors"
	"os"
)

func mapNodeRecords(*os.File, int) ([]byte, error) {
	return nil, errors.New("mapping node records is unix-only")
}

func unmapNodeRecords([]byte) {}

func nodeStoreProcessGone(int) bool { return false }
