//go:build !darwin && !linux

package clashsum

import (
	"os"
	"time"
)

func stampOf(os.FileInfo) (Stamp, bool) { return Stamp{}, false }

func openFile(path string) (*os.File, error) { return os.Open(path) }

const platformRacyMargin = 100 * time.Millisecond
