//go:build !unix

package outbound

import "os"

func fileIdentity(os.FileInfo) (dev, ino uint64) { return 0, 0 }
