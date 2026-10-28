//go:build clash_internal

package clash

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

func init() {
	if !godebugSetsMemProfileRate(os.Getenv("GODEBUG")) {
		runtime.MemProfileRate = 512 * 1024
	}
}

func godebugSetsMemProfileRate(godebug string) bool {
	for _, field := range strings.Split(godebug, ",") {
		key, value, _ := strings.Cut(field, "=")
		if key != "memprofilerate" {
			continue
		}
		if _, err := strconv.Atoi(value); err == nil {
			return true
		}
	}
	return false
}

func memoryProfilingForDebug(bool) {}
