//go:build !darwin

package clash

func goStackRegionsKept() (regions int, bytes int64, notKept uint64) { return 0, 0, 0 }
