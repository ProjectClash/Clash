//go:build !darwin || !cgo

package clash

func processCPUTimeNanoseconds() int64 { return -1 }
