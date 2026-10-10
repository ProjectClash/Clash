//go:build !darwin || !cgo

package clash

func startMemoryPressureMonitor() {}

func physFootprint() int64 { return -1 }

func availableMemory() int64 { return -1 }
