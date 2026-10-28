//go:build !darwin || !cgo

package clash

func coreImageIdentity() string { return "" }
