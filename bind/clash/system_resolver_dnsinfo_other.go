//go:build !(darwin && cgo)

package clash

func dnsInfoAvailable() bool { return false }

func dnsInfoChanged() bool { return false }

func physicalResolversForInterface(int32) []string { return nil }
