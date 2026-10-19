//go:build !darwin

package tun

func ipRewriteFrame(packet []byte) []byte { return packet }
