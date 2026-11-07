//go:build !darwin

package tun

func UtunControlName(fd int) (string, bool) {
	return "", false
}
