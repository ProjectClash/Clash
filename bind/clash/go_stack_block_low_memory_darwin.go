//go:build darwin && with_low_memory

package clash

const goStreamBlock = 16 << 10

const goStackUDPNATMax = 1024
