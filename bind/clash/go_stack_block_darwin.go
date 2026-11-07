//go:build darwin && !with_low_memory

package clash

const goStreamBlock = 32 << 10

const goStackUDPNATMax = 0
