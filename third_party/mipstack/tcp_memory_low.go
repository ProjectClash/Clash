//go:build with_low_memory

package mipstack

const (
	tcpFitSmallSendSpare = true
	tcpReadChunkRetain = 32
	tcpSendChunkInitial = 1024
	tcpReusableSendChunkLimit = 16 * 1024
)
