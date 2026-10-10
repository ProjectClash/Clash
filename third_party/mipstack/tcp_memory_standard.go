//go:build !with_low_memory

package mipstack

const (
	tcpFitSmallSendSpare = false
	tcpReadChunkRetain = 64
	tcpSendChunkInitial = 2 * 1024
	tcpReusableSendChunkLimit = 32 * 1024
)
