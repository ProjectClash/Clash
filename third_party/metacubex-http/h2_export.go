//go:build !nethttpomithttp2

package http

import "io"

func Http2ConfigureServer(s *Server, conf *http2Server) error {
	return http2ConfigureServer(s, conf)
}
func Http2ConfigureTransport(t1 *Transport) error {
	return http2ConfigureTransport(t1)
}
func Http2ReadFrameHeader(r io.Reader) (Http2FrameHeader, error) {
	return http2ReadFrameHeader(r)
}
func Http2NewFramer(w io.Writer, r io.Reader) *Http2Framer {
	return http2NewFramer(w, r)
}
func Http2ConfigureTransports(t1 *Transport) (*Http2Transport, error) {
	return http2ConfigureTransports(t1)
}
func Http2NewPriorityWriteScheduler(cfg *Http2PriorityWriteSchedulerConfig) Http2WriteScheduler {
	return http2NewPriorityWriteScheduler(cfg)
}
func Http2NewRandomWriteScheduler() Http2WriteScheduler {
	return http2NewRandomWriteScheduler()
}

type Http2ClientConn = http2ClientConn
type Http2ClientConnPool = http2ClientConnPool
type Http2ClientConnIdleState = http2clientConnIdleState
type Http2ConnectionError = http2ConnectionError
type Http2ContinuationFrame = http2ContinuationFrame
type Http2DataFrame = http2DataFrame
type Http2ErrCode = http2ErrCode
type Http2Flags = http2Flags
type Http2Frame = http2Frame
type Http2FrameHeader = http2FrameHeader
type Http2FrameType = http2FrameType
type Http2FrameWriteRequest = http2FrameWriteRequest
type Http2Framer = http2Framer
type Http2GoAwayError = http2GoAwayError
type Http2GoAwayFrame = http2GoAwayFrame
type Http2HeadersFrame = http2HeadersFrame
type Http2HeadersFrameParam = http2HeadersFrameParam
type Http2MetaHeadersFrame = http2MetaHeadersFrame
type Http2OpenStreamOptions = http2OpenStreamOptions
type Http2PingFrame = http2PingFrame
type Http2PriorityFrame = http2PriorityFrame
type Http2PriorityParam = http2PriorityParam
type Http2PriorityWriteSchedulerConfig = http2PriorityWriteSchedulerConfig
type Http2PushPromiseFrame = http2PushPromiseFrame
type Http2PushPromiseParam = http2PushPromiseParam
type Http2RSTStreamFrame = http2RSTStreamFrame
type Http2RoundTripOpt = http2RoundTripOpt
type Http2ServeConnOpts = http2ServeConnOpts
type Http2Server = http2Server
type Http2Setting = http2Setting
type Http2SettingID = http2SettingID
type Http2SettingsFrame = http2SettingsFrame
type Http2StreamError = http2StreamError
type Http2Transport = http2Transport
type Http2UnknownFrame = http2UnknownFrame
type Http2WindowUpdateFrame = http2WindowUpdateFrame
type Http2WriteScheduler = http2WriteScheduler

const Http2ClientPreface = http2ClientPreface
const Http2NextProtoTLS = http2NextProtoTLS
const Http2TrailerPrefix = http2TrailerPrefix

var Http2ErrRecursivePush = http2ErrRecursivePush
var Http2ErrPushLimitReached = http2ErrPushLimitReached
var Http2ErrFrameTooLarge = http2ErrFrameTooLarge
var Http2ErrNoCachedConn = http2ErrNoCachedConn

const (
	Http2ErrCodeNo                 = http2ErrCodeNo
	Http2ErrCodeProtocol           = http2ErrCodeProtocol
	Http2ErrCodeInternal           = http2ErrCodeInternal
	Http2ErrCodeFlowControl        = http2ErrCodeFlowControl
	Http2ErrCodeSettingsTimeout    = http2ErrCodeSettingsTimeout
	Http2ErrCodeStreamClosed       = http2ErrCodeStreamClosed
	Http2ErrCodeFrameSize          = http2ErrCodeFrameSize
	Http2ErrCodeRefusedStream      = http2ErrCodeRefusedStream
	Http2ErrCodeCancel             = http2ErrCodeCancel
	Http2ErrCodeCompression        = http2ErrCodeCompression
	Http2ErrCodeConnect            = http2ErrCodeConnect
	Http2ErrCodeEnhanceYourCalm    = http2ErrCodeEnhanceYourCalm
	Http2ErrCodeInadequateSecurity = http2ErrCodeInadequateSecurity
	Http2ErrCodeHTTP11Required     = http2ErrCodeHTTP11Required
)

const (
	Http2FlagDataEndStream = http2FlagDataEndStream
	Http2FlagDataPadded    = http2FlagDataPadded

	Http2FlagHeadersEndStream  = http2FlagHeadersEndStream
	Http2FlagHeadersEndHeaders = http2FlagHeadersEndHeaders
	Http2FlagHeadersPadded     = http2FlagHeadersPadded
	Http2FlagHeadersPriority   = http2FlagHeadersPriority

	Http2FlagSettingsAck = http2FlagSettingsAck

	Http2FlagPingAck = http2FlagPingAck

	Http2FlagContinuationEndHeaders = http2FlagContinuationEndHeaders

	Http2FlagPushPromiseEndHeaders = http2FlagPushPromiseEndHeaders
	Http2FlagPushPromisePadded     = http2FlagPushPromisePadded
)

const (
	Http2FrameData         = http2FrameData
	Http2FrameHeaders      = http2FrameHeaders
	Http2FramePriority     = http2FramePriority
	Http2FrameRSTStream    = http2FrameRSTStream
	Http2FrameSettings     = http2FrameSettings
	Http2FramePushPromise  = http2FramePushPromise
	Http2FramePing         = http2FramePing
	Http2FrameGoAway       = http2FrameGoAway
	Http2FrameWindowUpdate = http2FrameWindowUpdate
	Http2FrameContinuation = http2FrameContinuation
)

const (
	Http2SettingHeaderTableSize       = http2SettingHeaderTableSize
	Http2SettingEnablePush            = http2SettingEnablePush
	Http2SettingMaxConcurrentStreams  = http2SettingMaxConcurrentStreams
	Http2SettingInitialWindowSize     = http2SettingInitialWindowSize
	Http2SettingMaxFrameSize          = http2SettingMaxFrameSize
	Http2SettingMaxHeaderListSize     = http2SettingMaxHeaderListSize
	Http2SettingEnableConnectProtocol = http2SettingEnableConnectProtocol
)
