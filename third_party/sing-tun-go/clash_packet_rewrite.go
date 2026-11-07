package tun

import E "github.com/sagernet/sing/common/exceptions"

type PacketRewrite func(packet []byte) (handled, writeBack bool, reply []byte)

func (s *Go) SetPacketRewrite(rewrite PacketRewrite) {
	if rewrite == nil {
		s.clashPacketRewrite.Store(nil)
		return
	}
	s.clashPacketRewrite.Store(&rewrite)
}

func (e *goEngine) clashRewritePacket(frame *goFrame) bool {
	rewrite := e.stack.clashPacketRewrite.Load()
	if rewrite == nil {
		return false
	}
	packet := frame.buffer.Bytes()
	handled, writeBack, reply := (*rewrite)(packet)
	if !handled {
		return false
	}
	out, meta := reply, ForwardFrameMeta{}
	if writeBack {
		out, meta = packet, frame.meta
	}
	if out != nil {
		err := e.platformIO.writeData(e.singleFrame(out), meta, nil, 0)
		if err == errGoTransmitBlocked {
			e.droppedHairpinFrames.record(e.stack.logger, "rewritten frames")
		} else if err != nil {
			e.stack.logger.Trace(E.Cause(err, "go: write rewritten frame"))
		}
	}
	return true
}
