package tun

func (c *GoConn) QueuedSendBytes() (int, bool) {
	buffered, released := c.bufferedTail.Load(), c.sendReleased.Load()
	if released >= buffered {
		return 0, true
	}
	return int(buffered - released), true
}
