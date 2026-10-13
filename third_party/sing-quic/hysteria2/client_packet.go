package hysteria2

import E "github.com/metacubex/sing/common/exceptions"

func (c *Client) loopMessages(conn *clientQUICConnection) {
	for {
		message, err := conn.quicConn.ReceiveDatagram(c.ctx)
		if err != nil {
			conn.closeWithError(E.Cause(err, "receive message"))
			return
		}
		hErr := c.handleMessage(conn, message)
		if hErr != nil {
			conn.closeWithError(E.Cause(hErr, "handle message"))
			return
		}
	}
}

func (c *Client) handleMessage(conn *clientQUICConnection, data []byte) error {
	message := allocMessage()
	err := decodeUDPMessage(message, data)
	if err != nil {
		message.releaseMessage()
		return E.Cause(err, "decode UDP message")
	}
	conn.handleUDPMessage(message)
	return nil
}

func (c *clientQUICConnection) handleUDPMessage(message *udpMessage) {
	c.udpAccess.RLock()
	udpConn, loaded := c.udpConnMap[message.sessionID]
	c.udpAccess.RUnlock()
	if !loaded {
		message.releaseMessage()
		return
	}
	select {
	case <-udpConn.ctx.Done():
		message.releaseMessage()
		return
	default:
	}
	udpConn.inputPacket(message)
}
