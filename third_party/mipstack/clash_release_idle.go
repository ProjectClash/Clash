package mipstack

import "unsafe"


func (s *Stack) ReleaseIdleBacking() int {
	s.mu.Lock()
	connections := make([]*TCPConn, 0, len(s.tcp))
	for _, connection := range s.tcp {
		connections = append(connections, connection)
	}
	s.mu.Unlock()
	released := 0
	for _, connection := range connections {
		released += connection.releaseIdleBacking()
	}
	return released
}

func (c *TCPConn) releaseIdleBacking() int {
	released := 0
	c.mu.Lock()
	if c.sendBuffer.size == 0 && len(c.sendBuffer.chunks) == 0 && c.sendBuffer.spare != nil {
		released += cap(c.sendBuffer.spare)
		c.sendBuffer.spare = nil
	}
	if c.readBuffer.size == 0 && c.readBuffer.chunks != nil {
		released += cap(c.readBuffer.chunks) * int(unsafe.Sizeof([]byte{}))
		c.readBuffer.chunks = nil
		c.readBuffer.head = 0
	}
	c.mu.Unlock()
	q := &c.inbound
	q.mu.Lock()
	q.spare = nil
	if q.head == len(q.segments) && q.segments != nil {
		released += cap(q.segments) * int(unsafe.Sizeof(tcpSegment{}))
		q.segments = nil
		q.head = 0
	}
	q.mu.Unlock()
	return released
}
