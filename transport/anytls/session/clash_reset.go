package session

func (c *Client) Reset() {
	c.sessionsLock.Lock()
	sessionToClose := make([]*Session, 0, len(c.sessions))
	for _, session := range c.sessions {
		sessionToClose = append(sessionToClose, session)
	}
	c.sessionsLock.Unlock()

	for _, session := range sessionToClose {
		session.Close()
	}
}
