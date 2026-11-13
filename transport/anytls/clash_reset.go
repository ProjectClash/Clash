package anytls

func (c *Client) Reset() {
	c.sessionClient.Reset()
}
