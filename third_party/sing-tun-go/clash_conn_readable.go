package tun

import "context"

func (c *GoConn) WaitReadable() error {
	err := c.awaitHandshake(context.Background(), c.readDeadline.Wait())
	if err != nil {
		return err
	}
	c.readAccess.Lock()
	err = c.waitReadableLocked()
	c.readAccess.Unlock()
	c.engine.reapAfterExit()
	return err
}

func (c *GoConn) waitReadableLocked() error {
	for {
		if c.receiveAvailable.Load() > c.consumedTail.Load() {
			return nil
		}
		if !c.readable() {
			return c.receiveResult()
		}
		result := c.receiveResult()
		if result != nil {
			return result
		}
		c.receiveTarget.buffer = nil
		c.receiveTarget.direct = clashEmptyTarget[:]
		delivered, parkErr := c.parkReader()
		c.receiveTarget.direct = nil
		if delivered {
			continue
		}
		if parkErr != nil {
			return parkErr
		}
	}
}

var clashEmptyTarget [0]byte
