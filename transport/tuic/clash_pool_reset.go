package tuic

func (t *PoolClient) Reset() {
	t.tcpClientsMutex.Lock()
	for it := t.tcpClients.Front(); it != nil; it = it.Next() {
		if it.Value != nil {
			it.Value.Close()
		}
	}
	t.tcpClients.Init()
	t.tcpClientsMutex.Unlock()

	t.udpClientsMutex.Lock()
	for it := t.udpClients.Front(); it != nil; it = it.Next() {
		if it.Value != nil {
			it.Value.Close()
		}
	}
	t.udpClients.Init()
	t.udpClientsMutex.Unlock()
}

type forceCloser interface {
	ForceClose()
}

func (t *PoolClient) Release() {
	closeNow := func(client Client) {
		if forced, ok := client.(forceCloser); ok {
			forced.ForceClose()
		} else {
			client.Close()
		}
	}
	t.tcpClientsMutex.Lock()
	for it := t.tcpClients.Front(); it != nil; it = it.Next() {
		if it.Value != nil {
			closeNow(it.Value)
		}
	}
	t.tcpClients.Init()
	t.tcpClientsMutex.Unlock()

	t.udpClientsMutex.Lock()
	for it := t.udpClients.Front(); it != nil; it = it.Next() {
		if it.Value != nil {
			closeNow(it.Value)
		}
	}
	t.udpClients.Init()
	t.udpClientsMutex.Unlock()
}
