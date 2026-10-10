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
