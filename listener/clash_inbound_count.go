package listener

func InboundListenerCount() int {
	inboundMux.Lock()
	defer inboundMux.Unlock()
	return len(inboundListeners)
}
