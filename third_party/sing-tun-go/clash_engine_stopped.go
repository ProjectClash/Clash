package tun

import "sync"

func (s *Go) EngineStopped() <-chan struct{} {
	s.access.Lock()
	engines := s.engines
	s.access.Unlock()
	if len(engines) == 0 {
		return nil
	}
	stopped := make(chan struct{})
	var once sync.Once
	for _, engine := range engines {
		go func(exited <-chan struct{}) {
			<-exited
			once.Do(func() { close(stopped) })
		}(engine.exitSignal)
	}
	return stopped
}

func (s *Go) Closed() bool {
	return s.closed.Load()
}
