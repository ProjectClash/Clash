package http2

type CloseHttp2Connections interface {
	CloseHttp2Connections()
}

func (p *clientConnPool) CloseHttp2Connections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, vv := range p.conns {
		for _, cc := range vv {
			cc.closeConn()
		}
	}
	p.conns = make(map[string][]*ClientConn)
	p.keys = make(map[*ClientConn][]string)
}

func (t *Transport) CloseHttp2Connections() {
	if p, _ := t.connPool().(CloseHttp2Connections); p != nil {
		p.CloseHttp2Connections()
	}
}
