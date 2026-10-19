package http

type CloseHttp2Connections interface {
	CloseHttp2Connections()
}

func (p *http2clientConnPool) CloseHttp2Connections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, vv := range p.conns {
		for _, cc := range vv {
			cc.closeConn()
		}
	}
	p.conns = make(map[string][]*http2ClientConn)
	p.keys = make(map[*http2ClientConn][]string)
}

func (t *http2Transport) CloseHttp2Connections() {
	if p, _ := t.connPool().(CloseHttp2Connections); p != nil {
		p.CloseHttp2Connections()
	}
}

func (t *Transport) CloseHttp2Connections() {
	if t2, _ := t.h2transport.(CloseHttp2Connections); t2 != nil {
		t2.CloseHttp2Connections()
	}
}
