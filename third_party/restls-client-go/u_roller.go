package tls

import (
	"net"
	"sync"
	"time"
)

type Roller struct {
	HelloIDs            []ClientHelloID
	HelloIDMu           sync.Mutex
	WorkingHelloID      *ClientHelloID
	TcpDialTimeout      time.Duration
	TlsHandshakeTimeout time.Duration
	r                   *prng
}

func NewRoller() (*Roller, error) {
	r, err := newPRNG()
	if err != nil {
		return nil, err
	}

	tcpDialTimeoutInc := r.Intn(14)
	tcpDialTimeoutInc = 7 + tcpDialTimeoutInc

	tlsHandshakeTimeoutInc := r.Intn(20)
	tlsHandshakeTimeoutInc = 11 + tlsHandshakeTimeoutInc

	return &Roller{
		HelloIDs: []ClientHelloID{
			HelloChrome_Auto,
			HelloFirefox_Auto,
			HelloIOS_Auto,
			HelloRandomized,
		},
		TcpDialTimeout:      time.Second * time.Duration(tcpDialTimeoutInc),
		TlsHandshakeTimeout: time.Second * time.Duration(tlsHandshakeTimeoutInc),
		r:                   r,
	}, nil
}

func (c *Roller) Dial(network, addr, serverName string) (*UConn, error) {
	helloIDs := make([]ClientHelloID, len(c.HelloIDs))
	copy(helloIDs, c.HelloIDs)
	c.r.rand.Shuffle(len(c.HelloIDs), func(i, j int) {
		helloIDs[i], helloIDs[j] = helloIDs[j], helloIDs[i]
	})

	c.HelloIDMu.Lock()
	workingHelloId := c.WorkingHelloID
	c.HelloIDMu.Unlock()
	if workingHelloId != nil {
		helloIDFound := false
		for i, ID := range helloIDs {
			if ID == *workingHelloId {
				helloIDs[i] = helloIDs[0]
				helloIDs[0] = *workingHelloId
				helloIDFound = true
				break
			}
		}
		if !helloIDFound {
			helloIDs = append([]ClientHelloID{*workingHelloId}, helloIDs...)
		}
	}

	var tcpConn net.Conn
	var err error
	for _, helloID := range helloIDs {
		tcpConn, err = net.DialTimeout(network, addr, c.TcpDialTimeout)
		if err != nil {
			return nil, err
		}

		client := UClient(tcpConn, nil, helloID)
		client.SetSNI(serverName)
		client.SetDeadline(time.Now().Add(c.TlsHandshakeTimeout))
		err = client.Handshake()
		client.SetDeadline(time.Time{})
		if err != nil {
			continue
		}

		c.HelloIDMu.Lock()
		c.WorkingHelloID = &client.ClientHelloID
		c.HelloIDMu.Unlock()
		return client, err
	}
	return nil, err
}
