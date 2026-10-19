package xhttp

import (
	"errors"
	"net"
	"sync/atomic"

	"github.com/metacubex/http"
)

func (c *Client) ReuseConfigs() (upload, download *ReuseConfig) {
	if c.uploadManager == nil {
		return nil, nil
	}
	upload = c.cfg.ReuseConfig
	if c.downloadManager != nil && c.cfg.DownloadConfig != nil {
		download = c.cfg.DownloadConfig.ReuseConfig
	}
	return upload, download
}

func (c *Client) Reuses() bool { return c.uploadManager != nil }

func (c *Client) Reset() {
	c.uploadManager.reset()
	c.downloadManager.reset()
}

func (m *ReuseManager) reset() {
	if m == nil {
		return
	}
	m.mu.Lock()
	entries := m.entries
	m.entries = make([]*reuseEntry, 0, len(entries))
	m.mu.Unlock()
	for _, entry := range entries {
		entry.close()
	}
}

var errTransportClosed = errors.New("xhttp: the transport was closed while this dial was in flight")

type closedTransport struct {
	*http.Transport
	closed *atomic.Bool
}

func closableTransport(closed *atomic.Bool, transport *http.Transport) http.RoundTripper {
	return &closedTransport{Transport: transport, closed: closed}
}

func (t *closedTransport) CloseIdleConnections() {
	t.closed.Store(true)
	t.Transport.CloseIdleConnections()
}

func (t *closedTransport) Close() error {
	t.CloseIdleConnections()
	return nil
}

func openUnlessClosed(closed *atomic.Bool, conn net.Conn) (net.Conn, error) {
	if closed.Load() {
		_ = conn.Close()
		return nil, errTransportClosed
	}
	return conn, nil
}
