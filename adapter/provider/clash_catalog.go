package provider

import (
	"time"
)

func (pp *proxySetProvider) LoadDetached(buf []byte, updatedAt time.Time) error {
	proxies, err := pp.Fetcher.Parse(buf)
	if err != nil {
		return err
	}
	pp.Fetcher.SetUpdatedAt(updatedAt)
	pp.mutex.Lock()
	defer pp.mutex.Unlock()
	pp.list = proxies
	pp.version += 1
	pp.healthCheck.setProxyList(proxies)
	return nil
}
