package resource

import "time"

func (f *Fetcher[V]) Parse(buf []byte) (V, error) {
	return f.parser(buf)
}

func (f *Fetcher[V]) SetUpdatedAt(t time.Time) {
	f.loadBufMutex.Lock()
	defer f.loadBufMutex.Unlock()
	f.updatedAt = t
}
