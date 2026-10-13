package clash

import (
	"crypto/sha256"
	"sync/atomic"

	"github.com/ProjectClash/Clash/config"
)

type startedIntentRecord struct {
	sum   [sha256.Size]byte
	stack ipStackSettings
	data  []byte
}

var startedIntent atomic.Pointer[startedIntentRecord]

func rememberStartedIntent(text string, raw *config.RawConfig) {
	stack := currentIPStackSettings()
	decoded := *raw
	data, err := platformConfigIntentFromRawWithIPStack(&decoded, stack)
	if err != nil {
		startedIntent.Store(nil)
		return
	}
	startedIntent.Store(&startedIntentRecord{sum: textDigest(text), stack: stack, data: data})
}

func takeStartedIntent(text string) ([]byte, bool) {
	record := startedIntent.Load()
	if record == nil || record.stack != currentIPStackSettings() || record.sum != textDigest(text) {
		return nil, false
	}
	if !startedIntent.CompareAndSwap(record, nil) {
		return nil, false
	}
	return record.data, true
}

func textDigest(text string) [sha256.Size]byte {
	h := sha256.New()
	var chunk [4096]byte
	for len(text) > 0 {
		n := copy(chunk[:], text)
		_, _ = h.Write(chunk[:n])
		text = text[n:]
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}
