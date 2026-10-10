package vmess

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/ProjectClash/Clash/component/ech"

	"github.com/ProjectClash/Clash/common/lru"

	"github.com/metacubex/tls"
)

const sessionCacheBuckets = 256

var sessionCaches = lru.New[string, tls.ClientSessionCache](
	lru.WithSize[string, tls.ClientSessionCache](sessionCacheBuckets),
)

func sessionCacheFor(cfg *TLSConfig) tls.ClientSessionCache {
	cache, _ := sessionCaches.GetOrStore(sessionCacheIdentity(cfg), func() tls.ClientSessionCache {
		return tls.NewLRUClientSessionCache(0)
	})
	return cache
}

func sessionCacheIdentity(cfg *TLSConfig) string {
	var identity strings.Builder
	writeField := func(value string) {
		identity.WriteString(strconv.Itoa(len(value)))
		identity.WriteByte(':')
		identity.WriteString(value)
		identity.WriteByte('|')
	}

	writeField(cfg.Host)
	writeField(strconv.FormatBool(cfg.SkipCertVerify))
	writeField(cfg.NameCertVerify)
	writeField(cfg.FingerPrint)
	writeField(cfg.Certificate)
	writeField(cfg.PrivateKey)
	writeField(echIdentity(cfg.ECH))
	identity.WriteString(strconv.Itoa(len(cfg.NextProtos)))
	identity.WriteByte(':')
	for _, protocol := range cfg.NextProtos {
		writeField(protocol)
	}
	return identity.String()
}

func echIdentity(config *ech.Config) string {
	if config == nil {
		return "absent"
	}
	return "0x" + strconv.FormatUint(uint64(reflect.ValueOf(config).Pointer()), 16)
}
