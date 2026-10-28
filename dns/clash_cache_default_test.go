package dns

import (
	"fmt"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

func TestAResolverCacheHoldsTheDefaultTheBindingSets(t *testing.T) {
	t.Cleanup(func() { ClashSetDefaultCacheMaxSize(0) })
	held := func(config Config, n int) int {
		cache := config.newCache()
		for i := 0; i < n; i++ {
			cache.SetWithExpire(fmt.Sprint(i), new(D.Msg), time.Now().Add(time.Hour))
		}
		count := 0
		for i := 0; i < n; i++ {
			if _, _, ok := cache.GetWithExpire(fmt.Sprint(i)); ok {
				count++
			}
		}
		return count
	}
	for _, algorithm := range []string{"", "lru", "arc"} {
		ClashSetDefaultCacheMaxSize(0)
		if got := held(Config{CacheAlgorithm: algorithm}, 5000); got != 4096 {
			t.Fatalf("%q with no default set holds %d, want upstream's 4096", algorithm, got)
		}
		ClashSetDefaultCacheMaxSize(64)
		if got := held(Config{CacheAlgorithm: algorithm}, 200); got != 64 {
			t.Fatalf("%q holds %d, want the default set, 64", algorithm, got)
		}
		if got := held(Config{CacheAlgorithm: algorithm, CacheMaxSize: 100}, 200); got != 100 {
			t.Fatalf("%q with a size given holds %d, want the 100 given", algorithm, got)
		}
		if got := ClashDefaultCacheMaxSize(); got != 64 {
			t.Fatalf("ClashDefaultCacheMaxSize = %d", got)
		}

	}
	r := NewResolverFromClient(nil)
	for i := 0; i < 200; i++ {
		r.cache.SetWithExpire(fmt.Sprint(i), new(D.Msg), time.Now().Add(time.Hour))
	}
	count := 0
	for i := 0; i < 200; i++ {
		if _, _, ok := r.cache.GetWithExpire(fmt.Sprint(i)); ok {
			count++
		}
	}
	if count != 64 {
		t.Fatalf("a resolver an outbound builds holds %d, want 64", count)
	}
}
