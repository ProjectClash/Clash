package cachefile

import (
	syncatomic "sync/atomic"

	"errors"
	"os"
	"sync"
	"time"

	"github.com/ProjectClash/Clash/component/profile"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"

	"github.com/metacubex/bbolt"
)

var (
	initOnce     sync.Once
	initMu       sync.Mutex
	initialized  bool
	disabled     bool
	cachePath    string
	fileMode     os.FileMode = 0o666
	defaultCache *CacheFile

	bucketSelected         = []byte("selected")
	bucketFakeip           = []byte("fakeip")
	bucketFakeip6          = []byte("fakeip6")
	bucketETag             = []byte("etag")
	bucketSubscriptionInfo = []byte("subscriptioninfo")
	bucketStorage          = []byte("storage")
)

// CacheFile store and update the cache file
type CacheFile struct {
	DB *bbolt.DB
}

var selectedObserver syncatomic.Pointer[func(group, selected string)]

func SetSelectedObserver(observe func(group, selected string)) {
	if observe == nil {
		selectedObserver.Store(nil)
		return
	}
	selectedObserver.Store(&observe)
}

func (c *CacheFile) SetSelected(group, selected string) {
	if observe := selectedObserver.Load(); observe != nil {
		(*observe)(group, selected)
	}
	if !profile.StoreSelected.Load() {
		return
	} else if c.DB == nil {
		return
	}

	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketSelected)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(group), []byte(selected))
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
		return
	}
}

func (c *CacheFile) SelectedMap() map[string]string {
	if !profile.StoreSelected.Load() {
		return nil
	} else if c.DB == nil {
		return nil
	}

	mapping := map[string]string{}
	c.DB.View(func(t *bbolt.Tx) error {
		bucket := t.Bucket(bucketSelected)
		if bucket == nil {
			return nil
		}

		c := bucket.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			mapping[string(k)] = string(v)
		}
		return nil
	})
	return mapping
}

func (c *CacheFile) Close() error {
	if c == nil || c.DB == nil {
		return nil
	}
	return c.DB.Close()
}

func DisablePersistentCache() error {
	initMu.Lock()
	defer initMu.Unlock()
	if initialized {
		if disabled {
			return nil
		}
		return errors.New("cachefile: cache already initialized")
	}
	disabled = true
	return nil
}

func SetPersistentCachePath(path string) error {
	initMu.Lock()
	defer initMu.Unlock()
	if initialized {
		if path == cachePath {
			return nil
		}
		return errors.New("cachefile: cache already initialized")
	}
	cachePath = path
	return nil
}

func initCache() {
	initMu.Lock()
	initialized = true
	cacheDisabled := disabled
	if cachePath == "" {
		cachePath = C.Path.Cache()
	}
	path := cachePath
	initMu.Unlock()
	if cacheDisabled {
		defaultCache = &CacheFile{}
		return
	}
	options := bbolt.Options{Timeout: time.Second, NoStatistics: true}
	db, err := bbolt.Open(path, fileMode, &options)
	switch err {
	case bbolt.ErrInvalid, bbolt.ErrChecksum, bbolt.ErrVersionMismatch:
		if err = os.Remove(path); err != nil {
			log.Warnln("[CacheFile] remove invalid cache file error: %s", err.Error())
			break
		}
		log.Infoln("[CacheFile] remove invalid cache file and create new one")
		db, err = bbolt.Open(path, fileMode, &options)
	}
	if err != nil {
		log.Warnln("[CacheFile] can't open cache file: %s", err.Error())
	}

	defaultCache = &CacheFile{
		DB: db,
	}
}

// Cache return singleton of CacheFile
func Cache() *CacheFile {
	initOnce.Do(initCache)

	return defaultCache
}
