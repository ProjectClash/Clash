package provider

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/log"
)

var clashMrsCache struct {
	sync.Mutex
	root       string
	generation string
	index      map[string]int
	used       map[string]time.Time
	providers  map[string]string
	refs       map[string]int
	swept      time.Time
}

const ClashMrsMappedCacheKeep = 3 * 24 * time.Hour

const clashMrsCacheSweepEvery = time.Hour

const clashMrsCacheTempPrefix = ".mrs-mapped-"

var clashMrsCacheWrites atomic.Int64

func ClashSetMrsMappedCacheDirectory(directory, identity string) {
	clashMrsCache.Lock()
	defer clashMrsCache.Unlock()
	if identity == "" {
		identity = C.Version
	}
	sum := sha256.Sum256([]byte("mrs-mapped/CDS1+CIP1/" + identity))
	clashMrsCache.root = directory
	clashMrsCache.generation = hex.EncodeToString(sum[:8])
	clashMrsCache.index = nil
	clashMrsCache.used = map[string]time.Time{}
	clashMrsCache.providers = map[string]string{}
	clashMrsCache.refs = map[string]int{}
	clashMrsCache.swept = time.Now()
}

func ClashMrsMappedCacheDirectory() string {
	clashMrsCache.Lock()
	defer clashMrsCache.Unlock()
	return clashMrsCache.root
}

func ClashSweepMrsMappedCache(age time.Duration) {
	clashMrsCache.Lock()
	root, generation := clashMrsCache.root, clashMrsCache.generation
	clashMrsCache.swept = time.Now()
	clashMrsCache.Unlock()
	if root == "" {
		return
	}
	if entries, err := os.ReadDir(root); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			switch {
			case entry.IsDir() && name != generation && clashMrsCacheGenerationName(name):
				_ = os.RemoveAll(filepath.Join(root, name))
			case !entry.IsDir() && clashMrsCacheOwnName(name):
				_ = os.Remove(filepath.Join(root, name))
			}
		}
	}
	directory := filepath.Join(root, generation)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	now := time.Now()
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, clashMrsCacheTempPrefix) {
			if now.Sub(info.ModTime()) > 10*time.Minute {
				_ = os.Remove(filepath.Join(directory, name))
			}
			continue
		}
		key, _, ok := clashMrsCacheName(name)
		if !ok {
			continue
		}
		last := info.ModTime()
		clashMrsCache.Lock()
		readNow := clashMrsCache.refs[name] > 0
		if read, ok := clashMrsCache.used[name]; ok && read.After(last) {
			last = read
		}
		if readNow || now.Sub(last) <= age || clashMrsCache.root != root || clashMrsCache.generation != generation {
			clashMrsCache.Unlock()
			continue
		}
		if os.Remove(filepath.Join(directory, name)) == nil {
			if clashMrsCache.index != nil {
				delete(clashMrsCache.index, key)
			}
			delete(clashMrsCache.used, name)
		}
		clashMrsCache.Unlock()
	}
}

func clashMrsCacheGenerationName(name string) bool {
	if len(name) != 16 {
		return false
	}
	_, err := hex.DecodeString(name)
	return err == nil
}

func clashMrsCacheOwnName(name string) bool {
	_, _, ok := clashMrsCacheName(name)
	return ok || strings.HasPrefix(name, clashMrsCacheTempPrefix)
}

func clashMrsCacheName(name string) (key string, count int, ok bool) {
	parts := strings.Split(name, ".")
	if len(parts) != 3 || len(parts[0]) != 2*sha256.Size || (parts[1] != "domain" && parts[1] != "ipcidr") {
		return "", 0, false
	}
	if _, err := hex.DecodeString(parts[0]); err != nil {
		return "", 0, false
	}
	n, err := strconv.Atoi(parts[2])
	if err != nil || n <= 0 {
		return "", 0, false
	}
	return parts[0] + "." + parts[1], n, true
}

func clashMrsCacheLookup(key string) (directory string, count int, hit bool) {
	clashMrsCache.Lock()
	defer clashMrsCache.Unlock()
	if clashMrsCache.root == "" {
		return "", 0, false
	}
	directory = filepath.Join(clashMrsCache.root, clashMrsCache.generation)
	if clashMrsCache.index == nil {
		clashMrsCache.index = map[string]int{}
		if entries, err := os.ReadDir(directory); err == nil {
			for _, entry := range entries {
				if k, n, ok := clashMrsCacheName(entry.Name()); ok {
					clashMrsCache.index[k] = n
				}
			}
		}
	}
	count, hit = clashMrsCache.index[key]
	return directory, count, hit
}

func clashMrsCacheForget(key string) {
	clashMrsCache.Lock()
	defer clashMrsCache.Unlock()
	if clashMrsCache.index != nil {
		delete(clashMrsCache.index, key)
	}
}

func clashMrsCacheRead(provider, directory, key, name string, count int) {
	clashMrsCache.Lock()
	if clashMrsCache.index == nil || filepath.Join(clashMrsCache.root, clashMrsCache.generation) != directory {
		clashMrsCache.Unlock()
		return
	}
	if name != "" {
		clashMrsCache.index[key] = count
		clashMrsCache.used[name] = time.Now()
	}
	previous, had := clashMrsCache.providers[provider]
	if had && previous == name {
		clashMrsCache.Unlock()
		return
	}
	if name != "" {
		clashMrsCache.providers[provider] = name
		clashMrsCache.refs[name]++
	} else {
		delete(clashMrsCache.providers, provider)
	}
	replaced := ""
	if had && previous != "" {
		if clashMrsCache.refs[previous]--; clashMrsCache.refs[previous] <= 0 {
			delete(clashMrsCache.refs, previous)
			delete(clashMrsCache.used, previous)
			if k, _, ok := clashMrsCacheName(previous); ok {
				delete(clashMrsCache.index, k)
			}
			replaced = previous
		}
	}
	clashMrsCache.Unlock()
	if replaced != "" {
		_ = os.Remove(filepath.Join(directory, replaced))
	}
}

func clashMrsCacheSweepDue() bool {
	clashMrsCache.Lock()
	defer clashMrsCache.Unlock()
	if time.Since(clashMrsCache.swept) < clashMrsCacheSweepEvery {
		return false
	}
	clashMrsCache.swept = time.Now()
	return true
}

func clashProviderParse(provider string, buf []byte, strategy ruleStrategy, format P.RuleFormat) (ruleStrategy, error) {
	if format == P.MrsRule {
		if mapped, ok, err := clashMrsMapped(provider, buf, strategy); ok {
			return mapped, err
		}
	}
	return rulesParse(buf, strategy, format)
}

func clashMrsMapped(provider string, buf []byte, strategy ruleStrategy) (_ ruleStrategy, ok bool, _ error) {
	var kind string
	switch strategy.(type) {
	case *domainStrategy:
		kind = "domain"
	case *ipcidrStrategy:
		kind = "ipcidr"
	default:
		return nil, false, nil
	}
	sum := sha256.Sum256(buf)
	key := hex.EncodeToString(sum[:]) + "." + kind
	directory, count, hit := clashMrsCacheLookup(key)
	if directory == "" {
		return nil, false, nil
	}
	if hit {
		name := fmt.Sprintf("%s.%d", key, count)
		path := filepath.Join(directory, name)
		strategy.Reset()
		err := clashMrsAttach(strategy, path, count)
		var notWhole clashSetNotWhole
		switch {
		case err == nil:
			now := time.Now()
			_ = os.Chtimes(path, now, now)
			clashMrsCacheRead(provider, directory, key, name, count)
			return strategy, true, nil
		case errors.Is(err, fs.ErrNotExist):
			clashMrsCacheForget(key)
		case errors.As(err, &notWhole):
			log.Warnln("[Provider] cached rule set %s is not whole, reading it again: %v", name, err)
			_ = os.Remove(path)
			clashMrsCacheForget(key)
		default:
			log.Warnln("[Provider] cached rule set %s cannot be read now, reading the set onto the heap: %v", name, err)
			clashMrsCacheRead(provider, directory, key, name, count)
			_, err := rulesParse(buf, strategy, P.MrsRule)
			return strategy, true, err
		}
	}
	if _, err := rulesParse(buf, strategy, P.MrsRule); err != nil {
		return strategy, true, err
	}
	count = strategy.Count()
	if count <= 0 {
		clashMrsCacheRead(provider, directory, key, "", 0)
		return strategy, true, nil
	}
	name := fmt.Sprintf("%s.%d", key, count)
	path := filepath.Join(directory, name)
	if err := clashMrsWrite(strategy, directory, path); err != nil {
		log.Warnln("[Provider] rule set kept on the heap, its mapping could not be written: %v", err)
		clashMrsCacheRead(provider, directory, key, "", 0)
		return strategy, true, nil
	}
	clashMrsCacheWrites.Add(1)
	if err := clashMrsAttach(strategy, path, count); err != nil {
		log.Warnln("[Provider] rule set kept on the heap, its mapping could not be read: %v", err)
		var notWhole clashSetNotWhole
		if errors.As(err, &notWhole) {
			_ = os.Remove(path)
			clashMrsCacheRead(provider, directory, key, "", 0)
			return strategy, true, nil
		}
	}
	clashMrsCacheRead(provider, directory, key, name, count)
	if clashMrsCacheSweepDue() {
		go ClashSweepMrsMappedCache(ClashMrsMappedCacheKeep)
	}
	return strategy, true, nil
}

func clashMrsWrite(strategy ruleStrategy, directory, path string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, clashMrsCacheTempPrefix+"*")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	w := bufio.NewWriterSize(file, 32<<10)
	switch s := strategy.(type) {
	case *domainStrategy:
		err = s.domainSet.WriteMapped(w)
	case *ipcidrStrategy:
		err = s.cidrSet.WriteMapped(w)
	}
	if err == nil {
		err = w.Flush()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func clashMrsAttach(strategy ruleStrategy, path string, count int) error {
	switch s := strategy.(type) {
	case *domainStrategy:
		m, err := openMappedDomainSet(path, nil)
		if err != nil {
			return err
		}
		s.mapped, s.domainSet, s.count = m, nil, count
	case *ipcidrStrategy:
		m, err := openMappedIPSet(path, nil)
		if err != nil {
			return err
		}
		s.mapped, s.cidrSet, s.count = m, nil, count
	}
	return nil
}
