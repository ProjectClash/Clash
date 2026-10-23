package clash

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/common/clashsum"
	"github.com/ProjectClash/Clash/component/age"
	"github.com/ProjectClash/Clash/config"
	"go.yaml.in/yaml/v3"
)

type publishParsed struct {
	sections publishSections
	document *yaml.Node
	rules    *RuleCatalog
}

func (p *publishParsed) release() {
	if p != nil && p.rules != nil {
		p.rules.Close()
	}
}

type publishParseKey struct {
	path  string
	stamp clashsum.Stamp
}

var keptParseLifetime = time.Minute

var keptParseLook = 250 * time.Millisecond

var keptParse struct {
	sync.Mutex
	key    publishParseKey
	parsed *publishParsed
	done   chan struct{}
}

func keepParse(key publishParseKey, parsed *publishParsed) {
	keptParse.Lock()
	defer keptParse.Unlock()
	dropKeptParseLocked()
	parsed.rules.forget()
	done := make(chan struct{})
	keptParse.key, keptParse.parsed, keptParse.done = key, parsed, done
	lifetime, every := keptParseLifetime, keptParseLook
	go func() {
		expiry := time.NewTimer(lifetime)
		defer expiry.Stop()
		look := time.NewTicker(every)
		defer look.Stop()
		for {
			select {
			case <-done:
				return
			case <-look.C:
				if info, err := os.Stat(key.path); err == nil {
					if stamp, ok := clashsum.StampOf(info); ok && stamp == key.stamp {
						continue
					}
				}
			case <-expiry.C:
			}
			keptParse.Lock()
			if keptParse.parsed == parsed {
				dropKeptParseLocked()
			}
			keptParse.Unlock()
			return
		}
	}()
}

func takeKeptParse(key publishParseKey) *publishParsed {
	keptParse.Lock()
	defer keptParse.Unlock()
	if keptParse.parsed == nil || keptParse.key != key {
		return nil
	}
	parsed := keptParse.parsed
	keptParse.parsed, keptParse.key = nil, publishParseKey{}
	close(keptParse.done)
	keptParse.done = nil
	return parsed
}

func dropKeptParse() {
	keptParse.Lock()
	defer keptParse.Unlock()
	dropKeptParseLocked()
}

func dropKeptParseLocked() {
	if keptParse.done != nil {
		close(keptParse.done)
		keptParse.done = nil
	}
	keptParse.parsed.release()
	keptParse.parsed, keptParse.key = nil, publishParseKey{}
}

func (c *RuleCatalog) forget() {
	if c != nil {
		c.mu.Lock()
		c.text = ""
		c.mu.Unlock()
	}
}

func planForPublish(text, targetProfile string, key publishParseKey, keyed bool) (*StringBox, error) {
	profile, err := normalizeRuntimeProfile(targetProfile)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	if !strings.HasPrefix(text, age.FileHeader) {
		plan, err := withCompactHeap(func() (*StringBox, error) {
			sections := publishSections{nodes: true, rules: true, inPlace: finalizeReadsRulesInPlace}
			document, rules, err := parseForPublish(text, sections)
			if err != nil {
				return nil, err
			}
			parsed := &publishParsed{sections: sections, document: document, rules: rules}
			root, raw, err := publishViews(parsed)
			if err != nil {
				parsed.release()
				return nil, err
			}
			doc := &ConfigDocument{}
			doc.views.Store(&documentViews{rawText: text, root: root, raw: raw})
			plan, err := doc.planResourcesJSON(runtimePolicyFor(profile, true))
			doc.Close()
			if err != nil || !keyed {
				parsed.release()
				return plan, err
			}
			keepParse(key, parsed)
			return plan, nil
		})
		if err == nil {
			return plan, nil
		}
	}
	planFallbacks.Add(1)
	return planResourcesForProfileUnguarded(text, targetProfile)
}

var planFallbacks atomic.Int64

func publishViews(parsed *publishParsed) (map[string]any, *config.RawConfig, error) {
	var root map[string]any
	raw := config.DefaultRawConfig()
	if parsed.document != nil && len(parsed.document.Content) > 0 {
		if err := parsed.document.Decode(&root); err != nil {
			return nil, nil, err
		}
		if err := parsed.document.Decode(raw); err != nil {
			return nil, nil, err
		}
	}
	if parsed.rules != nil && len(parsed.rules.items) > 0 && len(raw.Rule) == 0 {
		raw.ClashRules = catalogRules{parsed.rules}
	}
	return root, raw, nil
}
