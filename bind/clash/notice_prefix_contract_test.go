package clash

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestNoNewLogPrefixArrivesUnnoticed(t *testing.T) {
	type usage struct {
		levels string
		note   string
	}
	known := map[string]usage{
		"Apple|Warnln": {"Warnln", "reader-facing; this is the pair the app selects on"},
		"Apple|Errorln": {"Errorln", "reader-facing, and the most important pair here: a start or " +
			"reload that FAILED. Added 2026-08-28 because these paths returned in silence -- the phase " +
			"record stopped at config-parsed, the core log ended on a memory footprint, and what a user " +
			"saw was a tunnel that did not come up for no stated reason. Errorln rather than Warnln " +
			"because the tunnel is not running; a warning describes something that happened anyway."},
		"Apple %s|Warnln":               {"Warnln", "reader-facing, formatted with the runtime profile name"},
		"Apple NetworkExtension|Warnln": {"Warnln", "reader-facing; profile-independent statements"},
		"Apple|Infoln": {"Infoln", "instrumentation that happens to carry the reader prefix: the " +
			"physical-path trace and the geo compile summaries. The app filters these out by " +
			"level. A failure inside one of them gets its own Warnln -- see geosite_cache.go " +
			"and geoip_cache.go -- because a category that will not compile is a statement " +
			"about the user's rules, not about this process"},
		"mDNS|Infoln": {"Infoln", "developer-facing: one line per multicast-DNS query with its " +
			"answer count and elapsed time. Instrumentation, not a notice -- a Bonjour " +
			"name resolving is not something to tell a user about. It exists because the path " +
			"was unobservable and a device round could not tell a sandbox that blocks the " +
			"daemon's socket from a query that never reached the core at all"},
		"mDNS|Warnln": {"Warnln", "developer-facing: a multicast-DNS query that did not answer. " +
			"Two wordings on purpose -- \"unreachable\" means the daemon's socket could not be " +
			"reached, which inside a Network Extension is the sandbox question and the errno " +
			"is the whole evidence for it; \"failed\" means the daemon answered and did not " +
			"resolve the name, which is a result. Also the concurrency-cap refusal. NOT " +
			"selected by the app: a user has nothing to do about either"},
		"App|Errorln": {"Errorln", "developer-facing: an export the containing App called panicked " +
			"and was recovered into an error. Written in the App process with its stack; the " +
			"App shows the returned error where the call was made, so the line is the diagnosis, " +
			"not a notice -- NOT selected by the app"},
		"App|Warnln": {"Warnln", "developer-facing: the stack of a recovered App panic could not be " +
			"kept in the App's crash report. NOT selected by the app"},
		"Memory|Warnln": {"Warnln", "developer-facing: pressure and threshold telemetry"},
		"Memory|Infoln": {"Infoln", "developer-facing: pressure sampling"},
		"Proxy|Infoln":  {"Infoln", "developer-facing: node catalog housekeeping -- store files a killed tunnel left, swept"},
		"mem|Infoln":    {"Infoln", "developer-facing: allocator sampling"},
		"iOS|Warnln": {"Warnln", "developer-facing: provider staging and lifecycle internals. NOT " +
			"selected by the app -- if a line here ever needs to reach a user, give it an " +
			"[Apple prefix rather than widening the app's selector"},
		"iOS|Errorln": {"Errorln", "developer-facing: staging and lifecycle failures"},
		"Provider|Infoln": {"Infoln", "developer-facing: a provider refreshed in the tunnel, with its " +
			"entry count. NOT selected by the app; the outcome is in provider-refresh/state.json"},
		"Provider|Warnln": {"Warnln", "developer-facing: a refresh that failed, a payload left for the " +
			"App, a cache file that could not be kept, a build marker the last process left. NOT " +
			"selected by the app; state.json carries result, error and pendingReason"},
		"Provider|Errorln": {"Errorln", "developer-facing: the refresher goroutine recovered from a " +
			"panic and stopped. NOT selected by the app"},
	}

	prefix := regexp.MustCompile(`log\.(Warnln|Errorln|Infoln)\("\[([^\]]+)\]`)
	found := map[string][]string{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		content, readErr := os.ReadFile(filepath.Join(".", name))
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		for _, match := range prefix.FindAllStringSubmatch(string(content), -1) {
			key := match[2] + "|" + match[1]
			found[key] = append(found[key], name)
		}
	}
	if len(found) == 0 {
		t.Fatal("no prefixed log calls found at all, which cannot be right -- the scan is broken, " +
			"and a broken scan passes silently")
	}

	for tag, files := range found {
		if _, isKnown := known[tag]; !isKnown {
			sort.Strings(files)
			t.Errorf("new prefix/level pair %q in %v. The app selects on BOTH: an [Apple prefix "+
				"at Infoln is filtered out as instrumentation, and a private tag at any level "+
				"reaches nobody. Decide which this is, then record it here", tag, files)
		}
	}
	for tag := range known {
		if _, stillUsed := found[tag]; !stillUsed {
			t.Errorf("pair %q is recorded here but no longer used; drop it so the list stays "+
				"a description rather than a wish", tag)
		}
	}
}

func TestEveryReaderFacingNoticeFamilyStaysAtWarnLevel(t *testing.T) {
	for family, site := range map[string]struct{ file, needle string }{
		"published deviations": {"config_deviations.go", "range deviations"},
	} {
		content, err := os.ReadFile(site.file)
		if err != nil {
			t.Fatalf("read %s: %v", site.file, err)
		}
		lines := strings.Split(string(content), "\n")
		emitted := false
		for index, line := range lines {
			if !strings.Contains(line, site.needle) {
				continue
			}
			for offset := 1; offset <= 4 && index+offset < len(lines); offset++ {
				if strings.Contains(lines[index+offset], `log.Warnln("[Apple`) {
					emitted = true
				}
			}
		}
		if !emitted {
			t.Errorf("%s no longer emits through an [Apple prefixed Warnln in %s; the app "+
				"selects on prefix AND level, so this family reaches nobody", family, site.file)
		}
	}

	content, err := os.ReadFile("config_pipeline.go")
	if err != nil {
		t.Fatalf("read config_pipeline.go: %v", err)
	}
	body := string(content)
	for family, needle := range map[string]string{
		"kept owner-metadata rules":    "summarizeMetadataRuleOccurrences",
		"unguarded controller":         "unguardedControllerNotices",
		"unauthenticated LAN listener": "unauthenticatedLANListenerNotices",
	} {
		lines := strings.Split(body, "\n")
		emitted := false
		for lineIndex, line := range lines {
			if !strings.Contains(line, needle) || !strings.Contains(line, "range ") {
				continue
			}
			for offset := 1; offset <= 3 && lineIndex+offset < len(lines); offset++ {
				if strings.Contains(lines[lineIndex+offset], `log.Warnln("[Apple`) {
					emitted = true
				}
				if strings.Contains(lines[lineIndex+offset], "}") && offset > 1 {
					break
				}
			}
		}
		if !emitted {
			t.Errorf("%s no longer emits through an [Apple prefixed warning; the app selects on "+
				"that prefix and will drop this family without saying so", family)
		}
	}
}
