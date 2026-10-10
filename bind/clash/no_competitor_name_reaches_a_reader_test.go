package clash

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestNoCompetitorNameReachesAReader(t *testing.T) {
	banned := []string{
		"sing-box", "surge", "shadowrock", "shadowrocket", "stash", "loon",
		"quantumult", "clashx", "potatso", "kitsunebi", "pharos",
	}
	producer := regexp.MustCompile(
		`(fmt\.Errorf\(|fmt\.Sprintf\(|errors\.New\(|log\.\w+ln\(|unsupportedProxyImportField\()`)

	roots := []string{".", filepath.Join("..", "..", "component", "dialer")}
	scanned, hits := 0, 0
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("cannot read %s: %v", root, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			body, err := os.ReadFile(filepath.Join(root, name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			scanned++
			lines := strings.Split(string(body), "\n")
			window := 0
			for index, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") {
					continue
				}
				if producer.MatchString(line) {
					window = strings.Count(line, "(") - strings.Count(line, ")")
					if window < 0 {
						window = 0
					}
					if !checkLine(t, name, index, trimmed, banned) {
						hits++
					}
					continue
				}
				if window == 0 {
					continue
				}
				window += strings.Count(line, "(") - strings.Count(line, ")")
				if window < 0 {
					window = 0
				}
				if !checkLine(t, name, index, trimmed, banned) {
					hits++
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no source files; the roots are wrong, not the code")
	}
	t.Logf("scanned %d files for %d banned names; %d hit(s)", scanned, len(banned), hits)
}

func checkLine(t *testing.T, file string, index int, trimmed string, banned []string) bool {
	t.Helper()
	clean := true
	isFieldPath := func(literal string) bool {
		inner := strings.Trim(literal, `"`)
		if !strings.Contains(inner, ".") || strings.Contains(inner, " ") {
			return false
		}
		return !strings.ContainsAny(inner, "%:;,!?")
	}
	for _, literal := range regexp.MustCompile(`"([^"\\]|\\.)*"`).FindAllString(trimmed, -1) {
		if isFieldPath(literal) {
			continue
		}
		lowered := strings.ToLower(literal)
		for _, word := range banned {
			if strings.Contains(lowered, word) {
				clean = false
				t.Errorf("%s:%d formats %q into a message a reader can see. The listing audit bans "+
					"that word because guideline 2.3.7 does, and it cannot reach runtime "+
					"strings:\n\t%s", file, index+1, word, trimmed)
			}
		}
	}
	return clean
}
