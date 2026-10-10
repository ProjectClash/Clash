package clash

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestNoStartOrReloadFailureIsSilent(t *testing.T) {
	source, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("cannot read service.go: %v", err)
	}
	lines := strings.Split(string(source), "\n")

	exit := regexp.MustCompile(`^\s*(done <- err|done <- fmt\.Errorf)`)
	logged := regexp.MustCompile(`log\.(Errorln|Warnln)\(`)

	exits, silent := 0, []int{}
	for index, line := range lines {
		if !exit.MatchString(line) {
			continue
		}
		exits++
		covered := false
		for back := index - 1; back >= 0 && back >= index-8; back-- {
			if logged.MatchString(lines[back]) {
				covered = true
				break
			}
			if strings.TrimSpace(lines[back]) == "}" && back < index-1 {
				break
			}
		}
		if !covered {
			silent = append(silent, index+1)
		}
	}

	if exits == 0 {
		t.Fatal("found no error exits in service.go; the scan is broken, not the code")
	}

	helpers := 0
	for index, line := range lines {
		if !strings.Contains(line, "fail := func(err error) {") {
			continue
		}
		helpers++
		audible := false
		for ahead := index + 1; ahead < len(lines) && ahead <= index+6; ahead++ {
			if logged.MatchString(lines[ahead]) {
				audible = true
				break
			}
		}
		if !audible {
			t.Errorf("the fail helper at service.go:%d returns without logging, and every one of its "+
				"callers relies on it to", index+1)
		}
	}
	if helpers == 0 {
		t.Fatal("found no fail helper; the scan no longer matches the code it describes")
	}
	if len(silent) != 0 {
		t.Errorf("service.go returns a start/reload failure with no log line at %v -- a failure that "+
			"leaves no readable reason is indistinguishable from a crash, and from nothing having "+
			"happened at all", silent)
	}
	t.Logf("checked %d error exits, all audible", exits)
}
