package utils

import (
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dlclark/regexp2"
)

func TestFiltersShareOneRegexpPerPattern(t *testing.T) {
	const long = `(?i)(群|返利|循环|官网|客服|网站|网址|获取|订阅|流量|到期|机场|下次|版本|官址|过期|已用|联系|邮箱|工单|\.com|\btraffic\b)`
	a, err := SharedRegexp2(long)
	if err != nil {
		t.Fatal(err)
	}
	b := MustSharedRegexp2(long)
	if a != b {
		t.Fatal("two holders of one pattern got two regexps")
	}
	if c := MustSharedRegexp2("^MODULE-ENGINE$"); c == a {
		t.Fatal("another pattern got the same regexp")
	}
	if _, err := SharedRegexp2("(unclosed"); err == nil {
		t.Fatal("a pattern that does not compile was accepted")
	}
	want := func() (msg string) {
		defer func() { msg, _ = recover().(string) }()
		regexp2.MustCompile("(unclosed", regexp2.None)
		return ""
	}()
	got := func() (msg string) {
		defer func() { msg, _ = recover().(string) }()
		MustSharedRegexp2("(unclosed")
		return ""
	}()
	if got == "" || got != want {
		t.Fatalf("MustSharedRegexp2 panicked %q, want regexp2.MustCompile's %q", got, want)
	}
	runtime.KeepAlive(a)
}

func TestASharedRegexpMatchesConcurrently(t *testing.T) {
	re := MustSharedRegexp2(`(?i)(香港|hong\s*kong|HK)`)
	names := []string{"p1 | 香港 s1", "Hong Kong 02", "日本 s2", "US-s3", "hk-d5"}
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				name := names[i%len(names)]
				ok, err := re.MatchString(name)
				want := strings.Contains(name, "香港") || strings.Contains(strings.ToLower(name), "hong") || strings.Contains(strings.ToLower(name), "hk")
				if err != nil || ok != want {
					t.Errorf("%q: matched %v (%v), want %v", name, ok, err, want)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestARegexpNobodyHoldsLeavesTheCache(t *testing.T) {
	const pattern = `^a pattern only this test uses \d+$`
	held := func() bool {
		sharedRegexps.Lock()
		defer sharedRegexps.Unlock()
		_, ok := sharedRegexps.byPattern[pattern]
		return ok
	}
	func() {
		re := MustSharedRegexp2(pattern)
		runtime.KeepAlive(re)
	}()
	if !held() {
		t.Fatal("the cache did not take the pattern")
	}
	deadline := time.Now().Add(5 * time.Second)
	for held() {
		if time.Now().After(deadline) {
			t.Fatal("the entry of a regexp nobody holds stayed in the cache")
		}
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
}
