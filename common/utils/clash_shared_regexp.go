package utils

import (
	"runtime"
	"strconv"
	"sync"
	"weak"

	"github.com/dlclark/regexp2"
)


var sharedRegexps struct {
	sync.Mutex
	byPattern map[string]weak.Pointer[regexp2.Regexp]
}

func SharedRegexp2(pattern string) (*regexp2.Regexp, error) {
	sharedRegexps.Lock()
	defer sharedRegexps.Unlock()
	if held, ok := sharedRegexps.byPattern[pattern]; ok {
		if re := held.Value(); re != nil {
			return re, nil
		}
	}
	re, err := regexp2.Compile(pattern, regexp2.None)
	if err != nil {
		return nil, err
	}
	if sharedRegexps.byPattern == nil {
		sharedRegexps.byPattern = map[string]weak.Pointer[regexp2.Regexp]{}
	}
	held := weak.Make(re)
	sharedRegexps.byPattern[pattern] = held
	runtime.AddCleanup(re, func(pattern string) {
		sharedRegexps.Lock()
		defer sharedRegexps.Unlock()
		if current, ok := sharedRegexps.byPattern[pattern]; ok && current == held {
			delete(sharedRegexps.byPattern, pattern)
		}
	}, pattern)
	return re, nil
}

func MustSharedRegexp2(pattern string) *regexp2.Regexp {
	re, err := SharedRegexp2(pattern)
	if err != nil {
		quoted := strconv.Quote(pattern)
		if strconv.CanBackquote(pattern) {
			quoted = "`" + pattern + "`"
		}
		panic(`regexp2: Compile(` + quoted + `): ` + err.Error())
	}
	return re
}
