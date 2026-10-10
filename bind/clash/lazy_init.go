package clash

import (
	"regexp"
	"sync"
)

type lazyRegexp struct {
	expr string
	once sync.Once
	re   *regexp.Regexp
}

func (l *lazyRegexp) get() *regexp.Regexp {
	l.once.Do(func() { l.re = regexp.MustCompile(l.expr) })
	return l.re
}

type lazyValue[T any] struct {
	build func() T
	once  sync.Once
	value T
}

func (l *lazyValue[T]) get() T {
	l.once.Do(func() { l.value = l.build() })
	return l.value
}
