package fswatch

import (
	"os"
	"time"
)

const DefaultWaitTimeout = 100 * time.Millisecond

type Logger interface {
	Error(args ...any)
}

type Options struct {
	Path        []string
	Direct      bool
	Callback    func(path string)
	WaitTimeout time.Duration
	Logger      Logger
}

type Watcher struct{}

func NewWatcher(options Options) (*Watcher, error) {
	if len(options.Path) == 0 || options.Callback == nil {
		return nil, os.ErrInvalid
	}
	return &Watcher{}, nil
}

func (*Watcher) Start() error {
	return nil
}

func (*Watcher) Close() error {
	return nil
}
