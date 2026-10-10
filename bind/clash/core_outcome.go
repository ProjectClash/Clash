package clash

import (
	"errors"
	"io/fs"
	"os"
	"sync/atomic"
	"syscall"
)

func stagingFailureIsEnvironmental(err error) bool {
	var pathError *fs.PathError
	var linkError *os.LinkError
	var syscallError *os.SyscallError
	var errno syscall.Errno
	var classified *classifiedError
	switch {
	case errors.As(err, &classified):
		return classified.class == CoreOutcomeUnknown
	case errors.As(err, &pathError), errors.As(err, &linkError), errors.As(err, &syscallError), errors.As(err, &errno):
		return true
	}
	return false
}

const (
	CoreOutcomeConfig    = "config"
	CoreOutcomeMemory    = "memory"
	CoreOutcomeRestart   = "restart"
	CoreOutcomeCommitted = "committed"
	CoreOutcomeUnknown   = "unknown"
)

type CoreOutcome struct {
	ErrorClass string
	Message    string
}

type classifiedError struct {
	class string
	err   error
}

func (e *classifiedError) Error() string { return e.err.Error() }
func (e *classifiedError) Unwrap() error { return e.err }

func classify(class string, err error) error {
	if err == nil {
		return nil
	}
	var already *classifiedError
	if errors.As(err, &already) {
		return err
	}
	return &classifiedError{class: class, err: err}
}

func coreOutcomeOf(err error) *CoreOutcome {
	if err == nil {
		return &CoreOutcome{}
	}
	class := CoreOutcomeUnknown
	var classified *classifiedError
	if errors.As(err, &classified) {
		class = classified.class
	}
	return &CoreOutcome{ErrorClass: class, Message: bridgeSafeString(err.Error())}
}

var reloadTestPanicBeforeCommit atomic.Bool

var reloadTestPanicAfterApplyBegins atomic.Bool

var reloadTestAfterParse func()

func (s *BoxService) StartClassified(configContent string) *CoreOutcome {
	return coreOutcomeOf(s.start(configContent))
}

func (s *BoxService) ReloadClassified(configContent string) *CoreOutcome {
	return coreOutcomeOf(s.reload(configContent))
}
