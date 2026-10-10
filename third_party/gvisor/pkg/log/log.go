// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"fmt"
	"io"
	stdlog "log"
	"os"
	"regexp"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/metacubex/gvisor/pkg/linewriter"
	"github.com/metacubex/gvisor/pkg/sync"
)

type Level uint32

const (
	Warning Level = iota

	Info

	Debug
)

func (l Level) String() string {
	switch l {
	case Warning:
		return "Warning"
	case Info:
		return "Info"
	case Debug:
		return "Debug"
	default:
		return fmt.Sprintf("Invalid level: %d", l)
	}
}

type Emitter interface {
	Emit(depth int, level Level, timestamp time.Time, format string, v ...any)
}

type Writer struct {
	Next io.Writer

	mu sync.Mutex

	atomicErrors int32
}

func (l *Writer) Write(data []byte) (int, error) {
	n := 0

	for n < len(data) {
		w, err := l.Next.Write(data[n:])
		n += w

		if pathErr, ok := err.(*os.PathError); ok && pathErr.Timeout() {
			runtime.Gosched()
			continue
		}

		if err != nil {
			l.mu.Lock()
			atomic.AddInt32(&l.atomicErrors, 1)
			l.mu.Unlock()
			return n, err
		}
	}

	if len(data) == 0 || data[len(data)-1] != '\n' {
		l.Write([]byte{'\n'})
	}

	if atomic.LoadInt32(&l.atomicErrors) > 0 {
		l.mu.Lock()
		defer l.mu.Unlock()

		if e := atomic.LoadInt32(&l.atomicErrors); e > 0 {
			msg := fmt.Sprintf("\n*** Dropped %d log messages ***\n", e)
			if _, err := l.Next.Write([]byte(msg)); err == nil {
				atomic.StoreInt32(&l.atomicErrors, 0)
			}
		}
	}

	return n, nil
}

func (l *Writer) Emit(_ int, _ Level, _ time.Time, format string, args ...any) {
	fmt.Fprintf(l, format, args...)
}

type MultiEmitter []Emitter

func (m *MultiEmitter) Emit(depth int, level Level, timestamp time.Time, format string, v ...any) {
	for _, e := range *m {
		e.Emit(1+depth, level, timestamp, format, v...)
	}
}

type TestLogger interface {
	Logf(format string, v ...any)
}

type TestEmitter struct {
	TestLogger
}

func (t *TestEmitter) Emit(_ int, level Level, timestamp time.Time, format string, v ...any) {
	t.Logf(format, v...)
}

type Logger interface {
	Debugf(format string, v ...any)

	Infof(format string, v ...any)

	Warningf(format string, v ...any)

	IsLogging(level Level) bool
}

type BasicLogger struct {
	Level
	Emitter
}

func (l *BasicLogger) Debugf(format string, v ...any) {
	l.DebugfAtDepth(1, format, v...)
}

func (l *BasicLogger) Infof(format string, v ...any) {
	l.InfofAtDepth(1, format, v...)
}

func (l *BasicLogger) Warningf(format string, v ...any) {
	l.WarningfAtDepth(1, format, v...)
}

func (l *BasicLogger) DebugfAtDepth(depth int, format string, v ...any) {
	if l.IsLogging(Debug) {
		l.Emit(1+depth, Debug, time.Now(), format, v...)
	}
}

func (l *BasicLogger) InfofAtDepth(depth int, format string, v ...any) {
	if l.IsLogging(Info) {
		l.Emit(1+depth, Info, time.Now(), format, v...)
	}
}

func (l *BasicLogger) WarningfAtDepth(depth int, format string, v ...any) {
	if l.IsLogging(Warning) {
		l.Emit(1+depth, Warning, time.Now(), format, v...)
	}
}

func (l *BasicLogger) IsLogging(level Level) bool {
	return atomic.LoadUint32((*uint32)(&l.Level)) >= uint32(level)
}

func (l *BasicLogger) SetLevel(level Level) {
	atomic.StoreUint32((*uint32)(&l.Level), uint32(level))
}

var logMu sync.Mutex

var log atomic.Pointer[BasicLogger]

func Log() *BasicLogger {
	return log.Load()
}

func SetTarget(target Emitter) {
	logMu.Lock()
	defer logMu.Unlock()
	oldLog := Log()
	log.Store(&BasicLogger{Level: oldLog.Level, Emitter: target})
}

func SetLevel(newLevel Level) {
	Log().SetLevel(newLevel)
}

func Debugf(format string, v ...any) {
	Log().DebugfAtDepth(1, format, v...)
}

func Infof(format string, v ...any) {
	Log().InfofAtDepth(1, format, v...)
}

func Warningf(format string, v ...any) {
	Log().WarningfAtDepth(1, format, v...)
}

func DebugfAtDepth(depth int, format string, v ...any) {
	Log().DebugfAtDepth(1+depth, format, v...)
}

func InfofAtDepth(depth int, format string, v ...any) {
	Log().InfofAtDepth(1+depth, format, v...)
}

func WarningfAtDepth(depth int, format string, v ...any) {
	Log().WarningfAtDepth(1+depth, format, v...)
}

const defaultStackSize = 1 << 16

const maxStackSize = 1 << 26

func Stacks(all bool) []byte {
	var trace []byte
	for s := defaultStackSize; s <= maxStackSize; s *= 4 {
		trace = make([]byte, s)
		nbytes := runtime.Stack(trace, all)
		if nbytes == s {
			continue
		}
		return trace[:nbytes]
	}
	trace = append(trace, []byte("\n\n...<too large, truncated>")...)
	return trace
}

var stackRegexp = regexp.MustCompile(`(?m)^\S+\(.*\)$\r?\n^\t\S+:\d+.*$\r?\n`)

func LocalStack(excludeTopN int) []byte {
	replaceNext := excludeTopN + 1
	return stackRegexp.ReplaceAllFunc(Stacks(false), func(s []byte) []byte {
		if replaceNext > 0 {
			replaceNext--
			return nil
		}
		return s
	})
}

func Traceback(format string, v ...any) {
	v = append(v, Stacks(false))
	Warningf(format+":\n%s", v...)
}

func TracebackAll(format string, v ...any) {
	v = append(v, Stacks(true))
	Warningf(format+":\n%s", v...)
}

func IsLogging(level Level) bool {
	return Log().IsLogging(level)
}

func CopyStandardLogTo(l Level) error {
	var f func(string, ...any)

	switch l {
	case Debug:
		f = Debugf
	case Info:
		f = Infof
	case Warning:
		f = Warningf
	default:
		return fmt.Errorf("unknown log level %v", l)
	}

	stdlog.SetOutput(linewriter.NewWriter(func(p []byte) {
		b := make([]byte, len(p))
		copy(b, p)

		f("%s", b)
	}))

	return nil
}

func init() {
	log.Store(&BasicLogger{Level: Info, Emitter: GoogleEmitter{&Writer{Next: os.Stderr}}})

	warnedSet = make(map[string]struct{})
}
