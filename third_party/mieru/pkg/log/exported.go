package log

import (
	"context"
	"io"
	"strings"
	"time"
)

var (
	std = New()
)

func StandardLogger() *Logger {
	return std
}

func SetOutput(out io.Writer) {
	std.SetOutput(out)
}

func SetFormatter(formatter Formatter) {
	std.SetFormatter(formatter)
}

func SetCallback(callback Callback) {
	std.SetCallback(callback)
}

func SetReportCaller(include bool) {
	std.SetReportCaller(include)
}

func SetLevel(level string) (ok bool) {
	level = strings.ToUpper(level)
	switch level {
	case "FATAL":
		std.SetLevel(FatalLevel)
		return true
	case "ERROR":
		std.SetLevel(ErrorLevel)
		return true
	case "WARN", "WARNING":
		std.SetLevel(WarnLevel)
		return true
	case "INFO":
		std.SetLevel(InfoLevel)
		return true
	case "DEBUG":
		std.SetLevel(DebugLevel)
		return true
	case "TRACE":
		std.SetLevel(TraceLevel)
		return true
	default:
		return false
	}
}

func GetLevel() Level {
	return std.GetLevel()
}

func IsLevelEnabled(level Level) bool {
	return std.IsLevelEnabled(level)
}

func WithError(err error) *Entry {
	return std.WithField(ErrorKey, err)
}

func WithContext(ctx context.Context) *Entry {
	return std.WithContext(ctx)
}

func WithField(key string, value interface{}) *Entry {
	return std.WithField(key, value)
}

func WithFields(fields Fields) *Entry {
	return std.WithFields(fields)
}

func WithTime(t time.Time) *Entry {
	return std.WithTime(t)
}

func Tracef(format string, args ...interface{}) {
	std.Tracef(format, args...)
}

func Debugf(format string, args ...interface{}) {
	std.Debugf(format, args...)
}

func Printf(format string, args ...interface{}) {
	std.Printf(format, args...)
}

func Infof(format string, args ...interface{}) {
	std.Infof(format, args...)
}

func Warnf(format string, args ...interface{}) {
	std.Warnf(format, args...)
}

func Warningf(format string, args ...interface{}) {
	std.Warningf(format, args...)
}

func Errorf(format string, args ...interface{}) {
	std.Errorf(format, args...)
}

func Panicf(format string, args ...interface{}) {
	std.Panicf(format, args...)
}

func Fatalf(format string, args ...interface{}) {
	std.Fatalf(format, args...)
}

func Print(args ...interface{}) {
	std.Print(args...)
}

func Panic(args ...interface{}) {
	std.Panic(args...)
}

func Fatal(args ...interface{}) {
	std.Fatal(args...)
}

func Println(args ...interface{}) {
	std.Println(args...)
}

func Panicln(args ...interface{}) {
	std.Panicln(args...)
}

func Fatalln(args ...interface{}) {
	std.Fatalln(args...)
}
