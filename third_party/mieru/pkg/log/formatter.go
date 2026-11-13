package log

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	defaultTimestampFormat = time.RFC3339
	FieldKeyMsg            = "msg"
	FieldKeyLevel          = "level"
	FieldKeyTime           = "time"
	FieldKeyFunc           = "func"
	FieldKeyFile           = "file"
)

var LogPrefix = ""

type Formatter interface {
	Format(*Entry) ([]byte, error)
}

type CliFormatter struct{}

func (f *CliFormatter) Format(entry *Entry) ([]byte, error) {
	var buf *bytes.Buffer
	if entry.Buffer != nil {
		buf = entry.Buffer
	} else {
		buf = &bytes.Buffer{}
	}

	buf.WriteString(entry.Message)
	buf.WriteString("\n")
	return buf.Bytes(), nil
}

type DaemonFormatter struct {
	NoPrefix    bool
	NoTimestamp bool
	NoLevel     bool
}

func (f *DaemonFormatter) Format(entry *Entry) ([]byte, error) {
	userData := make(Fields)
	for k, v := range entry.Data {
		userData[k] = v
	}
	userKeys := make([]string, 0, len(userData))
	for k := range userData {
		userKeys = append(userKeys, k)
	}

	var fileInfo, funcInfo string

	orderedKeys := make([]string, 0, 5+len(userData))
	if !f.NoTimestamp {
		orderedKeys = append(orderedKeys, FieldKeyTime)
	}
	if !f.NoLevel {
		orderedKeys = append(orderedKeys, FieldKeyLevel)
	}
	orderedKeys = append(orderedKeys, FieldKeyMsg)
	if entry.HasCaller() {
		fileInfo = fmt.Sprintf("%s:%d", entry.Caller.File, entry.Caller.Line)
		funcInfo = entry.Caller.Function
		orderedKeys = append(orderedKeys, FieldKeyFile)
		orderedKeys = append(orderedKeys, FieldKeyFunc)
	}
	sort.Strings(userKeys)
	orderedKeys = append(orderedKeys, userKeys...)

	var buf *bytes.Buffer
	if entry.Buffer != nil {
		buf = entry.Buffer
	} else {
		buf = &bytes.Buffer{}
	}

	if !f.NoPrefix {
		buf.WriteString(LogPrefix)
	}
	for _, key := range orderedKeys {
		var value string
		switch {
		case key == FieldKeyTime:
			value = entry.Time.Format(defaultTimestampFormat)
		case key == FieldKeyLevel:
			value = strings.ToUpper(entry.Level.String())
		case key == FieldKeyMsg:
			value = entry.Message
		case key == FieldKeyFile && entry.HasCaller():
			value = fileInfo
		case key == FieldKeyFunc && entry.HasCaller():
			value = funcInfo
		default:
			value = fmt.Sprintf("%v=%v", key, userData[key])
		}

		if buf.Len() > 0 {
			buf.WriteString(" ")
		}
		buf.WriteString(value)
	}
	buf.WriteString("\n")

	if entry.Level == FatalLevel {
		fmt.Fprint(os.Stderr, buf.String())
	}

	return buf.Bytes(), nil
}

type NilFormatter struct{}

func (f *NilFormatter) Format(entry *Entry) ([]byte, error) {
	return []byte{}, nil
}
