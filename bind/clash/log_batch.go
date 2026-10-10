package clash

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync/atomic"
)

type LogBatchWriter interface {
	WriteLogBatch(linesJSON string)
}

var logBatchWriter atomic.Pointer[LogBatchWriter]

func SetLogBatchWriter(writer LogBatchWriter) {
	if writer == nil {
		logBatchWriter.Store(nil)
		return
	}
	writer = bridgeSafeLogBatch(writer)
	logBatchWriter.Store(&writer)
}

const (
	logBatchMax   = 64
	logBatchBytes = 256 << 10
)

func writeLogBatch(sink LogBatchWriter, batch []logLine) {
	lines := make([]string, len(batch))
	for i, line := range batch {
		lines[i] = bridgeSafeString(line.message)
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(lines)
	sink.WriteLogBatch(strings.TrimSuffix(encoded.String(), "\n"))
}
