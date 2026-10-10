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
	"os"
	"runtime"
	"strings"
	"time"
)

type GoogleEmitter struct {
	*Writer
}

var pid = os.Getpid()

func (g GoogleEmitter) Emit(depth int, level Level, timestamp time.Time, format string, args ...any) {
	prefix := byte('?')
	switch level {
	case Debug:
		prefix = byte('D')
	case Info:
		prefix = byte('I')
	case Warning:
		prefix = byte('W')
	}

	_, month, day := timestamp.Date()
	hour, minute, second := timestamp.Clock()
	microsecond := int(timestamp.Nanosecond() / 1000)

	_, file, line, ok := runtime.Caller(depth + 1)
	if ok {
		slash := strings.LastIndexByte(file, byte('/'))
		if slash >= 0 {
			file = file[slash+1:]
		}
	} else {
		file = "???"
		line = 0
	}

	message := fmt.Sprintf(format, args...)

	fmt.Fprintf(g.Writer, "%c%02d%02d %02d:%02d:%02d.%06d % 7d %s:%d] %s\n", prefix, int(month), day, hour, minute, second, microsecond, pid, file, line, message)
}
