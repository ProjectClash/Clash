// Copyright 2026 The gVisor Authors.
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
	"path/filepath"
)

type FileOpts interface {
	Build(logPattern string) string
}

type DefaultFileOpts struct{}

func (f *DefaultFileOpts) Build(logPattern string) string {
	return logPattern
}

func OpenFile(logPattern string, flags int, opts FileOpts) (*os.File, error) {
	if len(logPattern) == 0 {
		return nil, nil
	}

	logPath := opts.Build(logPattern)

	dir := filepath.Dir(logPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("error creating dir %q: %v", dir, err)
	}

	f, err := os.OpenFile(logPath, flags, 0644)
	if err != nil {
		return nil, fmt.Errorf("error opening file %q: %v", logPath, err)
	}
	return f, nil
}
