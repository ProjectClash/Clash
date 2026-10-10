// Copyright 2020 The gVisor Authors.
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

package cleanup

type Cleanup struct {
	cleaners []func()
}

func Make(f func()) Cleanup {
	return Cleanup{cleaners: []func(){f}}
}

func (c *Cleanup) Add(f func()) {
	c.cleaners = append(c.cleaners, f)
}

func (c *Cleanup) Clean() {
	clean(c.cleaners)
	c.cleaners = nil
}

func (c *Cleanup) Release() func() {
	old := c.cleaners
	c.cleaners = nil
	return func() { clean(old) }
}

func clean(cleaners []func()) {
	for i := len(cleaners) - 1; i >= 0; i-- {
		cleaners[i]()
	}
}
