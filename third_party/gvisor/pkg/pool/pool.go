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

package pool

import (
	"github.com/metacubex/gvisor/pkg/sync"
)

type Pool struct {
	mu sync.Mutex

	cache []uint64

	Start uint64

	max uint64

	Limit uint64
}

func (p *Pool) Get() (uint64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.cache) > 0 {
		v := p.cache[len(p.cache)-1]
		p.cache = p.cache[:len(p.cache)-1]
		return v, true
	}

	if p.Start == p.Limit {
		return 0, false
	}

	v := p.Start
	p.Start++
	return v, true
}

func (p *Pool) Put(v uint64) {
	p.mu.Lock()
	p.cache = append(p.cache, v)
	p.mu.Unlock()
}
