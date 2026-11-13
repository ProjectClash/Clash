// Copyright (C) 2021  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package replay

import (
	"hash/fnv"
	"sync"
	"time"

	"github.com/enfein/mieru/v3/pkg/metrics"
)

const (
	EmptyTag = ""
)

var (
	NewSession = metrics.RegisterMetric("replay", "NewSession", metrics.COUNTER)

	NewSessionDecrypted = metrics.RegisterMetric("replay", "NewSessionDecrypted", metrics.COUNTER)

	KnownSession = metrics.RegisterMetric("replay", "KnownSession", metrics.COUNTER)
)

type ReplayCache struct {
	mu sync.Mutex

	capacity int

	expireTime time.Time

	expireInterval time.Duration

	current map[uint64]string

	previous map[uint64]string
}

func NewCache(capacity int, expireInterval time.Duration) *ReplayCache {
	if capacity < 0 {
		panic("replay cache capacity can't be negative")
	}
	if expireInterval.Nanoseconds() <= 0 {
		panic("replay cache expire interval must be a positive time range")
	}
	return &ReplayCache{
		capacity:       capacity,
		expireTime:     time.Now().Add(expireInterval),
		expireInterval: expireInterval,
		current:        make(map[uint64]string),
		previous:       make(map[uint64]string),
	}
}

func (c *ReplayCache) IsDuplicate(data []byte, tag string) bool {
	if c == nil || c.capacity == 0 {
		return false
	}
	signature := c.computeSignature(data)
	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Since(c.expireTime) > c.expireInterval {
		c.current = make(map[uint64]string)
		c.previous = make(map[uint64]string)
		c.expireTime = time.Now().Add(c.expireInterval)
	}
	if len(c.current) >= c.capacity || time.Now().After(c.expireTime) {
		c.previous = c.current
		c.current = make(map[uint64]string)
		c.expireTime = time.Now().Add(c.expireInterval)
	}

	if existingTag, ok := c.current[signature]; ok {
		if existingTag == EmptyTag || tag == EmptyTag {
			return true
		}
		return existingTag != tag
	} else {
		c.current[signature] = tag
	}
	if existingTag, ok := c.previous[signature]; ok {
		if existingTag == EmptyTag || tag == EmptyTag {
			return true
		}
		return existingTag != tag
	}
	return false
}

func (c *ReplayCache) Sizes() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.current), len(c.previous)
}

func (c *ReplayCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = make(map[uint64]string)
	c.previous = make(map[uint64]string)
}

func (c *ReplayCache) computeSignature(data []byte) uint64 {
	hash := fnv.New64a()
	hash.Write(data)
	return hash.Sum64()
}
