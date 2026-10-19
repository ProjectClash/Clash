// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import "math"

type routingIndex struct {
	segments map[routingIndexKey][]*pattern
	multis []*pattern
}

type routingIndexKey struct {
	pos int
	s   string
}

func (idx *routingIndex) addPattern(pat *pattern) {
	if pat.lastSegment().multi {
		idx.multis = append(idx.multis, pat)
	} else {
		if idx.segments == nil {
			idx.segments = map[routingIndexKey][]*pattern{}
		}
		for pos, seg := range pat.segments {
			key := routingIndexKey{pos: pos, s: ""}
			if !seg.wild {
				key.s = seg.s
			}
			idx.segments[key] = append(idx.segments[key], pat)
		}
	}
}

func (idx *routingIndex) possiblyConflictingPatterns(pat *pattern, f func(*pattern) error) (err error) {

	apply := func(pats []*pattern) error {
		if err != nil {
			return err
		}
		for _, p := range pats {
			err = f(p)
			if err != nil {
				return err
			}
		}
		return nil
	}

	if err := apply(idx.multis); err != nil {
		return err
	}
	if pat.lastSegment().s == "/" {
		return apply(idx.segments[routingIndexKey{s: "/", pos: len(pat.segments) - 1}])
	}
	var lmin, wmin []*pattern
	min := math.MaxInt
	hasLit := false
	for i, seg := range pat.segments {
		if seg.multi {
			break
		}
		if !seg.wild {
			hasLit = true
			lpats := idx.segments[routingIndexKey{s: seg.s, pos: i}]
			wpats := idx.segments[routingIndexKey{s: "", pos: i}]
			if sum := len(lpats) + len(wpats); sum < min {
				lmin = lpats
				wmin = wpats
				min = sum
			}
		}
	}
	if hasLit {
		apply(lmin)
		apply(wmin)
		return err
	}

	for _, pats := range idx.segments {
		apply(pats)
	}
	return err
}
