// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.


package http

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

type pattern struct {
	str    string
	method string
	host   string
	segments []segment
	loc      string
}

func (p *pattern) String() string { return p.str }

func (p *pattern) lastSegment() segment {
	return p.segments[len(p.segments)-1]
}

type segment struct {
	s     string
	wild  bool
	multi bool
}

func parsePattern(s string) (_ *pattern, err error) {
	if len(s) == 0 {
		return nil, errors.New("empty pattern")
	}
	off := 0
	defer func() {
		if err != nil {
			err = fmt.Errorf("at offset %d: %w", off, err)
		}
	}()

	method, rest, found := s, "", false
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		method, rest, found = s[:i], strings.TrimLeft(s[i+1:], " \t"), true
	}
	if !found {
		rest = method
		method = ""
	}
	if method != "" && !validMethod(method) {
		return nil, fmt.Errorf("invalid method %q", method)
	}
	p := &pattern{str: s, method: method}

	if found {
		off = len(method) + 1
	}
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return nil, errors.New("host/path missing /")
	}
	p.host = rest[:i]
	rest = rest[i:]
	if j := strings.IndexByte(p.host, '{'); j >= 0 {
		off += j
		return nil, errors.New("host contains '{' (missing initial '/'?)")
	}
	off += i

	if method != "" && method != "CONNECT" && rest != cleanPath(rest) {
		return nil, errors.New("non-CONNECT pattern with unclean path can never match")
	}

	seenNames := map[string]bool{}
	for len(rest) > 0 {
		rest = rest[1:]
		off = len(s) - len(rest)
		if len(rest) == 0 {
			p.segments = append(p.segments, segment{wild: true, multi: true})
			break
		}
		i := strings.IndexByte(rest, '/')
		if i < 0 {
			i = len(rest)
		}
		var seg string
		seg, rest = rest[:i], rest[i:]
		if i := strings.IndexByte(seg, '{'); i < 0 {
			seg = pathUnescape(seg)
			p.segments = append(p.segments, segment{s: seg})
		} else {
			if i != 0 {
				return nil, errors.New("bad wildcard segment (must start with '{')")
			}
			if seg[len(seg)-1] != '}' {
				return nil, errors.New("bad wildcard segment (must end with '}')")
			}
			name := seg[1 : len(seg)-1]
			if name == "$" {
				if len(rest) != 0 {
					return nil, errors.New("{$} not at end")
				}
				p.segments = append(p.segments, segment{s: "/"})
				break
			}
			name, multi := strings.CutSuffix(name, "...")
			if multi && len(rest) != 0 {
				return nil, errors.New("{...} wildcard not at end")
			}
			if name == "" {
				return nil, errors.New("empty wildcard")
			}
			if !isValidWildcardName(name) {
				return nil, fmt.Errorf("bad wildcard name %q", name)
			}
			if seenNames[name] {
				return nil, fmt.Errorf("duplicate wildcard name %q", name)
			}
			seenNames[name] = true
			p.segments = append(p.segments, segment{s: name, wild: true, multi: multi})
		}
	}
	return p, nil
}

func isValidWildcardName(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if !unicode.IsLetter(c) && c != '_' && (i == 0 || !unicode.IsDigit(c)) {
			return false
		}
	}
	return true
}

func pathUnescape(path string) string {
	u, err := url.PathUnescape(path)
	if err != nil {
		return path
	}
	return u
}

type relationship string

const (
	equivalent   relationship = "equivalent"
	moreGeneral  relationship = "moreGeneral"
	moreSpecific relationship = "moreSpecific"
	disjoint     relationship = "disjoint"
	overlaps     relationship = "overlaps"
)

func (p1 *pattern) conflictsWith(p2 *pattern) bool {
	if p1.host != p2.host {
		return false
	}
	rel := p1.comparePathsAndMethods(p2)
	return rel == equivalent || rel == overlaps
}

func (p1 *pattern) comparePathsAndMethods(p2 *pattern) relationship {
	mrel := p1.compareMethods(p2)
	if mrel == disjoint {
		return disjoint
	}
	prel := p1.comparePaths(p2)
	return combineRelationships(mrel, prel)
}

func (p1 *pattern) compareMethods(p2 *pattern) relationship {
	if p1.method == p2.method {
		return equivalent
	}
	if p1.method == "" {
		return moreGeneral
	}
	if p2.method == "" {
		return moreSpecific
	}
	if p1.method == "GET" && p2.method == "HEAD" {
		return moreGeneral
	}
	if p2.method == "GET" && p1.method == "HEAD" {
		return moreSpecific
	}
	return disjoint
}

func (p1 *pattern) comparePaths(p2 *pattern) relationship {
	if len(p1.segments) != len(p2.segments) && !p1.lastSegment().multi && !p2.lastSegment().multi {
		return disjoint
	}

	var segs1, segs2 []segment
	rel := equivalent
	for segs1, segs2 = p1.segments, p2.segments; len(segs1) > 0 && len(segs2) > 0; segs1, segs2 = segs1[1:], segs2[1:] {
		rel = combineRelationships(rel, compareSegments(segs1[0], segs2[0]))
		if rel == disjoint {
			return rel
		}
	}
	if len(segs1) == 0 && len(segs2) == 0 {
		return rel
	}
	if len(segs1) < len(segs2) && p1.lastSegment().multi {
		return combineRelationships(rel, moreGeneral)
	}
	if len(segs2) < len(segs1) && p2.lastSegment().multi {
		return combineRelationships(rel, moreSpecific)
	}
	return disjoint
}

func compareSegments(s1, s2 segment) relationship {
	if s1.multi && s2.multi {
		return equivalent
	}
	if s1.multi {
		return moreGeneral
	}
	if s2.multi {
		return moreSpecific
	}
	if s1.wild && s2.wild {
		return equivalent
	}
	if s1.wild {
		if s2.s == "/" {
			return disjoint
		}
		return moreGeneral
	}
	if s2.wild {
		if s1.s == "/" {
			return disjoint
		}
		return moreSpecific
	}
	if s1.s == s2.s {
		return equivalent
	}
	return disjoint
}

func combineRelationships(r1, r2 relationship) relationship {
	switch r1 {
	case equivalent:
		return r2
	case disjoint:
		return disjoint
	case overlaps:
		if r2 == disjoint {
			return disjoint
		}
		return overlaps
	case moreGeneral, moreSpecific:
		switch r2 {
		case equivalent:
			return r1
		case inverseRelationship(r1):
			return overlaps
		default:
			return r2
		}
	default:
		panic(fmt.Sprintf("unknown relationship %q", r1))
	}
}

func inverseRelationship(r relationship) relationship {
	switch r {
	case moreSpecific:
		return moreGeneral
	case moreGeneral:
		return moreSpecific
	default:
		return r
	}
}

func describeConflict(p1, p2 *pattern) string {
	mrel := p1.compareMethods(p2)
	prel := p1.comparePaths(p2)
	rel := combineRelationships(mrel, prel)
	if rel == equivalent {
		return fmt.Sprintf("%s matches the same requests as %s", p1, p2)
	}
	if rel != overlaps {
		panic("describeConflict called with non-conflicting patterns")
	}
	if prel == overlaps {
		return fmt.Sprintf(`%[1]s and %[2]s both match some paths, like %[3]q.
But neither is more specific than the other.
%[1]s matches %[4]q, but %[2]s doesn't.
%[2]s matches %[5]q, but %[1]s doesn't.`,
			p1, p2, commonPath(p1, p2), differencePath(p1, p2), differencePath(p2, p1))
	}
	if mrel == moreGeneral && prel == moreSpecific {
		return fmt.Sprintf("%s matches more methods than %s, but has a more specific path pattern", p1, p2)
	}
	if mrel == moreSpecific && prel == moreGeneral {
		return fmt.Sprintf("%s matches fewer methods than %s, but has a more general path pattern", p1, p2)
	}
	return fmt.Sprintf("bug: unexpected way for two patterns %s and %s to conflict: methods %s, paths %s", p1, p2, mrel, prel)
}

func writeMatchingPath(b *strings.Builder, segs []segment) {
	for _, s := range segs {
		writeSegment(b, s)
	}
}

func writeSegment(b *strings.Builder, s segment) {
	b.WriteByte('/')
	if !s.multi && s.s != "/" {
		b.WriteString(s.s)
	}
}

func commonPath(p1, p2 *pattern) string {
	var b strings.Builder
	var segs1, segs2 []segment
	for segs1, segs2 = p1.segments, p2.segments; len(segs1) > 0 && len(segs2) > 0; segs1, segs2 = segs1[1:], segs2[1:] {
		if s1 := segs1[0]; s1.wild {
			writeSegment(&b, segs2[0])
		} else {
			writeSegment(&b, s1)
		}
	}
	if len(segs1) > 0 {
		writeMatchingPath(&b, segs1)
	} else if len(segs2) > 0 {
		writeMatchingPath(&b, segs2)
	}
	return b.String()
}

func differencePath(p1, p2 *pattern) string {
	var b strings.Builder

	var segs1, segs2 []segment
	for segs1, segs2 = p1.segments, p2.segments; len(segs1) > 0 && len(segs2) > 0; segs1, segs2 = segs1[1:], segs2[1:] {
		s1 := segs1[0]
		s2 := segs2[0]
		if s1.multi && s2.multi {
			b.WriteByte('/')
			return b.String()

		}
		if s1.multi && !s2.multi {
			b.WriteByte('/')
			if s2.s == "/" {
				if s1.s != "" {
					b.WriteString(s1.s)
				} else {
					b.WriteString("x")
				}
			}
			return b.String()
		}
		if !s1.multi && s2.multi {
			writeSegment(&b, s1)
		} else if s1.wild && s2.wild {
			writeSegment(&b, s1)
		} else if s1.wild && !s2.wild {
			if s1.s != s2.s {
				writeSegment(&b, s1)
			} else {
				b.WriteByte('/')
				b.WriteString(s2.s + "x")
			}
		} else if !s1.wild && s2.wild {
			writeSegment(&b, s1)
		} else {
			if s1.s != s2.s {
				panic(fmt.Sprintf("literals differ: %q and %q", s1.s, s2.s))
			}
			writeSegment(&b, s1)
		}
	}
	if len(segs1) > 0 {
		writeMatchingPath(&b, segs1)
	} else if len(segs2) > 0 {
		writeMatchingPath(&b, segs2)
	}
	return b.String()
}
