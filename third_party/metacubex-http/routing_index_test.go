// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"fmt"
	"golang.org/x/exp/slices"
	"strings"
	"testing"
)

func TestIndex(t *testing.T) {
	patterns := generatePatterns()
	var idx routingIndex
	for i, pat := range patterns {
		got := indexConflicts(pat, &idx)
		want := trueConflicts(pat, patterns[:i])
		if !slices.Equal(got, want) {
			t.Fatalf("%q:\ngot  %q\nwant %q", pat, got, want)
		}
		idx.addPattern(pat)
	}
}

func trueConflicts(pat *pattern, pats []*pattern) []string {
	var s []string
	for _, p := range pats {
		if pat.conflictsWith(p) {
			s = append(s, p.String())
		}
	}
	slices.Sort(s)
	return s
}

func indexConflicts(pat *pattern, idx *routingIndex) []string {
	var s []string
	idx.possiblyConflictingPatterns(pat, func(p *pattern) error {
		if pat.conflictsWith(p) {
			s = append(s, p.String())
		}
		return nil
	})
	slices.Sort(s)
	return slices.Compact(s)
}

func generatePatterns() []*pattern {
	var pats []*pattern

	collect := func(s string) {
		var b strings.Builder
		wc := 0
		for {
			i := strings.Index(s, "{x}")
			if i < 0 {
				b.WriteString(s)
				break
			}
			b.WriteString(s[:i])
			fmt.Fprintf(&b, "{x%d}", wc)
			wc++
			s = s[i+3:]
		}
		pat, err := parsePattern(b.String())
		if err != nil {
			panic(err)
		}
		pats = append(pats, pat)
	}

	var (
		methods   = []string{"", "GET ", "HEAD ", "POST "}
		hosts     = []string{"", "h1", "h2"}
		segs      = []string{"/a", "/b", "/{x}"}
		finalSegs = []string{"/a", "/b", "/{f}", "/{m...}", "/{$}"}
	)

	g := genConcat(
		genChoice(methods),
		genChoice(hosts),
		genStar(3, genChoice(segs)),
		genChoice(finalSegs))
	g(collect)
	return pats
}

type generator func(collect func(string))

func genConst(s string) generator {
	return func(collect func(string)) {
		collect(s)
	}
}

func genChoice(choices []string) generator {
	return func(collect func(string)) {
		for _, c := range choices {
			collect(c)
		}
	}
}

func genConcat2(g1, g2 generator) generator {
	return func(collect func(string)) {
		g1(func(s1 string) {
			g2(func(s2 string) {
				collect(s1 + s2)
			})
		})
	}
}

func genConcat(gs ...generator) generator {
	if len(gs) == 0 {
		return genConst("")
	}
	return genConcat2(gs[0], genConcat(gs[1:]...))
}

func genRepeat(n int, g generator) generator {
	if n == 0 {
		return genConst("")
	}
	return genConcat(g, genRepeat(n-1, g))
}

func genStar(max int, g generator) generator {
	return func(collect func(string)) {
		for i := 0; i <= max; i++ {
			genRepeat(i, g)(collect)
		}
	}
}

func BenchmarkMultiConflicts(b *testing.B) {
	const nMultis = 1000
	var pats []*pattern
	for i := 0; i < nMultis; i++ {
		pats = append(pats, mustParsePattern(b, fmt.Sprintf("/a/b/{x}/d%d/", i)))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var idx routingIndex
		for _, p := range pats {
			got := indexConflicts(p, &idx)
			if len(got) != 0 {
				b.Fatalf("got %d conflicts, want 0", len(got))
			}
			idx.addPattern(p)
		}
		if i == 0 {
			if g, w := len(idx.multis), nMultis; g != w {
				b.Fatalf("got %d multis, want %d", g, w)
			}
		}
	}
}
