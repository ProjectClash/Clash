// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.


package http

import (
	"golang.org/x/exp/slices"
	"net/url"
	"testing"
)

func TestForeachHeaderElement(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"Foo", []string{"Foo"}},
		{" Foo", []string{"Foo"}},
		{"Foo ", []string{"Foo"}},
		{" Foo ", []string{"Foo"}},

		{"foo", []string{"foo"}},
		{"anY-cAsE", []string{"anY-cAsE"}},

		{"", nil},
		{",,,,  ,  ,,   ,,, ,", nil},

		{" Foo,Bar, Baz,lower,,Quux ", []string{"Foo", "Bar", "Baz", "lower", "Quux"}},
	}
	for _, tt := range tests {
		var got []string
		foreachHeaderElement(tt.in, func(v string) {
			got = append(got, v)
		})
		if !slices.Equal(got, tt.want) {
			t.Errorf("foreachHeaderElement(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}

var valuesCount int

func BenchmarkCopyValues(b *testing.B) {
	b.ReportAllocs()
	src := url.Values{
		"a": {"1", "2", "3", "4", "5"},
		"b": {"2", "2", "3", "4", "5"},
		"c": {"3", "2", "3", "4", "5"},
		"d": {"4", "2", "3", "4", "5"},
		"e": {"1", "1", "2", "3", "4", "5", "6", "7", "abcdef", "l", "a", "b", "c", "d", "z"},
		"j": {"1", "2"},
		"m": nil,
	}
	for i := 0; i < b.N; i++ {
		dst := url.Values{"a": {"b"}, "b": {"2"}, "c": {"3"}, "d": {"4"}, "j": nil, "m": {"x"}}
		copyValues(dst, src)
		if valuesCount = len(dst["a"]); valuesCount != 6 {
			b.Fatalf(`%d items in dst["a"] but expected 6`, valuesCount)
		}
	}
	if valuesCount == 0 {
		b.Fatal("Benchmark wasn't run")
	}
}

func TestProtocols(t *testing.T) {
	var p Protocols
	if p.HTTP1() {
		t.Errorf("zero-value protocols: p.HTTP1() = true, want false")
	}
	p.SetHTTP1(true)
	p.SetHTTP2(true)
	if !p.HTTP1() {
		t.Errorf("initialized protocols: p.HTTP1() = false, want true")
	}
	if !p.HTTP2() {
		t.Errorf("initialized protocols: p.HTTP2() = false, want true")
	}
	p.SetHTTP1(false)
	if p.HTTP1() {
		t.Errorf("after unsetting HTTP1: p.HTTP1() = true, want false")
	}
	if !p.HTTP2() {
		t.Errorf("after unsetting HTTP1: p.HTTP2() = false, want true")
	}
}

const redirectURL = "/thisaredirect细雪withasciilettersのけぶabcdefghijk.html"

func BenchmarkHexEscapeNonASCII(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		hexEscapeNonASCII(redirectURL)
	}
}
