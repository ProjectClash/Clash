// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hpack

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func TestEncoderTableSizeUpdate(t *testing.T) {
	tests := []struct {
		size1, size2 uint32
		wantHex      string
	}{
		{2048, 4096, "3fe10f 3fe11f 82"},

		{16384, 2048, "3fe10f 82"},
	}
	for _, tt := range tests {
		var buf bytes.Buffer
		e := NewEncoder(&buf)
		e.SetMaxDynamicTableSize(tt.size1)
		e.SetMaxDynamicTableSize(tt.size2)
		if err := e.WriteField(pair(":method", "GET")); err != nil {
			t.Fatal(err)
		}
		want := removeSpace(tt.wantHex)
		if got := hex.EncodeToString(buf.Bytes()); got != want {
			t.Errorf("e.SetDynamicTableSize %v, %v = %q; want %q", tt.size1, tt.size2, got, want)
		}
	}
}

func TestEncoderWriteField(t *testing.T) {
	var buf bytes.Buffer
	e := NewEncoder(&buf)
	var got []HeaderField
	d := NewDecoder(4<<10, func(f HeaderField) {
		got = append(got, f)
	})

	tests := []struct {
		hdrs []HeaderField
	}{
		{[]HeaderField{
			pair(":method", "GET"),
			pair(":scheme", "http"),
			pair(":path", "/"),
			pair(":authority", "www.example.com"),
		}},
		{[]HeaderField{
			pair(":method", "GET"),
			pair(":scheme", "http"),
			pair(":path", "/"),
			pair(":authority", "www.example.com"),
			pair("cache-control", "no-cache"),
		}},
		{[]HeaderField{
			pair(":method", "GET"),
			pair(":scheme", "https"),
			pair(":path", "/index.html"),
			pair(":authority", "www.example.com"),
			pair("custom-key", "custom-value"),
		}},
	}
	for i, tt := range tests {
		buf.Reset()
		got = got[:0]
		for _, hf := range tt.hdrs {
			if err := e.WriteField(hf); err != nil {
				t.Fatal(err)
			}
		}
		_, err := d.Write(buf.Bytes())
		if err != nil {
			t.Errorf("%d. Decoder Write = %v", i, err)
		}
		if !reflect.DeepEqual(got, tt.hdrs) {
			t.Errorf("%d. Decoded %+v; want %+v", i, got, tt.hdrs)
		}
	}
}

func TestEncoderSearchTable(t *testing.T) {
	e := NewEncoder(nil)

	e.dynTab.add(pair("foo", "bar"))
	e.dynTab.add(pair("blake", "miz"))
	e.dynTab.add(pair(":method", "GET"))

	tests := []struct {
		hf        HeaderField
		wantI     uint64
		wantMatch bool
	}{
		{pair("foo", "bar"), uint64(staticTable.len()) + 3, true},
		{pair("blake", "miz"), uint64(staticTable.len()) + 2, true},
		{pair(":method", "GET"), 2, true},

		{HeaderField{":method", "GET", true}, 3, false},

		{pair("foo", "..."), uint64(staticTable.len()) + 3, false},
		{pair("blake", "..."), uint64(staticTable.len()) + 2, false},
		{pair(":method", "..."), 3, false},

		{pair("foo-", "bar"), 0, false},
	}
	for _, tt := range tests {
		if gotI, gotMatch := e.searchTable(tt.hf); gotI != tt.wantI || gotMatch != tt.wantMatch {
			t.Errorf("d.search(%+v) = %v, %v; want %v, %v", tt.hf, gotI, gotMatch, tt.wantI, tt.wantMatch)
		}
	}
}

func TestAppendVarInt(t *testing.T) {
	tests := []struct {
		n    byte
		i    uint64
		want []byte
	}{
		{1, 0, []byte{0}},
		{2, 2, []byte{2}},
		{3, 6, []byte{6}},
		{4, 14, []byte{14}},
		{5, 30, []byte{30}},
		{6, 62, []byte{62}},
		{7, 126, []byte{126}},
		{8, 254, []byte{254}},

		{5, 1337, []byte{31, 154, 10}},
	}
	for _, tt := range tests {
		got := appendVarInt(nil, tt.n, tt.i)
		if !bytes.Equal(got, tt.want) {
			t.Errorf("appendVarInt(nil, %v, %v) = %v; want %v", tt.n, tt.i, got, tt.want)
		}
	}
}

func TestAppendHpackString(t *testing.T) {
	tests := []struct {
		s, wantHex string
	}{
		{"www.example.com", "8c f1e3 c2e5 f23a 6ba0 ab90 f4ff"},

		{"a", "01 61"},

		{"", "00"},
	}
	for _, tt := range tests {
		want := removeSpace(tt.wantHex)
		buf := appendHpackString(nil, tt.s)
		if got := hex.EncodeToString(buf); want != got {
			t.Errorf("appendHpackString(nil, %q) = %q; want %q", tt.s, got, want)
		}
	}
}

func TestAppendIndexed(t *testing.T) {
	tests := []struct {
		i       uint64
		wantHex string
	}{
		{1, "81"},
		{126, "fe"},

		{127, "ff00"},
		{128, "ff01"},
	}
	for _, tt := range tests {
		want := removeSpace(tt.wantHex)
		buf := appendIndexed(nil, tt.i)
		if got := hex.EncodeToString(buf); want != got {
			t.Errorf("appendIndex(nil, %v) = %q; want %q", tt.i, got, want)
		}
	}
}

func TestAppendNewName(t *testing.T) {
	tests := []struct {
		f        HeaderField
		indexing bool
		wantHex  string
	}{
		{HeaderField{"custom-key", "custom-value", false}, true, "40 88 25a8 49e9 5ba9 7d7f 89 25a8 49e9 5bb8 e8b4 bf"},

		{HeaderField{"custom-key", "custom-value", false}, false, "00 88 25a8 49e9 5ba9 7d7f 89 25a8 49e9 5bb8 e8b4 bf"},

		{HeaderField{"custom-key", "custom-value", true}, true, "10 88 25a8 49e9 5ba9 7d7f 89 25a8 49e9 5bb8 e8b4 bf"},
		{HeaderField{"custom-key", "custom-value", true}, false, "10 88 25a8 49e9 5ba9 7d7f 89 25a8 49e9 5bb8 e8b4 bf"},
	}
	for _, tt := range tests {
		want := removeSpace(tt.wantHex)
		buf := appendNewName(nil, tt.f, tt.indexing)
		if got := hex.EncodeToString(buf); want != got {
			t.Errorf("appendNewName(nil, %+v, %v) = %q; want %q", tt.f, tt.indexing, got, want)
		}
	}
}

func TestAppendIndexedName(t *testing.T) {
	tests := []struct {
		f        HeaderField
		i        uint64
		indexing bool
		wantHex  string
	}{
		{HeaderField{":status", "302", false}, 8, true, "48 82 6402"},

		{HeaderField{":status", "302", false}, 8, false, "08 82 6402"},

		{HeaderField{":status", "302", true}, 8, true, "18 82 6402"},
		{HeaderField{":status", "302", true}, 8, false, "18 82 6402"},
	}
	for _, tt := range tests {
		want := removeSpace(tt.wantHex)
		buf := appendIndexedName(nil, tt.f, tt.i, tt.indexing)
		if got := hex.EncodeToString(buf); want != got {
			t.Errorf("appendIndexedName(nil, %+v, %v) = %q; want %q", tt.f, tt.indexing, got, want)
		}
	}
}

func TestAppendTableSize(t *testing.T) {
	tests := []struct {
		i       uint32
		wantHex string
	}{
		{30, "3e"},

		{31, "3f00"},
		{32, "3f01"},
	}
	for _, tt := range tests {
		want := removeSpace(tt.wantHex)
		buf := appendTableSize(nil, tt.i)
		if got := hex.EncodeToString(buf); want != got {
			t.Errorf("appendTableSize(nil, %v) = %q; want %q", tt.i, got, want)
		}
	}
}

func TestEncoderSetMaxDynamicTableSize(t *testing.T) {
	var buf bytes.Buffer
	e := NewEncoder(&buf)
	tests := []struct {
		v           uint32
		wantUpdate  bool
		wantMinSize uint32
		wantMaxSize uint32
	}{
		{2048, true, 2048, 2048},

		{16384, true, 2048, 4096},
	}
	for _, tt := range tests {
		e.SetMaxDynamicTableSize(tt.v)
		if got := e.tableSizeUpdate; tt.wantUpdate != got {
			t.Errorf("e.tableSizeUpdate = %v; want %v", got, tt.wantUpdate)
		}
		if got := e.minSize; tt.wantMinSize != got {
			t.Errorf("e.minSize = %v; want %v", got, tt.wantMinSize)
		}
		if got := e.dynTab.maxSize; tt.wantMaxSize != got {
			t.Errorf("e.maxSize = %v; want %v", got, tt.wantMaxSize)
		}
	}
}

func TestEncoderSetMaxDynamicTableSizeLimit(t *testing.T) {
	e := NewEncoder(nil)
	e.SetMaxDynamicTableSizeLimit(4095)
	if got, want := e.dynTab.maxSize, uint32(4095); got != want {
		t.Errorf("e.dynTab.maxSize = %v; want %v", got, want)
	}
	if got, want := e.maxSizeLimit, uint32(4095); got != want {
		t.Errorf("e.maxSizeLimit = %v; want %v", got, want)
	}
	if got, want := e.tableSizeUpdate, true; got != want {
		t.Errorf("e.tableSizeUpdate = %v; want %v", got, want)
	}
	e.SetMaxDynamicTableSize(16384)
	if got, want := e.dynTab.maxSize, uint32(4095); got != want {
		t.Errorf("e.dynTab.maxSize = %v; want %v", got, want)
	}
	e.SetMaxDynamicTableSizeLimit(8192)
	if got, want := e.dynTab.maxSize, uint32(4095); got != want {
		t.Errorf("e.dynTab.maxSize = %v; want %v", got, want)
	}
	if got, want := e.maxSizeLimit, uint32(8192); got != want {
		t.Errorf("e.maxSizeLimit = %v; want %v", got, want)
	}
}

func removeSpace(s string) string {
	return strings.Replace(s, " ", "", -1)
}

func BenchmarkEncoderSearchTable(b *testing.B) {
	e := NewEncoder(nil)

	var possible []HeaderField
	for _, f := range staticTable.ents {
		if f.Value == "" {
			possible = append(possible, f)
			continue
		}
		num := 5
		if f.Name == "cookie" || f.Name == "set-cookie" {
			num = 25
		}
		for i := 0; i < num; i++ {
			f.Value = fmt.Sprintf("%s-%d", f.Name, i)
			possible = append(possible, f)
		}
	}
	for k := 0; k < 10; k++ {
		f := HeaderField{
			Name:      fmt.Sprintf("x-header-%d", k),
			Sensitive: rand.Int()%2 == 0,
		}
		for i := 0; i < 5; i++ {
			f.Value = fmt.Sprintf("%s-%d", f.Name, i)
			possible = append(possible, f)
		}
	}

	for r := 0; r < 100*20; r++ {
		f := possible[rand.Int31n(int32(len(possible)))]
		if _, has := staticTable.search(f); !has {
			e.dynTab.add(f)
		}
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for _, f := range possible {
			e.searchTable(f)
		}
	}
}
