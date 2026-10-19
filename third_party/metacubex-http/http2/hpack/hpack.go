// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hpack

import (
	"bytes"
	"errors"
	"fmt"
)

type DecodingError struct {
	Err error
}

func (de DecodingError) Error() string {
	return fmt.Sprintf("decoding error: %v", de.Err)
}

type InvalidIndexError int

func (e InvalidIndexError) Error() string {
	return fmt.Sprintf("invalid indexed representation index %d", int(e))
}

type HeaderField struct {
	Name, Value string

	Sensitive bool
}

func (hf HeaderField) IsPseudo() bool {
	return len(hf.Name) != 0 && hf.Name[0] == ':'
}

func (hf HeaderField) String() string {
	var suffix string
	if hf.Sensitive {
		suffix = " (sensitive)"
	}
	return fmt.Sprintf("header field %q = %q%s", hf.Name, hf.Value, suffix)
}

func (hf HeaderField) Size() uint32 {

	return uint32(len(hf.Name) + len(hf.Value) + 32)
}

type Decoder struct {
	dynTab dynamicTable
	emit   func(f HeaderField)

	emitEnabled bool
	maxStrLen   int

	buf []byte

	saveBuf bytes.Buffer

	firstField bool
}

func NewDecoder(maxDynamicTableSize uint32, emitFunc func(f HeaderField)) *Decoder {
	d := &Decoder{
		emit:        emitFunc,
		emitEnabled: true,
		firstField:  true,
	}
	d.dynTab.table.init()
	d.dynTab.allowedMaxSize = maxDynamicTableSize
	d.dynTab.setMaxSize(maxDynamicTableSize)
	return d
}

var ErrStringLength = errors.New("hpack: string too long")

func (d *Decoder) SetMaxStringLength(n int) {
	d.maxStrLen = n
}

func (d *Decoder) SetEmitFunc(emitFunc func(f HeaderField)) {
	d.emit = emitFunc
}

func (d *Decoder) SetEmitEnabled(v bool) { d.emitEnabled = v }

func (d *Decoder) EmitEnabled() bool { return d.emitEnabled }


func (d *Decoder) SetMaxDynamicTableSize(v uint32) {
	d.dynTab.setMaxSize(v)
}

func (d *Decoder) SetAllowedMaxDynamicTableSize(v uint32) {
	d.dynTab.allowedMaxSize = v
}

type dynamicTable struct {
	table          headerFieldTable
	size           uint32
	maxSize        uint32
	allowedMaxSize uint32
}

func (dt *dynamicTable) setMaxSize(v uint32) {
	dt.maxSize = v
	dt.evict()
}

func (dt *dynamicTable) add(f HeaderField) {
	dt.table.addEntry(f)
	dt.size += f.Size()
	dt.evict()
}

func (dt *dynamicTable) evict() {
	var n int
	for dt.size > dt.maxSize && n < dt.table.len() {
		dt.size -= dt.table.ents[n].Size()
		n++
	}
	dt.table.evictOldest(n)
}

func (d *Decoder) maxTableIndex() int {
	return d.dynTab.table.len() + staticTable.len()
}

func (d *Decoder) at(i uint64) (hf HeaderField, ok bool) {
	if i == 0 {
		return
	}
	if i <= uint64(staticTable.len()) {
		return staticTable.ents[i-1], true
	}
	if i > uint64(d.maxTableIndex()) {
		return
	}
	dt := d.dynTab.table
	return dt.ents[dt.len()-(int(i)-staticTable.len())], true
}

func (d *Decoder) DecodeFull(p []byte) ([]HeaderField, error) {
	var hf []HeaderField
	saveFunc := d.emit
	defer func() { d.emit = saveFunc }()
	d.emit = func(f HeaderField) { hf = append(hf, f) }
	if _, err := d.Write(p); err != nil {
		return nil, err
	}
	if err := d.Close(); err != nil {
		return nil, err
	}
	return hf, nil
}

func (d *Decoder) Close() error {
	if d.saveBuf.Len() > 0 {
		d.saveBuf.Reset()
		return DecodingError{errors.New("truncated headers")}
	}
	d.firstField = true
	return nil
}

func (d *Decoder) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	if d.saveBuf.Len() == 0 {
		d.buf = p
	} else {
		d.saveBuf.Write(p)
		d.buf = d.saveBuf.Bytes()
		d.saveBuf.Reset()
	}

	for len(d.buf) > 0 {
		err = d.parseHeaderFieldRepr()
		if err == errNeedMore {
			const varIntOverhead = 8
			if d.maxStrLen != 0 && int64(len(d.buf)) > 2*(int64(d.maxStrLen)+varIntOverhead) {
				return 0, ErrStringLength
			}
			d.saveBuf.Write(d.buf)
			return len(p), nil
		}
		d.firstField = false
		if err != nil {
			break
		}
	}
	return len(p), err
}

var errNeedMore = errors.New("need more data")

type indexType int

const (
	indexedTrue indexType = iota
	indexedFalse
	indexedNever
)

func (v indexType) indexed() bool   { return v == indexedTrue }
func (v indexType) sensitive() bool { return v == indexedNever }

func (d *Decoder) parseHeaderFieldRepr() error {
	b := d.buf[0]
	switch {
	case b&128 != 0:
		return d.parseFieldIndexed()
	case b&192 == 64:
		return d.parseFieldLiteral(6, indexedTrue)
	case b&240 == 0:
		return d.parseFieldLiteral(4, indexedFalse)
	case b&240 == 16:
		return d.parseFieldLiteral(4, indexedNever)
	case b&224 == 32:
		return d.parseDynamicTableSizeUpdate()
	}

	return DecodingError{errors.New("invalid encoding")}
}

func (d *Decoder) parseFieldIndexed() error {
	buf := d.buf
	idx, buf, err := readVarInt(7, buf)
	if err != nil {
		return err
	}
	hf, ok := d.at(idx)
	if !ok {
		return DecodingError{InvalidIndexError(idx)}
	}
	d.buf = buf
	return d.callEmit(HeaderField{Name: hf.Name, Value: hf.Value})
}

func (d *Decoder) parseFieldLiteral(n uint8, it indexType) error {
	buf := d.buf
	nameIdx, buf, err := readVarInt(n, buf)
	if err != nil {
		return err
	}

	var hf HeaderField
	wantStr := d.emitEnabled || it.indexed()
	var undecodedName undecodedString
	if nameIdx > 0 {
		ihf, ok := d.at(nameIdx)
		if !ok {
			return DecodingError{InvalidIndexError(nameIdx)}
		}
		hf.Name = ihf.Name
	} else {
		undecodedName, buf, err = d.readString(buf)
		if err != nil {
			return err
		}
	}
	undecodedValue, buf, err := d.readString(buf)
	if err != nil {
		return err
	}
	if wantStr {
		if nameIdx <= 0 {
			hf.Name, err = d.decodeString(undecodedName)
			if err != nil {
				return err
			}
		}
		hf.Value, err = d.decodeString(undecodedValue)
		if err != nil {
			return err
		}
	}
	d.buf = buf
	if it.indexed() {
		d.dynTab.add(hf)
	}
	hf.Sensitive = it.sensitive()
	return d.callEmit(hf)
}

func (d *Decoder) callEmit(hf HeaderField) error {
	if d.maxStrLen != 0 {
		if len(hf.Name) > d.maxStrLen || len(hf.Value) > d.maxStrLen {
			return ErrStringLength
		}
	}
	if d.emitEnabled {
		d.emit(hf)
	}
	return nil
}

func (d *Decoder) parseDynamicTableSizeUpdate() error {
	if !d.firstField && d.dynTab.size > 0 {
		return DecodingError{errors.New("dynamic table size update MUST occur at the beginning of a header block")}
	}

	buf := d.buf
	size, buf, err := readVarInt(5, buf)
	if err != nil {
		return err
	}
	if size > uint64(d.dynTab.allowedMaxSize) {
		return DecodingError{errors.New("dynamic table size update too large")}
	}
	d.dynTab.setMaxSize(uint32(size))
	d.buf = buf
	return nil
}

var errVarintOverflow = DecodingError{errors.New("varint integer overflow")}

func readVarInt(n byte, p []byte) (i uint64, remain []byte, err error) {
	if n < 1 || n > 8 {
		panic("bad n")
	}
	if len(p) == 0 {
		return 0, p, errNeedMore
	}
	i = uint64(p[0])
	if n < 8 {
		i &= (1 << uint64(n)) - 1
	}
	if i < (1<<uint64(n))-1 {
		return i, p[1:], nil
	}

	origP := p
	p = p[1:]
	var m uint64
	for len(p) > 0 {
		b := p[0]
		p = p[1:]
		i += uint64(b&127) << m
		if b&128 == 0 {
			return i, p, nil
		}
		m += 7
		if m >= 63 {
			return 0, origP, errVarintOverflow
		}
	}
	return 0, origP, errNeedMore
}

func (d *Decoder) readString(p []byte) (u undecodedString, remain []byte, err error) {
	if len(p) == 0 {
		return u, p, errNeedMore
	}
	isHuff := p[0]&128 != 0
	strLen, p, err := readVarInt(7, p)
	if err != nil {
		return u, p, err
	}
	if d.maxStrLen != 0 && strLen > uint64(d.maxStrLen) {
		return u, nil, ErrStringLength
	}
	if uint64(len(p)) < strLen {
		return u, p, errNeedMore
	}
	u.isHuff = isHuff
	u.b = p[:strLen]
	return u, p[strLen:], nil
}

type undecodedString struct {
	isHuff bool
	b      []byte
}

func (d *Decoder) decodeString(u undecodedString) (string, error) {
	if !u.isHuff {
		return string(u.b), nil
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	var s string
	err := huffmanDecode(buf, d.maxStrLen, u.b)
	if err == nil {
		s = buf.String()
	}
	buf.Reset()
	bufPool.Put(buf)
	return s, err
}
