// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hpack

import (
	"bytes"
	"errors"
	"io"
	"sync"
)

var bufPool = sync.Pool{
	New: func() interface{} { return new(bytes.Buffer) },
}

func HuffmanDecode(w io.Writer, v []byte) (int, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	if err := huffmanDecode(buf, 0, v); err != nil {
		return 0, err
	}
	return w.Write(buf.Bytes())
}

func HuffmanDecodeToString(v []byte) (string, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	if err := huffmanDecode(buf, 0, v); err != nil {
		return "", err
	}
	return buf.String(), nil
}

var ErrInvalidHuffman = errors.New("hpack: invalid Huffman-encoded data")

func huffmanDecode(buf *bytes.Buffer, maxLen int, v []byte) error {
	rootHuffmanNode := getRootHuffmanNode()
	n := rootHuffmanNode
	cur, cbits, sbits := uint(0), uint8(0), uint8(0)
	for _, b := range v {
		cur = cur<<8 | uint(b)
		cbits += 8
		sbits += 8
		for cbits >= 8 {
			idx := byte(cur >> (cbits - 8))
			n = n.children[idx]
			if n == nil {
				return ErrInvalidHuffman
			}
			if n.children == nil {
				if maxLen != 0 && buf.Len() == maxLen {
					return ErrStringLength
				}
				buf.WriteByte(n.sym)
				cbits -= n.codeLen
				n = rootHuffmanNode
				sbits = cbits
			} else {
				cbits -= 8
			}
		}
	}
	for cbits > 0 {
		n = n.children[byte(cur<<(8-cbits))]
		if n == nil {
			return ErrInvalidHuffman
		}
		if n.children != nil || n.codeLen > cbits {
			break
		}
		if maxLen != 0 && buf.Len() == maxLen {
			return ErrStringLength
		}
		buf.WriteByte(n.sym)
		cbits -= n.codeLen
		n = rootHuffmanNode
		sbits = cbits
	}
	if sbits > 7 {
		return ErrInvalidHuffman
	}
	if mask := uint(1<<cbits - 1); cur&mask != mask {
		return ErrInvalidHuffman
	}

	return nil
}

type incomparable [0]func()

type node struct {
	_ incomparable

	children *[256]*node

	codeLen uint8
	sym     byte
}

func newInternalNode() *node {
	return &node{children: new([256]*node)}
}

var (
	buildRootOnce       sync.Once
	lazyRootHuffmanNode *node
)

func getRootHuffmanNode() *node {
	buildRootOnce.Do(buildRootHuffmanNode)
	return lazyRootHuffmanNode
}

func buildRootHuffmanNode() {
	if len(huffmanCodes) != 256 {
		panic("unexpected size")
	}
	lazyRootHuffmanNode = newInternalNode()
	leaves := new([256]node)

	for sym, code := range huffmanCodes {
		codeLen := huffmanCodeLen[sym]

		cur := lazyRootHuffmanNode
		for codeLen > 8 {
			codeLen -= 8
			i := uint8(code >> codeLen)
			if cur.children[i] == nil {
				cur.children[i] = newInternalNode()
			}
			cur = cur.children[i]
		}
		shift := 8 - codeLen
		start, end := int(uint8(code<<shift)), int(1<<shift)

		leaves[sym].sym = byte(sym)
		leaves[sym].codeLen = codeLen
		for i := start; i < start+end; i++ {
			cur.children[i] = &leaves[sym]
		}
	}
}

func AppendHuffmanString(dst []byte, s string) []byte {
	var (
		x uint64
		n uint
	)
	for i := 0; i < len(s); i++ {
		c := s[i]
		n += uint(huffmanCodeLen[c])
		x <<= huffmanCodeLen[c] % 64
		x |= uint64(huffmanCodes[c])
		if n >= 32 {
			n %= 32
			y := uint32(x >> n)
			dst = append(dst, byte(y>>24), byte(y>>16), byte(y>>8), byte(y))
		}
	}
	if over := n % 8; over > 0 {
		const (
			eosCode    = 0x3fffffff
			eosNBits   = 30
			eosPadByte = eosCode >> (eosNBits - 8)
		)
		pad := 8 - over
		x = (x << pad) | (eosPadByte >> over)
		n += pad
	}
	switch n / 8 {
	case 0:
		return dst
	case 1:
		return append(dst, byte(x))
	case 2:
		y := uint16(x)
		return append(dst, byte(y>>8), byte(y))
	case 3:
		y := uint16(x >> 8)
		return append(dst, byte(y>>8), byte(y), byte(x))
	}
	y := uint32(x)
	return append(dst, byte(y>>24), byte(y>>16), byte(y>>8), byte(y))
}

func HuffmanEncodeLength(s string) uint64 {
	n := uint64(0)
	for i := 0; i < len(s); i++ {
		n += uint64(huffmanCodeLen[s[i]])
	}
	return (n + 7) / 8
}
