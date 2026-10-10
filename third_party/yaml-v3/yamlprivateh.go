//
// Copyright (c) 2011-2019 Canonical Ltd
// Copyright (c) 2006-2010 Kirill Simonov
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is furnished to do
// so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package yaml

const (
	input_raw_buffer_size = 512

	input_buffer_size = input_raw_buffer_size * 3

	output_buffer_size = 128

	output_raw_buffer_size = (output_buffer_size*2 + 2)

	initial_stack_size  = 16
	initial_queue_size  = 16
	initial_string_size = 16
)

func is_alpha(b []byte, i int) bool {
	return b[i] >= '0' && b[i] <= '9' || b[i] >= 'A' && b[i] <= 'Z' || b[i] >= 'a' && b[i] <= 'z' || b[i] == '_' || b[i] == '-'
}

func is_digit(b []byte, i int) bool {
	return b[i] >= '0' && b[i] <= '9'
}

func as_digit(b []byte, i int) int {
	return int(b[i]) - '0'
}

func is_hex(b []byte, i int) bool {
	return b[i] >= '0' && b[i] <= '9' || b[i] >= 'A' && b[i] <= 'F' || b[i] >= 'a' && b[i] <= 'f'
}

func as_hex(b []byte, i int) int {
	bi := b[i]
	if bi >= 'A' && bi <= 'F' {
		return int(bi) - 'A' + 10
	}
	if bi >= 'a' && bi <= 'f' {
		return int(bi) - 'a' + 10
	}
	return int(bi) - '0'
}

func is_ascii(b []byte, i int) bool {
	return b[i] <= 0x7F
}

func is_printable(b []byte, i int) bool {
	return ((b[i] == 0x0A) ||
		(b[i] >= 0x20 && b[i] <= 0x7E) ||
		(b[i] == 0xC2 && b[i+1] >= 0xA0) ||
		(b[i] > 0xC2 && b[i] < 0xED) ||
		(b[i] == 0xED && b[i+1] < 0xA0) ||
		(b[i] == 0xEE) ||
		(b[i] == 0xEF &&
			!(b[i+1] == 0xBB && b[i+2] == 0xBF) &&
			!(b[i+1] == 0xBF && (b[i+2] == 0xBE || b[i+2] == 0xBF))))
}

func is_z(b []byte, i int) bool {
	return b[i] == 0x00
}

func is_bom(b []byte, i int) bool {
	return b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF
}

func is_bom_at(b []byte, i int) bool {
	return i+2 < len(b) && b[i] == 0xEF && b[i+1] == 0xBB && b[i+2] == 0xBF
}

func is_space(b []byte, i int) bool {
	return b[i] == ' '
}

func is_tab(b []byte, i int) bool {
	return b[i] == '\t'
}

func is_blank(b []byte, i int) bool {
	return b[i] == ' ' || b[i] == '\t'
}

func is_break(b []byte, i int) bool {
	return (b[i] == '\r' ||
		b[i] == '\n' ||
		b[i] == 0xC2 && b[i+1] == 0x85 ||
		b[i] == 0xE2 && b[i+1] == 0x80 && b[i+2] == 0xA8 ||
		b[i] == 0xE2 && b[i+1] == 0x80 && b[i+2] == 0xA9)
}

func is_crlf(b []byte, i int) bool {
	return b[i] == '\r' && b[i+1] == '\n'
}

func is_breakz(b []byte, i int) bool {
	return (
	b[i] == '\r' ||
		b[i] == '\n' ||
		b[i] == 0xC2 && b[i+1] == 0x85 ||
		b[i] == 0xE2 && b[i+1] == 0x80 && b[i+2] == 0xA8 ||
		b[i] == 0xE2 && b[i+1] == 0x80 && b[i+2] == 0xA9 ||
		b[i] == 0)
}

func is_spacez(b []byte, i int) bool {
	return (
	b[i] == ' ' ||
		b[i] == '\r' ||
		b[i] == '\n' ||
		b[i] == 0xC2 && b[i+1] == 0x85 ||
		b[i] == 0xE2 && b[i+1] == 0x80 && b[i+2] == 0xA8 ||
		b[i] == 0xE2 && b[i+1] == 0x80 && b[i+2] == 0xA9 ||
		b[i] == 0)
}

func is_blankz(b []byte, i int) bool {
	return (
	b[i] == ' ' || b[i] == '\t' ||
		b[i] == '\r' ||
		b[i] == '\n' ||
		b[i] == 0xC2 && b[i+1] == 0x85 ||
		b[i] == 0xE2 && b[i+1] == 0x80 && b[i+2] == 0xA8 ||
		b[i] == 0xE2 && b[i+1] == 0x80 && b[i+2] == 0xA9 ||
		b[i] == 0)
}

func width(b byte) int {
	if b&0x80 == 0x00 {
		return 1
	}
	if b&0xE0 == 0xC0 {
		return 2
	}
	if b&0xF0 == 0xE0 {
		return 3
	}
	if b&0xF8 == 0xF0 {
		return 4
	}
	return 0

}
