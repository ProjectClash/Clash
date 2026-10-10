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

import (
	"bytes"
	"fmt"
)


func cache(parser *yaml_parser_t, length int) bool {
	return parser.unread >= length || yaml_parser_update_buffer(parser, length)
}

func skip(parser *yaml_parser_t) {
	if !is_blank(parser.buffer, parser.buffer_pos) {
		parser.newlines = 0
	}
	parser.mark.index++
	parser.mark.column++
	parser.unread--
	parser.buffer_pos += width(parser.buffer[parser.buffer_pos])
}

func skip_line(parser *yaml_parser_t) {
	if is_crlf(parser.buffer, parser.buffer_pos) {
		parser.mark.index += 2
		parser.mark.column = 0
		parser.mark.line++
		parser.unread -= 2
		parser.buffer_pos += 2
		parser.newlines++
	} else if is_break(parser.buffer, parser.buffer_pos) {
		parser.mark.index++
		parser.mark.column = 0
		parser.mark.line++
		parser.unread--
		parser.buffer_pos += width(parser.buffer[parser.buffer_pos])
		parser.newlines++
	}
}

func read(parser *yaml_parser_t, s []byte) []byte {
	if !is_blank(parser.buffer, parser.buffer_pos) {
		parser.newlines = 0
	}
	w := width(parser.buffer[parser.buffer_pos])
	if w == 0 {
		panic("invalid character sequence")
	}
	if len(s) == 0 {
		s = make([]byte, 0, 32)
	}
	if w == 1 && len(s)+w <= cap(s) {
		s = s[:len(s)+1]
		s[len(s)-1] = parser.buffer[parser.buffer_pos]
		parser.buffer_pos++
	} else {
		s = append(s, parser.buffer[parser.buffer_pos:parser.buffer_pos+w]...)
		parser.buffer_pos += w
	}
	parser.mark.index++
	parser.mark.column++
	parser.unread--
	return s
}

func read_line(parser *yaml_parser_t, s []byte) []byte {
	buf := parser.buffer
	pos := parser.buffer_pos
	switch {
	case buf[pos] == '\r' && buf[pos+1] == '\n':
		s = append(s, '\n')
		parser.buffer_pos += 2
		parser.mark.index++
		parser.unread--
	case buf[pos] == '\r' || buf[pos] == '\n':
		s = append(s, '\n')
		parser.buffer_pos += 1
	case buf[pos] == '\xC2' && buf[pos+1] == '\x85':
		s = append(s, '\n')
		parser.buffer_pos += 2
	case buf[pos] == '\xE2' && buf[pos+1] == '\x80' && (buf[pos+2] == '\xA8' || buf[pos+2] == '\xA9'):
		s = append(s, buf[parser.buffer_pos:pos+3]...)
		parser.buffer_pos += 3
	default:
		return s
	}
	parser.mark.index++
	parser.mark.column = 0
	parser.mark.line++
	parser.unread--
	parser.newlines++
	return s
}

func yaml_parser_scan(parser *yaml_parser_t, token *yaml_token_t) bool {
	*token = yaml_token_t{}

	if parser.stream_end_produced || parser.error != yaml_NO_ERROR {
		return true
	}

	if !parser.token_available {
		if !yaml_parser_fetch_more_tokens(parser) {
			return false
		}
	}

	*token = parser.tokens[parser.tokens_head]
	parser.tokens_head++
	parser.tokens_parsed++
	parser.token_available = false

	if token.typ == yaml_STREAM_END_TOKEN {
		parser.stream_end_produced = true
	}
	return true
}

func yaml_parser_set_scanner_error(parser *yaml_parser_t, context string, context_mark yaml_mark_t, problem string) bool {
	parser.error = yaml_SCANNER_ERROR
	parser.context = context
	parser.context_mark = context_mark
	parser.problem = problem
	parser.problem_mark = parser.mark
	return false
}

func yaml_parser_set_scanner_tag_error(parser *yaml_parser_t, directive bool, context_mark yaml_mark_t, problem string) bool {
	context := "while parsing a tag"
	if directive {
		context = "while parsing a %TAG directive"
	}
	return yaml_parser_set_scanner_error(parser, context, context_mark, problem)
}

func trace(args ...interface{}) func() {
	pargs := append([]interface{}{"+++"}, args...)
	fmt.Println(pargs...)
	pargs = append([]interface{}{"---"}, args...)
	return func() { fmt.Println(pargs...) }
}

func yaml_parser_fetch_more_tokens(parser *yaml_parser_t) bool {
	for {
		if parser.tokens_head < len(parser.tokens)-2 {
			head_tok_idx, ok := parser.simple_keys_by_tok[parser.tokens_parsed]
			if !ok {
				break
			} else if valid, ok := yaml_simple_key_is_valid(parser, &parser.simple_keys[head_tok_idx]); !ok {
				return false
			} else if !valid {
				break
			}
		}
		if !yaml_parser_fetch_next_token(parser) {
			return false
		}
	}

	parser.token_available = true
	return true
}

func yaml_parser_fetch_next_token(parser *yaml_parser_t) (ok bool) {
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}

	if !parser.stream_start_produced {
		return yaml_parser_fetch_stream_start(parser)
	}

	scan_mark := parser.mark

	if !yaml_parser_scan_to_next_token(parser) {
		return false
	}


	if !yaml_parser_unroll_indent(parser, parser.mark.column, scan_mark) {
		return false
	}

	if parser.unread < 4 && !yaml_parser_update_buffer(parser, 4) {
		return false
	}

	if is_z(parser.buffer, parser.buffer_pos) {
		return yaml_parser_fetch_stream_end(parser)
	}

	if parser.mark.column == 0 && parser.buffer[parser.buffer_pos] == '%' {
		return yaml_parser_fetch_directive(parser)
	}

	buf := parser.buffer
	pos := parser.buffer_pos

	if parser.mark.column == 0 && buf[pos] == '-' && buf[pos+1] == '-' && buf[pos+2] == '-' && is_blankz(buf, pos+3) {
		return yaml_parser_fetch_document_indicator(parser, yaml_DOCUMENT_START_TOKEN)
	}

	if parser.mark.column == 0 && buf[pos] == '.' && buf[pos+1] == '.' && buf[pos+2] == '.' && is_blankz(buf, pos+3) {
		return yaml_parser_fetch_document_indicator(parser, yaml_DOCUMENT_END_TOKEN)
	}

	comment_mark := parser.mark
	if len(parser.tokens) > 0 && (parser.flow_level == 0 && buf[pos] == ':' || parser.flow_level > 0 && buf[pos] == ',') {
		comment_mark = parser.tokens[len(parser.tokens)-1].start_mark
	}
	defer func() {
		if !ok {
			return
		}
		if len(parser.tokens) > 0 && parser.tokens[len(parser.tokens)-1].typ == yaml_BLOCK_ENTRY_TOKEN {
			return
		}
		if !yaml_parser_scan_line_comment(parser, comment_mark) {
			ok = false
			return
		}
	}()

	if buf[pos] == '[' {
		return yaml_parser_fetch_flow_collection_start(parser, yaml_FLOW_SEQUENCE_START_TOKEN)
	}

	if parser.buffer[parser.buffer_pos] == '{' {
		return yaml_parser_fetch_flow_collection_start(parser, yaml_FLOW_MAPPING_START_TOKEN)
	}

	if parser.buffer[parser.buffer_pos] == ']' {
		return yaml_parser_fetch_flow_collection_end(parser,
			yaml_FLOW_SEQUENCE_END_TOKEN)
	}

	if parser.buffer[parser.buffer_pos] == '}' {
		return yaml_parser_fetch_flow_collection_end(parser,
			yaml_FLOW_MAPPING_END_TOKEN)
	}

	if parser.buffer[parser.buffer_pos] == ',' {
		return yaml_parser_fetch_flow_entry(parser)
	}

	if parser.buffer[parser.buffer_pos] == '-' && is_blankz(parser.buffer, parser.buffer_pos+1) {
		return yaml_parser_fetch_block_entry(parser)
	}

	if parser.buffer[parser.buffer_pos] == '?' && (parser.flow_level > 0 || is_blankz(parser.buffer, parser.buffer_pos+1)) {
		return yaml_parser_fetch_key(parser)
	}

	if parser.buffer[parser.buffer_pos] == ':' && (parser.flow_level > 0 || is_blankz(parser.buffer, parser.buffer_pos+1)) {
		return yaml_parser_fetch_value(parser)
	}

	if parser.buffer[parser.buffer_pos] == '*' {
		return yaml_parser_fetch_anchor(parser, yaml_ALIAS_TOKEN)
	}

	if parser.buffer[parser.buffer_pos] == '&' {
		return yaml_parser_fetch_anchor(parser, yaml_ANCHOR_TOKEN)
	}

	if parser.buffer[parser.buffer_pos] == '!' {
		return yaml_parser_fetch_tag(parser)
	}

	if parser.buffer[parser.buffer_pos] == '|' && parser.flow_level == 0 {
		return yaml_parser_fetch_block_scalar(parser, true)
	}

	if parser.buffer[parser.buffer_pos] == '>' && parser.flow_level == 0 {
		return yaml_parser_fetch_block_scalar(parser, false)
	}

	if parser.buffer[parser.buffer_pos] == '\'' {
		return yaml_parser_fetch_flow_scalar(parser, true)
	}

	if parser.buffer[parser.buffer_pos] == '"' {
		return yaml_parser_fetch_flow_scalar(parser, false)
	}

	if !(is_blankz(parser.buffer, parser.buffer_pos) || parser.buffer[parser.buffer_pos] == '-' ||
		parser.buffer[parser.buffer_pos] == '?' || parser.buffer[parser.buffer_pos] == ':' ||
		parser.buffer[parser.buffer_pos] == ',' || parser.buffer[parser.buffer_pos] == '[' ||
		parser.buffer[parser.buffer_pos] == ']' || parser.buffer[parser.buffer_pos] == '{' ||
		parser.buffer[parser.buffer_pos] == '}' || parser.buffer[parser.buffer_pos] == '#' ||
		parser.buffer[parser.buffer_pos] == '&' || parser.buffer[parser.buffer_pos] == '*' ||
		parser.buffer[parser.buffer_pos] == '!' || parser.buffer[parser.buffer_pos] == '|' ||
		parser.buffer[parser.buffer_pos] == '>' || parser.buffer[parser.buffer_pos] == '\'' ||
		parser.buffer[parser.buffer_pos] == '"' || parser.buffer[parser.buffer_pos] == '%' ||
		parser.buffer[parser.buffer_pos] == '@' || parser.buffer[parser.buffer_pos] == '`') ||
		(parser.buffer[parser.buffer_pos] == '-' && !is_blank(parser.buffer, parser.buffer_pos+1)) ||
		(parser.flow_level == 0 &&
			(parser.buffer[parser.buffer_pos] == '?' || parser.buffer[parser.buffer_pos] == ':') &&
			!is_blankz(parser.buffer, parser.buffer_pos+1)) {
		return yaml_parser_fetch_plain_scalar(parser)
	}

	return yaml_parser_set_scanner_error(parser,
		"while scanning for the next token", parser.mark,
		"found character that cannot start any token")
}

func yaml_simple_key_is_valid(parser *yaml_parser_t, simple_key *yaml_simple_key_t) (valid, ok bool) {
	if !simple_key.possible {
		return false, true
	}

	if simple_key.mark.line < parser.mark.line || simple_key.mark.index+1024 < parser.mark.index {
		if simple_key.required {
			return false, yaml_parser_set_scanner_error(parser,
				"while scanning a simple key", simple_key.mark,
				"could not find expected ':'")
		}
		simple_key.possible = false
		return false, true
	}
	return true, true
}

func yaml_parser_save_simple_key(parser *yaml_parser_t) bool {

	required := parser.flow_level == 0 && parser.indent == parser.mark.column

	if parser.simple_key_allowed {
		simple_key := yaml_simple_key_t{
			possible:     true,
			required:     required,
			token_number: parser.tokens_parsed + (len(parser.tokens) - parser.tokens_head),
			mark:         parser.mark,
		}

		if !yaml_parser_remove_simple_key(parser) {
			return false
		}
		parser.simple_keys[len(parser.simple_keys)-1] = simple_key
		parser.simple_keys_by_tok[simple_key.token_number] = len(parser.simple_keys) - 1
	}
	return true
}

func yaml_parser_remove_simple_key(parser *yaml_parser_t) bool {
	i := len(parser.simple_keys) - 1
	if parser.simple_keys[i].possible {
		if parser.simple_keys[i].required {
			return yaml_parser_set_scanner_error(parser,
				"while scanning a simple key", parser.simple_keys[i].mark,
				"could not find expected ':'")
		}
		parser.simple_keys[i].possible = false
		delete(parser.simple_keys_by_tok, parser.simple_keys[i].token_number)
	}
	return true
}

const max_flow_level = 10000

func yaml_parser_increase_flow_level(parser *yaml_parser_t) bool {
	parser.simple_keys = append(parser.simple_keys, yaml_simple_key_t{
		possible:     false,
		required:     false,
		token_number: parser.tokens_parsed + (len(parser.tokens) - parser.tokens_head),
		mark:         parser.mark,
	})

	parser.flow_level++
	if parser.flow_level > max_flow_level {
		return yaml_parser_set_scanner_error(parser,
			"while increasing flow level", parser.simple_keys[len(parser.simple_keys)-1].mark,
			fmt.Sprintf("exceeded max depth of %d", max_flow_level))
	}
	return true
}

func yaml_parser_decrease_flow_level(parser *yaml_parser_t) bool {
	if parser.flow_level > 0 {
		parser.flow_level--
		last := len(parser.simple_keys) - 1
		delete(parser.simple_keys_by_tok, parser.simple_keys[last].token_number)
		parser.simple_keys = parser.simple_keys[:last]
	}
	return true
}

const max_indents = 10000

func yaml_parser_roll_indent(parser *yaml_parser_t, column, number int, typ yaml_token_type_t, mark yaml_mark_t) bool {
	if parser.flow_level > 0 {
		return true
	}

	if parser.indent < column {
		parser.indents = append(parser.indents, parser.indent)
		parser.indent = column
		if len(parser.indents) > max_indents {
			return yaml_parser_set_scanner_error(parser,
				"while increasing indent level", parser.simple_keys[len(parser.simple_keys)-1].mark,
				fmt.Sprintf("exceeded max depth of %d", max_indents))
		}

		token := yaml_token_t{
			typ:        typ,
			start_mark: mark,
			end_mark:   mark,
		}
		if number > -1 {
			number -= parser.tokens_parsed
		}
		yaml_insert_token(parser, number, &token)
	}
	return true
}

func yaml_parser_unroll_indent(parser *yaml_parser_t, column int, scan_mark yaml_mark_t) bool {
	if parser.flow_level > 0 {
		return true
	}

	block_mark := scan_mark
	block_mark.index--

	for parser.indent > column {

		stop_index := block_mark.index
		for i := len(parser.comments) - 1; i >= 0; i-- {
			comment := &parser.comments[i]

			if comment.end_mark.index < stop_index {
				break
			}
			if comment.start_mark.column == parser.indent+1 {
				block_mark = comment.start_mark
			}

			stop_index = comment.scan_mark.index
		}

		token := yaml_token_t{
			typ:        yaml_BLOCK_END_TOKEN,
			start_mark: block_mark,
			end_mark:   block_mark,
		}
		yaml_insert_token(parser, -1, &token)

		parser.indent = parser.indents[len(parser.indents)-1]
		parser.indents = parser.indents[:len(parser.indents)-1]
	}
	return true
}

func yaml_parser_fetch_stream_start(parser *yaml_parser_t) bool {

	parser.indent = -1

	parser.simple_keys = append(parser.simple_keys, yaml_simple_key_t{})

	parser.simple_keys_by_tok = make(map[int]int)

	parser.simple_key_allowed = true

	parser.stream_start_produced = true

	token := yaml_token_t{
		typ:        yaml_STREAM_START_TOKEN,
		start_mark: parser.mark,
		end_mark:   parser.mark,
		encoding:   parser.encoding,
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

func yaml_parser_fetch_stream_end(parser *yaml_parser_t) bool {

	if parser.mark.column != 0 {
		parser.mark.column = 0
		parser.mark.line++
	}

	if !yaml_parser_unroll_indent(parser, -1, parser.mark) {
		return false
	}

	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	parser.simple_key_allowed = false

	token := yaml_token_t{
		typ:        yaml_STREAM_END_TOKEN,
		start_mark: parser.mark,
		end_mark:   parser.mark,
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

func yaml_parser_fetch_directive(parser *yaml_parser_t) bool {
	if !yaml_parser_unroll_indent(parser, -1, parser.mark) {
		return false
	}

	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	parser.simple_key_allowed = false

	token := yaml_token_t{}
	if !yaml_parser_scan_directive(parser, &token) {
		return false
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

func yaml_parser_fetch_document_indicator(parser *yaml_parser_t, typ yaml_token_type_t) bool {
	if !yaml_parser_unroll_indent(parser, -1, parser.mark) {
		return false
	}

	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	parser.simple_key_allowed = false

	start_mark := parser.mark

	skip(parser)
	skip(parser)
	skip(parser)

	end_mark := parser.mark

	token := yaml_token_t{
		typ:        typ,
		start_mark: start_mark,
		end_mark:   end_mark,
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

func yaml_parser_fetch_flow_collection_start(parser *yaml_parser_t, typ yaml_token_type_t) bool {

	if !yaml_parser_save_simple_key(parser) {
		return false
	}

	if !yaml_parser_increase_flow_level(parser) {
		return false
	}

	parser.simple_key_allowed = true

	start_mark := parser.mark
	skip(parser)
	end_mark := parser.mark

	token := yaml_token_t{
		typ:        typ,
		start_mark: start_mark,
		end_mark:   end_mark,
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

func yaml_parser_fetch_flow_collection_end(parser *yaml_parser_t, typ yaml_token_type_t) bool {
	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	if !yaml_parser_decrease_flow_level(parser) {
		return false
	}

	parser.simple_key_allowed = false


	start_mark := parser.mark
	skip(parser)
	end_mark := parser.mark

	token := yaml_token_t{
		typ:        typ,
		start_mark: start_mark,
		end_mark:   end_mark,
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

func yaml_parser_fetch_flow_entry(parser *yaml_parser_t) bool {
	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	parser.simple_key_allowed = true

	start_mark := parser.mark
	skip(parser)
	end_mark := parser.mark

	token := yaml_token_t{
		typ:        yaml_FLOW_ENTRY_TOKEN,
		start_mark: start_mark,
		end_mark:   end_mark,
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

func yaml_parser_fetch_block_entry(parser *yaml_parser_t) bool {
	if parser.flow_level == 0 {
		if !parser.simple_key_allowed {
			return yaml_parser_set_scanner_error(parser, "", parser.mark,
				"block sequence entries are not allowed in this context")
		}
		if !yaml_parser_roll_indent(parser, parser.mark.column, -1, yaml_BLOCK_SEQUENCE_START_TOKEN, parser.mark) {
			return false
		}
	} else {
	}

	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	parser.simple_key_allowed = true

	start_mark := parser.mark
	skip(parser)
	end_mark := parser.mark

	token := yaml_token_t{
		typ:        yaml_BLOCK_ENTRY_TOKEN,
		start_mark: start_mark,
		end_mark:   end_mark,
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

func yaml_parser_fetch_key(parser *yaml_parser_t) bool {

	if parser.flow_level == 0 {
		if !parser.simple_key_allowed {
			return yaml_parser_set_scanner_error(parser, "", parser.mark,
				"mapping keys are not allowed in this context")
		}
		if !yaml_parser_roll_indent(parser, parser.mark.column, -1, yaml_BLOCK_MAPPING_START_TOKEN, parser.mark) {
			return false
		}
	}

	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	parser.simple_key_allowed = parser.flow_level == 0

	start_mark := parser.mark
	skip(parser)
	end_mark := parser.mark

	token := yaml_token_t{
		typ:        yaml_KEY_TOKEN,
		start_mark: start_mark,
		end_mark:   end_mark,
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

func yaml_parser_fetch_value(parser *yaml_parser_t) bool {

	simple_key := &parser.simple_keys[len(parser.simple_keys)-1]

	if valid, ok := yaml_simple_key_is_valid(parser, simple_key); !ok {
		return false

	} else if valid {

		token := yaml_token_t{
			typ:        yaml_KEY_TOKEN,
			start_mark: simple_key.mark,
			end_mark:   simple_key.mark,
		}
		yaml_insert_token(parser, simple_key.token_number-parser.tokens_parsed, &token)

		if !yaml_parser_roll_indent(parser, simple_key.mark.column,
			simple_key.token_number,
			yaml_BLOCK_MAPPING_START_TOKEN, simple_key.mark) {
			return false
		}

		simple_key.possible = false
		delete(parser.simple_keys_by_tok, simple_key.token_number)

		parser.simple_key_allowed = false

	} else {

		if parser.flow_level == 0 {

			if !parser.simple_key_allowed {
				return yaml_parser_set_scanner_error(parser, "", parser.mark,
					"mapping values are not allowed in this context")
			}

			if !yaml_parser_roll_indent(parser, parser.mark.column, -1, yaml_BLOCK_MAPPING_START_TOKEN, parser.mark) {
				return false
			}
		}

		parser.simple_key_allowed = parser.flow_level == 0
	}

	start_mark := parser.mark
	skip(parser)
	end_mark := parser.mark

	token := yaml_token_t{
		typ:        yaml_VALUE_TOKEN,
		start_mark: start_mark,
		end_mark:   end_mark,
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

func yaml_parser_fetch_anchor(parser *yaml_parser_t, typ yaml_token_type_t) bool {
	if !yaml_parser_save_simple_key(parser) {
		return false
	}

	parser.simple_key_allowed = false

	var token yaml_token_t
	if !yaml_parser_scan_anchor(parser, &token, typ) {
		return false
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

func yaml_parser_fetch_tag(parser *yaml_parser_t) bool {
	if !yaml_parser_save_simple_key(parser) {
		return false
	}

	parser.simple_key_allowed = false

	var token yaml_token_t
	if !yaml_parser_scan_tag(parser, &token) {
		return false
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

func yaml_parser_fetch_block_scalar(parser *yaml_parser_t, literal bool) bool {
	if !yaml_parser_remove_simple_key(parser) {
		return false
	}

	parser.simple_key_allowed = true

	var token yaml_token_t
	if !yaml_parser_scan_block_scalar(parser, &token, literal) {
		return false
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

func yaml_parser_fetch_flow_scalar(parser *yaml_parser_t, single bool) bool {
	if !yaml_parser_save_simple_key(parser) {
		return false
	}

	parser.simple_key_allowed = false

	var token yaml_token_t
	if !yaml_parser_scan_flow_scalar(parser, &token, single) {
		return false
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

func yaml_parser_fetch_plain_scalar(parser *yaml_parser_t) bool {
	if !yaml_parser_save_simple_key(parser) {
		return false
	}

	parser.simple_key_allowed = false

	var token yaml_token_t
	if !yaml_parser_scan_plain_scalar(parser, &token) {
		return false
	}
	yaml_insert_token(parser, -1, &token)
	return true
}

func yaml_parser_scan_to_next_token(parser *yaml_parser_t) bool {

	scan_mark := parser.mark

	for {
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
		if parser.mark.column == 0 && is_bom(parser.buffer, parser.buffer_pos) {
			skip(parser)
		}

		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}

		for parser.buffer[parser.buffer_pos] == ' ' || ((parser.flow_level > 0 || !parser.simple_key_allowed) && parser.buffer[parser.buffer_pos] == '\t') {
			skip(parser)
			if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
				return false
			}
		}

		if len(parser.comments) > 0 && len(parser.tokens) > 1 {
			tokenA := parser.tokens[len(parser.tokens)-2]
			tokenB := parser.tokens[len(parser.tokens)-1]
			comment := &parser.comments[len(parser.comments)-1]
			if tokenA.typ == yaml_BLOCK_SEQUENCE_START_TOKEN && tokenB.typ == yaml_BLOCK_ENTRY_TOKEN && len(comment.line) > 0 && !is_break(parser.buffer, parser.buffer_pos) {
				comment.head = comment.line
				comment.line = nil
				if comment.start_mark.line == parser.mark.line-1 {
					comment.token_mark = parser.mark
				}
			}
		}

		if parser.buffer[parser.buffer_pos] == '#' {
			if !yaml_parser_scan_comments(parser, scan_mark) {
				return false
			}
		}

		if is_break(parser.buffer, parser.buffer_pos) {
			if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
				return false
			}
			skip_line(parser)

			if parser.flow_level == 0 {
				parser.simple_key_allowed = true
			}
		} else {
			break
		}
	}

	return true
}

func yaml_parser_scan_directive(parser *yaml_parser_t, token *yaml_token_t) bool {
	start_mark := parser.mark
	skip(parser)

	var name []byte
	if !yaml_parser_scan_directive_name(parser, start_mark, &name) {
		return false
	}

	if bytes.Equal(name, []byte("YAML")) {
		var major, minor int8
		if !yaml_parser_scan_version_directive_value(parser, start_mark, &major, &minor) {
			return false
		}
		end_mark := parser.mark

		*token = yaml_token_t{
			typ:        yaml_VERSION_DIRECTIVE_TOKEN,
			start_mark: start_mark,
			end_mark:   end_mark,
			major:      major,
			minor:      minor,
		}

	} else if bytes.Equal(name, []byte("TAG")) {
		var handle, prefix []byte
		if !yaml_parser_scan_tag_directive_value(parser, start_mark, &handle, &prefix) {
			return false
		}
		end_mark := parser.mark

		*token = yaml_token_t{
			typ:        yaml_TAG_DIRECTIVE_TOKEN,
			start_mark: start_mark,
			end_mark:   end_mark,
			value:      handle,
			prefix:     prefix,
		}

	} else {
		yaml_parser_set_scanner_error(parser, "while scanning a directive",
			start_mark, "found unknown directive name")
		return false
	}

	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}

	for is_blank(parser.buffer, parser.buffer_pos) {
		skip(parser)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}

	if parser.buffer[parser.buffer_pos] == '#' {
		for !is_breakz(parser.buffer, parser.buffer_pos) {
			skip(parser)
			if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
				return false
			}
		}
	}

	if !is_breakz(parser.buffer, parser.buffer_pos) {
		yaml_parser_set_scanner_error(parser, "while scanning a directive",
			start_mark, "did not find expected comment or line break")
		return false
	}

	if is_break(parser.buffer, parser.buffer_pos) {
		if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
			return false
		}
		skip_line(parser)
	}

	return true
}

func yaml_parser_scan_directive_name(parser *yaml_parser_t, start_mark yaml_mark_t, name *[]byte) bool {
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}

	var s []byte
	for is_alpha(parser.buffer, parser.buffer_pos) {
		s = read(parser, s)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}

	if len(s) == 0 {
		yaml_parser_set_scanner_error(parser, "while scanning a directive",
			start_mark, "could not find expected directive name")
		return false
	}

	if !is_blankz(parser.buffer, parser.buffer_pos) {
		yaml_parser_set_scanner_error(parser, "while scanning a directive",
			start_mark, "found unexpected non-alphabetical character")
		return false
	}
	*name = s
	return true
}

func yaml_parser_scan_version_directive_value(parser *yaml_parser_t, start_mark yaml_mark_t, major, minor *int8) bool {
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	for is_blank(parser.buffer, parser.buffer_pos) {
		skip(parser)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}

	if !yaml_parser_scan_version_directive_number(parser, start_mark, major) {
		return false
	}

	if parser.buffer[parser.buffer_pos] != '.' {
		return yaml_parser_set_scanner_error(parser, "while scanning a %YAML directive",
			start_mark, "did not find expected digit or '.' character")
	}

	skip(parser)

	if !yaml_parser_scan_version_directive_number(parser, start_mark, minor) {
		return false
	}
	return true
}

const max_number_length = 2

func yaml_parser_scan_version_directive_number(parser *yaml_parser_t, start_mark yaml_mark_t, number *int8) bool {

	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	var value, length int8
	for is_digit(parser.buffer, parser.buffer_pos) {
		length++
		if length > max_number_length {
			return yaml_parser_set_scanner_error(parser, "while scanning a %YAML directive",
				start_mark, "found extremely long version number")
		}
		value = value*10 + int8(as_digit(parser.buffer, parser.buffer_pos))
		skip(parser)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}

	if length == 0 {
		return yaml_parser_set_scanner_error(parser, "while scanning a %YAML directive",
			start_mark, "did not find expected version number")
	}
	*number = value
	return true
}

func yaml_parser_scan_tag_directive_value(parser *yaml_parser_t, start_mark yaml_mark_t, handle, prefix *[]byte) bool {
	var handle_value, prefix_value []byte

	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}

	for is_blank(parser.buffer, parser.buffer_pos) {
		skip(parser)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}

	if !yaml_parser_scan_tag_handle(parser, true, start_mark, &handle_value) {
		return false
	}

	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	if !is_blank(parser.buffer, parser.buffer_pos) {
		yaml_parser_set_scanner_error(parser, "while scanning a %TAG directive",
			start_mark, "did not find expected whitespace")
		return false
	}

	for is_blank(parser.buffer, parser.buffer_pos) {
		skip(parser)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}

	if !yaml_parser_scan_tag_uri(parser, true, nil, start_mark, &prefix_value) {
		return false
	}

	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	if !is_blankz(parser.buffer, parser.buffer_pos) {
		yaml_parser_set_scanner_error(parser, "while scanning a %TAG directive",
			start_mark, "did not find expected whitespace or line break")
		return false
	}

	*handle = handle_value
	*prefix = prefix_value
	return true
}

func yaml_parser_scan_anchor(parser *yaml_parser_t, token *yaml_token_t, typ yaml_token_type_t) bool {
	var s []byte

	start_mark := parser.mark
	skip(parser)

	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}

	for is_alpha(parser.buffer, parser.buffer_pos) {
		s = read(parser, s)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}

	end_mark := parser.mark


	if len(s) == 0 ||
		!(is_blankz(parser.buffer, parser.buffer_pos) || parser.buffer[parser.buffer_pos] == '?' ||
			parser.buffer[parser.buffer_pos] == ':' || parser.buffer[parser.buffer_pos] == ',' ||
			parser.buffer[parser.buffer_pos] == ']' || parser.buffer[parser.buffer_pos] == '}' ||
			parser.buffer[parser.buffer_pos] == '%' || parser.buffer[parser.buffer_pos] == '@' ||
			parser.buffer[parser.buffer_pos] == '`') {
		context := "while scanning an alias"
		if typ == yaml_ANCHOR_TOKEN {
			context = "while scanning an anchor"
		}
		yaml_parser_set_scanner_error(parser, context, start_mark,
			"did not find expected alphabetic or numeric character")
		return false
	}

	*token = yaml_token_t{
		typ:        typ,
		start_mark: start_mark,
		end_mark:   end_mark,
		value:      s,
	}

	return true
}


func yaml_parser_scan_tag(parser *yaml_parser_t, token *yaml_token_t) bool {
	var handle, suffix []byte

	start_mark := parser.mark

	if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
		return false
	}

	if parser.buffer[parser.buffer_pos+1] == '<' {

		skip(parser)
		skip(parser)

		if !yaml_parser_scan_tag_uri(parser, false, nil, start_mark, &suffix) {
			return false
		}

		if parser.buffer[parser.buffer_pos] != '>' {
			yaml_parser_set_scanner_error(parser, "while scanning a tag",
				start_mark, "did not find the expected '>'")
			return false
		}

		skip(parser)
	} else {

		if !yaml_parser_scan_tag_handle(parser, false, start_mark, &handle) {
			return false
		}

		if handle[0] == '!' && len(handle) > 1 && handle[len(handle)-1] == '!' {
			if !yaml_parser_scan_tag_uri(parser, false, nil, start_mark, &suffix) {
				return false
			}
		} else {
			if !yaml_parser_scan_tag_uri(parser, false, handle, start_mark, &suffix) {
				return false
			}

			handle = []byte{'!'}

			if len(suffix) == 0 {
				handle, suffix = suffix, handle
			}
		}
	}

	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	if !is_blankz(parser.buffer, parser.buffer_pos) {
		yaml_parser_set_scanner_error(parser, "while scanning a tag",
			start_mark, "did not find expected whitespace or line break")
		return false
	}

	end_mark := parser.mark

	*token = yaml_token_t{
		typ:        yaml_TAG_TOKEN,
		start_mark: start_mark,
		end_mark:   end_mark,
		value:      handle,
		suffix:     suffix,
	}
	return true
}

func yaml_parser_scan_tag_handle(parser *yaml_parser_t, directive bool, start_mark yaml_mark_t, handle *[]byte) bool {
	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	if parser.buffer[parser.buffer_pos] != '!' {
		yaml_parser_set_scanner_tag_error(parser, directive,
			start_mark, "did not find expected '!'")
		return false
	}

	var s []byte

	s = read(parser, s)

	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	for is_alpha(parser.buffer, parser.buffer_pos) {
		s = read(parser, s)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}

	if parser.buffer[parser.buffer_pos] == '!' {
		s = read(parser, s)
	} else {
		if directive && string(s) != "!" {
			yaml_parser_set_scanner_tag_error(parser, directive,
				start_mark, "did not find expected '!'")
			return false
		}
	}

	*handle = s
	return true
}

func yaml_parser_scan_tag_uri(parser *yaml_parser_t, directive bool, head []byte, start_mark yaml_mark_t, uri *[]byte) bool {
	var s []byte
	hasTag := len(head) > 0

	if len(head) > 1 {
		s = append(s, head[1:]...)
	}

	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}

	for is_alpha(parser.buffer, parser.buffer_pos) || parser.buffer[parser.buffer_pos] == ';' ||
		parser.buffer[parser.buffer_pos] == '/' || parser.buffer[parser.buffer_pos] == '?' ||
		parser.buffer[parser.buffer_pos] == ':' || parser.buffer[parser.buffer_pos] == '@' ||
		parser.buffer[parser.buffer_pos] == '&' || parser.buffer[parser.buffer_pos] == '=' ||
		parser.buffer[parser.buffer_pos] == '+' || parser.buffer[parser.buffer_pos] == '$' ||
		parser.buffer[parser.buffer_pos] == ',' || parser.buffer[parser.buffer_pos] == '.' ||
		parser.buffer[parser.buffer_pos] == '!' || parser.buffer[parser.buffer_pos] == '~' ||
		parser.buffer[parser.buffer_pos] == '*' || parser.buffer[parser.buffer_pos] == '\'' ||
		parser.buffer[parser.buffer_pos] == '(' || parser.buffer[parser.buffer_pos] == ')' ||
		parser.buffer[parser.buffer_pos] == '[' || parser.buffer[parser.buffer_pos] == ']' ||
		parser.buffer[parser.buffer_pos] == '%' {
		if parser.buffer[parser.buffer_pos] == '%' {
			if !yaml_parser_scan_uri_escapes(parser, directive, start_mark, &s) {
				return false
			}
		} else {
			s = read(parser, s)
		}
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
		hasTag = true
	}

	if !hasTag {
		yaml_parser_set_scanner_tag_error(parser, directive,
			start_mark, "did not find expected tag URI")
		return false
	}
	*uri = s
	return true
}

func yaml_parser_scan_uri_escapes(parser *yaml_parser_t, directive bool, start_mark yaml_mark_t, s *[]byte) bool {

	w := 1024
	for w > 0 {
		if parser.unread < 3 && !yaml_parser_update_buffer(parser, 3) {
			return false
		}

		if !(parser.buffer[parser.buffer_pos] == '%' &&
			is_hex(parser.buffer, parser.buffer_pos+1) &&
			is_hex(parser.buffer, parser.buffer_pos+2)) {
			return yaml_parser_set_scanner_tag_error(parser, directive,
				start_mark, "did not find URI escaped octet")
		}

		octet := byte((as_hex(parser.buffer, parser.buffer_pos+1) << 4) + as_hex(parser.buffer, parser.buffer_pos+2))

		if w == 1024 {
			w = width(octet)
			if w == 0 {
				return yaml_parser_set_scanner_tag_error(parser, directive,
					start_mark, "found an incorrect leading UTF-8 octet")
			}
		} else {
			if octet&0xC0 != 0x80 {
				return yaml_parser_set_scanner_tag_error(parser, directive,
					start_mark, "found an incorrect trailing UTF-8 octet")
			}
		}

		*s = append(*s, octet)
		skip(parser)
		skip(parser)
		skip(parser)
		w--
	}
	return true
}

func yaml_parser_scan_block_scalar(parser *yaml_parser_t, token *yaml_token_t, literal bool) bool {
	start_mark := parser.mark
	skip(parser)

	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}

	var chomping, increment int
	if parser.buffer[parser.buffer_pos] == '+' || parser.buffer[parser.buffer_pos] == '-' {
		if parser.buffer[parser.buffer_pos] == '+' {
			chomping = +1
		} else {
			chomping = -1
		}
		skip(parser)

		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
		if is_digit(parser.buffer, parser.buffer_pos) {
			if parser.buffer[parser.buffer_pos] == '0' {
				yaml_parser_set_scanner_error(parser, "while scanning a block scalar",
					start_mark, "found an indentation indicator equal to 0")
				return false
			}

			increment = as_digit(parser.buffer, parser.buffer_pos)
			skip(parser)
		}

	} else if is_digit(parser.buffer, parser.buffer_pos) {

		if parser.buffer[parser.buffer_pos] == '0' {
			yaml_parser_set_scanner_error(parser, "while scanning a block scalar",
				start_mark, "found an indentation indicator equal to 0")
			return false
		}
		increment = as_digit(parser.buffer, parser.buffer_pos)
		skip(parser)

		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
		if parser.buffer[parser.buffer_pos] == '+' || parser.buffer[parser.buffer_pos] == '-' {
			if parser.buffer[parser.buffer_pos] == '+' {
				chomping = +1
			} else {
				chomping = -1
			}
			skip(parser)
		}
	}

	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	for is_blank(parser.buffer, parser.buffer_pos) {
		skip(parser)
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
	}
	if parser.buffer[parser.buffer_pos] == '#' {
		if !yaml_parser_scan_line_comment(parser, start_mark) {
			return false
		}
		for !is_breakz(parser.buffer, parser.buffer_pos) {
			skip(parser)
			if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
				return false
			}
		}
	}

	if !is_breakz(parser.buffer, parser.buffer_pos) {
		yaml_parser_set_scanner_error(parser, "while scanning a block scalar",
			start_mark, "did not find expected comment or line break")
		return false
	}

	if is_break(parser.buffer, parser.buffer_pos) {
		if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
			return false
		}
		skip_line(parser)
	}

	end_mark := parser.mark

	var indent int
	if increment > 0 {
		if parser.indent >= 0 {
			indent = parser.indent + increment
		} else {
			indent = increment
		}
	}

	var s, leading_break, trailing_breaks []byte
	if !yaml_parser_scan_block_scalar_breaks(parser, &indent, &trailing_breaks, start_mark, &end_mark) {
		return false
	}

	if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
		return false
	}
	var leading_blank, trailing_blank bool
	for parser.mark.column == indent && !is_z(parser.buffer, parser.buffer_pos) {

		trailing_blank = is_blank(parser.buffer, parser.buffer_pos)

		if !literal && !leading_blank && !trailing_blank && len(leading_break) > 0 && leading_break[0] == '\n' {
			if len(trailing_breaks) == 0 {
				s = append(s, ' ')
			}
		} else {
			s = append(s, leading_break...)
		}
		leading_break = leading_break[:0]

		s = append(s, trailing_breaks...)
		trailing_breaks = trailing_breaks[:0]

		leading_blank = is_blank(parser.buffer, parser.buffer_pos)

		for !is_breakz(parser.buffer, parser.buffer_pos) {
			s = read(parser, s)
			if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
				return false
			}
		}

		if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
			return false
		}

		leading_break = read_line(parser, leading_break)

		if !yaml_parser_scan_block_scalar_breaks(parser, &indent, &trailing_breaks, start_mark, &end_mark) {
			return false
		}
	}

	if chomping != -1 {
		s = append(s, leading_break...)
	}
	if chomping == 1 {
		s = append(s, trailing_breaks...)
	}

	*token = yaml_token_t{
		typ:        yaml_SCALAR_TOKEN,
		start_mark: start_mark,
		end_mark:   end_mark,
		value:      s,
		style:      yaml_LITERAL_SCALAR_STYLE,
	}
	if !literal {
		token.style = yaml_FOLDED_SCALAR_STYLE
	}
	return true
}

func yaml_parser_scan_block_scalar_breaks(parser *yaml_parser_t, indent *int, breaks *[]byte, start_mark yaml_mark_t, end_mark *yaml_mark_t) bool {
	*end_mark = parser.mark

	max_indent := 0
	for {
		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}
		for (*indent == 0 || parser.mark.column < *indent) && is_space(parser.buffer, parser.buffer_pos) {
			skip(parser)
			if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
				return false
			}
		}
		if parser.mark.column > max_indent {
			max_indent = parser.mark.column
		}

		if (*indent == 0 || parser.mark.column < *indent) && is_tab(parser.buffer, parser.buffer_pos) {
			return yaml_parser_set_scanner_error(parser, "while scanning a block scalar",
				start_mark, "found a tab character where an indentation space is expected")
		}

		if !is_break(parser.buffer, parser.buffer_pos) {
			break
		}

		if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
			return false
		}
		*breaks = read_line(parser, *breaks)
		*end_mark = parser.mark
	}

	if *indent == 0 {
		*indent = max_indent
		if *indent < parser.indent+1 {
			*indent = parser.indent + 1
		}
		if *indent < 1 {
			*indent = 1
		}
	}
	return true
}

func yaml_parser_scan_flow_scalar(parser *yaml_parser_t, token *yaml_token_t, single bool) bool {
	start_mark := parser.mark
	skip(parser)

	var s, leading_break, trailing_breaks, whitespaces []byte
	for {
		if parser.unread < 4 && !yaml_parser_update_buffer(parser, 4) {
			return false
		}

		if parser.mark.column == 0 &&
			((parser.buffer[parser.buffer_pos+0] == '-' &&
				parser.buffer[parser.buffer_pos+1] == '-' &&
				parser.buffer[parser.buffer_pos+2] == '-') ||
				(parser.buffer[parser.buffer_pos+0] == '.' &&
					parser.buffer[parser.buffer_pos+1] == '.' &&
					parser.buffer[parser.buffer_pos+2] == '.')) &&
			is_blankz(parser.buffer, parser.buffer_pos+3) {
			yaml_parser_set_scanner_error(parser, "while scanning a quoted scalar",
				start_mark, "found unexpected document indicator")
			return false
		}

		if is_z(parser.buffer, parser.buffer_pos) {
			yaml_parser_set_scanner_error(parser, "while scanning a quoted scalar",
				start_mark, "found unexpected end of stream")
			return false
		}

		leading_blanks := false
		for !is_blankz(parser.buffer, parser.buffer_pos) {
			if single && parser.buffer[parser.buffer_pos] == '\'' && parser.buffer[parser.buffer_pos+1] == '\'' {
				s = append(s, '\'')
				skip(parser)
				skip(parser)

			} else if single && parser.buffer[parser.buffer_pos] == '\'' {
				break
			} else if !single && parser.buffer[parser.buffer_pos] == '"' {
				break

			} else if !single && parser.buffer[parser.buffer_pos] == '\\' && is_break(parser.buffer, parser.buffer_pos+1) {
				if parser.unread < 3 && !yaml_parser_update_buffer(parser, 3) {
					return false
				}
				skip(parser)
				skip_line(parser)
				leading_blanks = true
				break

			} else if !single && parser.buffer[parser.buffer_pos] == '\\' {
				code_length := 0

				switch parser.buffer[parser.buffer_pos+1] {
				case '0':
					s = append(s, 0)
				case 'a':
					s = append(s, '\x07')
				case 'b':
					s = append(s, '\x08')
				case 't', '\t':
					s = append(s, '\x09')
				case 'n':
					s = append(s, '\x0A')
				case 'v':
					s = append(s, '\x0B')
				case 'f':
					s = append(s, '\x0C')
				case 'r':
					s = append(s, '\x0D')
				case 'e':
					s = append(s, '\x1B')
				case ' ':
					s = append(s, '\x20')
				case '"':
					s = append(s, '"')
				case '\'':
					s = append(s, '\'')
				case '\\':
					s = append(s, '\\')
				case 'N':
					s = append(s, '\xC2')
					s = append(s, '\x85')
				case '_':
					s = append(s, '\xC2')
					s = append(s, '\xA0')
				case 'L':
					s = append(s, '\xE2')
					s = append(s, '\x80')
					s = append(s, '\xA8')
				case 'P':
					s = append(s, '\xE2')
					s = append(s, '\x80')
					s = append(s, '\xA9')
				case 'x':
					code_length = 2
				case 'u':
					code_length = 4
				case 'U':
					code_length = 8
				default:
					yaml_parser_set_scanner_error(parser, "while parsing a quoted scalar",
						start_mark, "found unknown escape character")
					return false
				}

				skip(parser)
				skip(parser)

				if code_length > 0 {
					var value int

					if parser.unread < code_length && !yaml_parser_update_buffer(parser, code_length) {
						return false
					}
					for k := 0; k < code_length; k++ {
						if !is_hex(parser.buffer, parser.buffer_pos+k) {
							yaml_parser_set_scanner_error(parser, "while parsing a quoted scalar",
								start_mark, "did not find expected hexdecimal number")
							return false
						}
						value = (value << 4) + as_hex(parser.buffer, parser.buffer_pos+k)
					}

					if (value >= 0xD800 && value <= 0xDFFF) || value > 0x10FFFF {
						yaml_parser_set_scanner_error(parser, "while parsing a quoted scalar",
							start_mark, "found invalid Unicode character escape code")
						return false
					}
					if value <= 0x7F {
						s = append(s, byte(value))
					} else if value <= 0x7FF {
						s = append(s, byte(0xC0+(value>>6)))
						s = append(s, byte(0x80+(value&0x3F)))
					} else if value <= 0xFFFF {
						s = append(s, byte(0xE0+(value>>12)))
						s = append(s, byte(0x80+((value>>6)&0x3F)))
						s = append(s, byte(0x80+(value&0x3F)))
					} else {
						s = append(s, byte(0xF0+(value>>18)))
						s = append(s, byte(0x80+((value>>12)&0x3F)))
						s = append(s, byte(0x80+((value>>6)&0x3F)))
						s = append(s, byte(0x80+(value&0x3F)))
					}

					for k := 0; k < code_length; k++ {
						skip(parser)
					}
				}
			} else {
				s = read(parser, s)
			}
			if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
				return false
			}
		}

		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}

		if single {
			if parser.buffer[parser.buffer_pos] == '\'' {
				break
			}
		} else {
			if parser.buffer[parser.buffer_pos] == '"' {
				break
			}
		}

		for is_blank(parser.buffer, parser.buffer_pos) || is_break(parser.buffer, parser.buffer_pos) {
			if is_blank(parser.buffer, parser.buffer_pos) {
				if !leading_blanks {
					whitespaces = read(parser, whitespaces)
				} else {
					skip(parser)
				}
			} else {
				if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
					return false
				}

				if !leading_blanks {
					whitespaces = whitespaces[:0]
					leading_break = read_line(parser, leading_break)
					leading_blanks = true
				} else {
					trailing_breaks = read_line(parser, trailing_breaks)
				}
			}
			if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
				return false
			}
		}

		if leading_blanks {
			if len(leading_break) > 0 && leading_break[0] == '\n' {
				if len(trailing_breaks) == 0 {
					s = append(s, ' ')
				} else {
					s = append(s, trailing_breaks...)
				}
			} else {
				s = append(s, leading_break...)
				s = append(s, trailing_breaks...)
			}
			trailing_breaks = trailing_breaks[:0]
			leading_break = leading_break[:0]
		} else {
			s = append(s, whitespaces...)
			whitespaces = whitespaces[:0]
		}
	}

	skip(parser)
	end_mark := parser.mark

	*token = yaml_token_t{
		typ:        yaml_SCALAR_TOKEN,
		start_mark: start_mark,
		end_mark:   end_mark,
		value:      s,
		style:      yaml_SINGLE_QUOTED_SCALAR_STYLE,
	}
	if !single {
		token.style = yaml_DOUBLE_QUOTED_SCALAR_STYLE
	}
	return true
}

func yaml_parser_scan_plain_scalar(parser *yaml_parser_t, token *yaml_token_t) bool {

	var s, leading_break, trailing_breaks, whitespaces []byte
	var leading_blanks bool
	var indent = parser.indent + 1

	start_mark := parser.mark
	end_mark := parser.mark

	for {
		if parser.unread < 4 && !yaml_parser_update_buffer(parser, 4) {
			return false
		}
		if parser.mark.column == 0 &&
			((parser.buffer[parser.buffer_pos+0] == '-' &&
				parser.buffer[parser.buffer_pos+1] == '-' &&
				parser.buffer[parser.buffer_pos+2] == '-') ||
				(parser.buffer[parser.buffer_pos+0] == '.' &&
					parser.buffer[parser.buffer_pos+1] == '.' &&
					parser.buffer[parser.buffer_pos+2] == '.')) &&
			is_blankz(parser.buffer, parser.buffer_pos+3) {
			break
		}

		if parser.buffer[parser.buffer_pos] == '#' {
			break
		}

		for !is_blankz(parser.buffer, parser.buffer_pos) {

			if (parser.buffer[parser.buffer_pos] == ':' && is_blankz(parser.buffer, parser.buffer_pos+1)) ||
				(parser.flow_level > 0 &&
					(parser.buffer[parser.buffer_pos] == ',' ||
						parser.buffer[parser.buffer_pos] == '?' || parser.buffer[parser.buffer_pos] == '[' ||
						parser.buffer[parser.buffer_pos] == ']' || parser.buffer[parser.buffer_pos] == '{' ||
						parser.buffer[parser.buffer_pos] == '}')) {
				break
			}

			if leading_blanks || len(whitespaces) > 0 {
				if leading_blanks {
					if leading_break[0] == '\n' {
						if len(trailing_breaks) == 0 {
							s = append(s, ' ')
						} else {
							s = append(s, trailing_breaks...)
						}
					} else {
						s = append(s, leading_break...)
						s = append(s, trailing_breaks...)
					}
					trailing_breaks = trailing_breaks[:0]
					leading_break = leading_break[:0]
					leading_blanks = false
				} else {
					s = append(s, whitespaces...)
					whitespaces = whitespaces[:0]
				}
			}

			s = read(parser, s)

			end_mark = parser.mark
			if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
				return false
			}
		}

		if !(is_blank(parser.buffer, parser.buffer_pos) || is_break(parser.buffer, parser.buffer_pos)) {
			break
		}

		if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
			return false
		}

		for is_blank(parser.buffer, parser.buffer_pos) || is_break(parser.buffer, parser.buffer_pos) {
			if is_blank(parser.buffer, parser.buffer_pos) {

				if leading_blanks && parser.mark.column < indent && is_tab(parser.buffer, parser.buffer_pos) {
					yaml_parser_set_scanner_error(parser, "while scanning a plain scalar",
						start_mark, "found a tab character that violates indentation")
					return false
				}

				if !leading_blanks {
					whitespaces = read(parser, whitespaces)
				} else {
					skip(parser)
				}
			} else {
				if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
					return false
				}

				if !leading_blanks {
					whitespaces = whitespaces[:0]
					leading_break = read_line(parser, leading_break)
					leading_blanks = true
				} else {
					trailing_breaks = read_line(parser, trailing_breaks)
				}
			}
			if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
				return false
			}
		}

		if parser.flow_level == 0 && parser.mark.column < indent {
			break
		}
	}

	*token = yaml_token_t{
		typ:        yaml_SCALAR_TOKEN,
		start_mark: start_mark,
		end_mark:   end_mark,
		value:      s,
		style:      yaml_PLAIN_SCALAR_STYLE,
	}

	if leading_blanks {
		parser.simple_key_allowed = true
	}
	return true
}

func yaml_parser_scan_line_comment(parser *yaml_parser_t, token_mark yaml_mark_t) bool {
	if parser.newlines > 0 {
		return true
	}

	var start_mark yaml_mark_t
	var text []byte

	for peek := 0; peek < 512; peek++ {
		if parser.unread < peek+1 && !yaml_parser_update_buffer(parser, peek+1) {
			break
		}
		if is_blank(parser.buffer, parser.buffer_pos+peek) {
			continue
		}
		if parser.buffer[parser.buffer_pos+peek] == '#' {
			seen := parser.mark.index + peek
			for {
				if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
					return false
				}
				if is_breakz(parser.buffer, parser.buffer_pos) {
					if parser.mark.index >= seen {
						break
					}
					if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
						return false
					}
					skip_line(parser)
				} else if parser.mark.index >= seen {
					if len(text) == 0 {
						start_mark = parser.mark
					}
					text = read(parser, text)
				} else {
					skip(parser)
				}
			}
		}
		break
	}
	if len(text) > 0 {
		parser.comments = append(parser.comments, yaml_comment_t{
			token_mark: token_mark,
			start_mark: start_mark,
			line:       text,
		})
	}
	return true
}

func yaml_parser_scan_comments(parser *yaml_parser_t, scan_mark yaml_mark_t) bool {
	token := parser.tokens[len(parser.tokens)-1]

	if token.typ == yaml_FLOW_ENTRY_TOKEN && len(parser.tokens) > 1 {
		token = parser.tokens[len(parser.tokens)-2]
	}

	var token_mark = token.start_mark
	var start_mark yaml_mark_t
	var next_indent = parser.indent
	if next_indent < 0 {
		next_indent = 0
	}

	var recent_empty = false
	var first_empty = parser.newlines <= 1

	var line = parser.mark.line
	var column = parser.mark.column

	var text []byte

	var foot_line = -1
	if scan_mark.line > 0 {
		foot_line = parser.mark.line - parser.newlines + 1
		if parser.newlines == 0 && parser.mark.column > 1 {
			foot_line++
		}
	}

	var peek = 0
	for ; peek < 512; peek++ {
		if parser.unread < peek+1 && !yaml_parser_update_buffer(parser, peek+1) {
			break
		}
		column++
		if is_blank(parser.buffer, parser.buffer_pos+peek) {
			continue
		}
		c := parser.buffer[parser.buffer_pos+peek]
		var close_flow = parser.flow_level > 0 && (c == ']' || c == '}')
		if close_flow || is_breakz(parser.buffer, parser.buffer_pos+peek) {
			if close_flow || !recent_empty {
				if close_flow || first_empty && (start_mark.line == foot_line && token.typ != yaml_VALUE_TOKEN || start_mark.column-1 < next_indent) {
					if len(text) > 0 {
						if start_mark.column-1 < next_indent {
							token_mark = start_mark
						}
						parser.comments = append(parser.comments, yaml_comment_t{
							scan_mark:  scan_mark,
							token_mark: token_mark,
							start_mark: start_mark,
							end_mark:   yaml_mark_t{parser.mark.index + peek, line, column},
							foot:       text,
						})
						scan_mark = yaml_mark_t{parser.mark.index + peek, line, column}
						token_mark = scan_mark
						text = nil
					}
				} else {
					if len(text) > 0 && parser.buffer[parser.buffer_pos+peek] != 0 {
						text = append(text, '\n')
					}
				}
			}
			if !is_break(parser.buffer, parser.buffer_pos+peek) {
				break
			}
			first_empty = false
			recent_empty = true
			column = 0
			line++
			continue
		}

		if len(text) > 0 && (close_flow || column-1 < next_indent && column != start_mark.column) {
			parser.comments = append(parser.comments, yaml_comment_t{
				scan_mark:  scan_mark,
				token_mark: token_mark,
				start_mark: start_mark,
				end_mark:   yaml_mark_t{parser.mark.index + peek, line, column},
				foot:       text,
			})
			scan_mark = yaml_mark_t{parser.mark.index + peek, line, column}
			token_mark = scan_mark
			text = nil
		}

		if parser.buffer[parser.buffer_pos+peek] != '#' {
			break
		}

		if len(text) == 0 {
			start_mark = yaml_mark_t{parser.mark.index + peek, line, column}
		} else {
			text = append(text, '\n')
		}

		recent_empty = false

		seen := parser.mark.index + peek
		for {
			if parser.unread < 1 && !yaml_parser_update_buffer(parser, 1) {
				return false
			}
			if is_breakz(parser.buffer, parser.buffer_pos) {
				if parser.mark.index >= seen {
					break
				}
				if parser.unread < 2 && !yaml_parser_update_buffer(parser, 2) {
					return false
				}
				skip_line(parser)
			} else if parser.mark.index >= seen {
				text = read(parser, text)
			} else {
				skip(parser)
			}
		}

		peek = 0
		column = 0
		line = parser.mark.line
		next_indent = parser.indent
		if next_indent < 0 {
			next_indent = 0
		}
	}

	if len(text) > 0 {
		parser.comments = append(parser.comments, yaml_comment_t{
			scan_mark:  scan_mark,
			token_mark: start_mark,
			start_mark: start_mark,
			end_mark:   yaml_mark_t{parser.mark.index + peek - 1, line, column},
			head:       text,
		})
	}
	return true
}
