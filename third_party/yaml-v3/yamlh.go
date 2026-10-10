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
	"fmt"
	"io"
)

type yaml_version_directive_t struct {
	major int8
	minor int8
}

type yaml_tag_directive_t struct {
	handle []byte
	prefix []byte
}

type yaml_encoding_t int

const (
	yaml_ANY_ENCODING yaml_encoding_t = iota

	yaml_UTF8_ENCODING
	yaml_UTF16LE_ENCODING
	yaml_UTF16BE_ENCODING
)

type yaml_break_t int

const (
	yaml_ANY_BREAK yaml_break_t = iota

	yaml_CR_BREAK
	yaml_LN_BREAK
	yaml_CRLN_BREAK
)

type yaml_error_type_t int

const (
	yaml_NO_ERROR yaml_error_type_t = iota

	yaml_MEMORY_ERROR
	yaml_READER_ERROR
	yaml_SCANNER_ERROR
	yaml_PARSER_ERROR
	yaml_COMPOSER_ERROR
	yaml_WRITER_ERROR
	yaml_EMITTER_ERROR
)

type yaml_mark_t struct {
	index  int
	line   int
	column int
}


type yaml_style_t int8

type yaml_scalar_style_t yaml_style_t

const (
	yaml_ANY_SCALAR_STYLE yaml_scalar_style_t = 0

	yaml_PLAIN_SCALAR_STYLE         yaml_scalar_style_t = 1 << iota
	yaml_SINGLE_QUOTED_SCALAR_STYLE
	yaml_DOUBLE_QUOTED_SCALAR_STYLE
	yaml_LITERAL_SCALAR_STYLE
	yaml_FOLDED_SCALAR_STYLE
)

type yaml_sequence_style_t yaml_style_t

const (
	yaml_ANY_SEQUENCE_STYLE yaml_sequence_style_t = iota

	yaml_BLOCK_SEQUENCE_STYLE
	yaml_FLOW_SEQUENCE_STYLE
)

type yaml_mapping_style_t yaml_style_t

const (
	yaml_ANY_MAPPING_STYLE yaml_mapping_style_t = iota

	yaml_BLOCK_MAPPING_STYLE
	yaml_FLOW_MAPPING_STYLE
)


type yaml_token_type_t int

const (
	yaml_NO_TOKEN yaml_token_type_t = iota

	yaml_STREAM_START_TOKEN
	yaml_STREAM_END_TOKEN

	yaml_VERSION_DIRECTIVE_TOKEN
	yaml_TAG_DIRECTIVE_TOKEN
	yaml_DOCUMENT_START_TOKEN
	yaml_DOCUMENT_END_TOKEN

	yaml_BLOCK_SEQUENCE_START_TOKEN
	yaml_BLOCK_MAPPING_START_TOKEN
	yaml_BLOCK_END_TOKEN

	yaml_FLOW_SEQUENCE_START_TOKEN
	yaml_FLOW_SEQUENCE_END_TOKEN
	yaml_FLOW_MAPPING_START_TOKEN
	yaml_FLOW_MAPPING_END_TOKEN

	yaml_BLOCK_ENTRY_TOKEN
	yaml_FLOW_ENTRY_TOKEN
	yaml_KEY_TOKEN
	yaml_VALUE_TOKEN

	yaml_ALIAS_TOKEN
	yaml_ANCHOR_TOKEN
	yaml_TAG_TOKEN
	yaml_SCALAR_TOKEN
)

func (tt yaml_token_type_t) String() string {
	switch tt {
	case yaml_NO_TOKEN:
		return "yaml_NO_TOKEN"
	case yaml_STREAM_START_TOKEN:
		return "yaml_STREAM_START_TOKEN"
	case yaml_STREAM_END_TOKEN:
		return "yaml_STREAM_END_TOKEN"
	case yaml_VERSION_DIRECTIVE_TOKEN:
		return "yaml_VERSION_DIRECTIVE_TOKEN"
	case yaml_TAG_DIRECTIVE_TOKEN:
		return "yaml_TAG_DIRECTIVE_TOKEN"
	case yaml_DOCUMENT_START_TOKEN:
		return "yaml_DOCUMENT_START_TOKEN"
	case yaml_DOCUMENT_END_TOKEN:
		return "yaml_DOCUMENT_END_TOKEN"
	case yaml_BLOCK_SEQUENCE_START_TOKEN:
		return "yaml_BLOCK_SEQUENCE_START_TOKEN"
	case yaml_BLOCK_MAPPING_START_TOKEN:
		return "yaml_BLOCK_MAPPING_START_TOKEN"
	case yaml_BLOCK_END_TOKEN:
		return "yaml_BLOCK_END_TOKEN"
	case yaml_FLOW_SEQUENCE_START_TOKEN:
		return "yaml_FLOW_SEQUENCE_START_TOKEN"
	case yaml_FLOW_SEQUENCE_END_TOKEN:
		return "yaml_FLOW_SEQUENCE_END_TOKEN"
	case yaml_FLOW_MAPPING_START_TOKEN:
		return "yaml_FLOW_MAPPING_START_TOKEN"
	case yaml_FLOW_MAPPING_END_TOKEN:
		return "yaml_FLOW_MAPPING_END_TOKEN"
	case yaml_BLOCK_ENTRY_TOKEN:
		return "yaml_BLOCK_ENTRY_TOKEN"
	case yaml_FLOW_ENTRY_TOKEN:
		return "yaml_FLOW_ENTRY_TOKEN"
	case yaml_KEY_TOKEN:
		return "yaml_KEY_TOKEN"
	case yaml_VALUE_TOKEN:
		return "yaml_VALUE_TOKEN"
	case yaml_ALIAS_TOKEN:
		return "yaml_ALIAS_TOKEN"
	case yaml_ANCHOR_TOKEN:
		return "yaml_ANCHOR_TOKEN"
	case yaml_TAG_TOKEN:
		return "yaml_TAG_TOKEN"
	case yaml_SCALAR_TOKEN:
		return "yaml_SCALAR_TOKEN"
	}
	return "<unknown token>"
}

type yaml_token_t struct {
	typ yaml_token_type_t

	start_mark, end_mark yaml_mark_t

	encoding yaml_encoding_t

	value []byte

	suffix []byte

	prefix []byte

	style yaml_scalar_style_t

	major, minor int8
}


type yaml_event_type_t int8

const (
	yaml_NO_EVENT yaml_event_type_t = iota

	yaml_STREAM_START_EVENT
	yaml_STREAM_END_EVENT
	yaml_DOCUMENT_START_EVENT
	yaml_DOCUMENT_END_EVENT
	yaml_ALIAS_EVENT
	yaml_SCALAR_EVENT
	yaml_SEQUENCE_START_EVENT
	yaml_SEQUENCE_END_EVENT
	yaml_MAPPING_START_EVENT
	yaml_MAPPING_END_EVENT
	yaml_TAIL_COMMENT_EVENT
)

var eventStrings = []string{
	yaml_NO_EVENT:             "none",
	yaml_STREAM_START_EVENT:   "stream start",
	yaml_STREAM_END_EVENT:     "stream end",
	yaml_DOCUMENT_START_EVENT: "document start",
	yaml_DOCUMENT_END_EVENT:   "document end",
	yaml_ALIAS_EVENT:          "alias",
	yaml_SCALAR_EVENT:         "scalar",
	yaml_SEQUENCE_START_EVENT: "sequence start",
	yaml_SEQUENCE_END_EVENT:   "sequence end",
	yaml_MAPPING_START_EVENT:  "mapping start",
	yaml_MAPPING_END_EVENT:    "mapping end",
	yaml_TAIL_COMMENT_EVENT:   "tail comment",
}

func (e yaml_event_type_t) String() string {
	if e < 0 || int(e) >= len(eventStrings) {
		return fmt.Sprintf("unknown event %d", e)
	}
	return eventStrings[e]
}

type yaml_event_t struct {

	typ yaml_event_type_t

	start_mark, end_mark yaml_mark_t

	encoding yaml_encoding_t

	version_directive *yaml_version_directive_t

	tag_directives []yaml_tag_directive_t

	head_comment []byte
	line_comment []byte
	foot_comment []byte
	tail_comment []byte

	anchor []byte

	tag []byte

	value []byte

	implicit bool

	quoted_implicit bool

	style yaml_style_t
}

func (e *yaml_event_t) scalar_style() yaml_scalar_style_t     { return yaml_scalar_style_t(e.style) }
func (e *yaml_event_t) sequence_style() yaml_sequence_style_t { return yaml_sequence_style_t(e.style) }
func (e *yaml_event_t) mapping_style() yaml_mapping_style_t   { return yaml_mapping_style_t(e.style) }


const (
	yaml_NULL_TAG      = "tag:yaml.org,2002:null"
	yaml_BOOL_TAG      = "tag:yaml.org,2002:bool"
	yaml_STR_TAG       = "tag:yaml.org,2002:str"
	yaml_INT_TAG       = "tag:yaml.org,2002:int"
	yaml_FLOAT_TAG     = "tag:yaml.org,2002:float"
	yaml_TIMESTAMP_TAG = "tag:yaml.org,2002:timestamp"

	yaml_SEQ_TAG = "tag:yaml.org,2002:seq"
	yaml_MAP_TAG = "tag:yaml.org,2002:map"

	yaml_BINARY_TAG = "tag:yaml.org,2002:binary"
	yaml_MERGE_TAG  = "tag:yaml.org,2002:merge"

	yaml_DEFAULT_SCALAR_TAG   = yaml_STR_TAG
	yaml_DEFAULT_SEQUENCE_TAG = yaml_SEQ_TAG
	yaml_DEFAULT_MAPPING_TAG  = yaml_MAP_TAG
)

type yaml_node_type_t int

const (
	yaml_NO_NODE yaml_node_type_t = iota

	yaml_SCALAR_NODE
	yaml_SEQUENCE_NODE
	yaml_MAPPING_NODE
)

type yaml_node_item_t int

type yaml_node_pair_t struct {
	key   int
	value int
}

type yaml_node_t struct {
	typ yaml_node_type_t
	tag []byte


	scalar struct {
		value  []byte
		length int
		style  yaml_scalar_style_t
	}

	sequence struct {
		items_data []yaml_node_item_t
		style      yaml_sequence_style_t
	}

	mapping struct {
		pairs_data  []yaml_node_pair_t
		pairs_start *yaml_node_pair_t
		pairs_end   *yaml_node_pair_t
		pairs_top   *yaml_node_pair_t
		style       yaml_mapping_style_t
	}

	start_mark yaml_mark_t
	end_mark   yaml_mark_t

}

type yaml_document_t struct {

	nodes []yaml_node_t

	version_directive *yaml_version_directive_t

	tag_directives_data  []yaml_tag_directive_t
	tag_directives_start int
	tag_directives_end   int

	start_implicit int
	end_implicit   int

	start_mark, end_mark yaml_mark_t
}

type yaml_read_handler_t func(parser *yaml_parser_t, buffer []byte) (n int, err error)

type yaml_simple_key_t struct {
	possible     bool
	required     bool
	token_number int
	mark         yaml_mark_t
}

type yaml_parser_state_t int

const (
	yaml_PARSE_STREAM_START_STATE yaml_parser_state_t = iota

	yaml_PARSE_IMPLICIT_DOCUMENT_START_STATE
	yaml_PARSE_DOCUMENT_START_STATE
	yaml_PARSE_DOCUMENT_CONTENT_STATE
	yaml_PARSE_DOCUMENT_END_STATE
	yaml_PARSE_BLOCK_NODE_STATE
	yaml_PARSE_BLOCK_NODE_OR_INDENTLESS_SEQUENCE_STATE
	yaml_PARSE_FLOW_NODE_STATE
	yaml_PARSE_BLOCK_SEQUENCE_FIRST_ENTRY_STATE
	yaml_PARSE_BLOCK_SEQUENCE_ENTRY_STATE
	yaml_PARSE_INDENTLESS_SEQUENCE_ENTRY_STATE
	yaml_PARSE_BLOCK_MAPPING_FIRST_KEY_STATE
	yaml_PARSE_BLOCK_MAPPING_KEY_STATE
	yaml_PARSE_BLOCK_MAPPING_VALUE_STATE
	yaml_PARSE_FLOW_SEQUENCE_FIRST_ENTRY_STATE
	yaml_PARSE_FLOW_SEQUENCE_ENTRY_STATE
	yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_KEY_STATE
	yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_VALUE_STATE
	yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_END_STATE
	yaml_PARSE_FLOW_MAPPING_FIRST_KEY_STATE
	yaml_PARSE_FLOW_MAPPING_KEY_STATE
	yaml_PARSE_FLOW_MAPPING_VALUE_STATE
	yaml_PARSE_FLOW_MAPPING_EMPTY_VALUE_STATE
	yaml_PARSE_END_STATE
)

func (ps yaml_parser_state_t) String() string {
	switch ps {
	case yaml_PARSE_STREAM_START_STATE:
		return "yaml_PARSE_STREAM_START_STATE"
	case yaml_PARSE_IMPLICIT_DOCUMENT_START_STATE:
		return "yaml_PARSE_IMPLICIT_DOCUMENT_START_STATE"
	case yaml_PARSE_DOCUMENT_START_STATE:
		return "yaml_PARSE_DOCUMENT_START_STATE"
	case yaml_PARSE_DOCUMENT_CONTENT_STATE:
		return "yaml_PARSE_DOCUMENT_CONTENT_STATE"
	case yaml_PARSE_DOCUMENT_END_STATE:
		return "yaml_PARSE_DOCUMENT_END_STATE"
	case yaml_PARSE_BLOCK_NODE_STATE:
		return "yaml_PARSE_BLOCK_NODE_STATE"
	case yaml_PARSE_BLOCK_NODE_OR_INDENTLESS_SEQUENCE_STATE:
		return "yaml_PARSE_BLOCK_NODE_OR_INDENTLESS_SEQUENCE_STATE"
	case yaml_PARSE_FLOW_NODE_STATE:
		return "yaml_PARSE_FLOW_NODE_STATE"
	case yaml_PARSE_BLOCK_SEQUENCE_FIRST_ENTRY_STATE:
		return "yaml_PARSE_BLOCK_SEQUENCE_FIRST_ENTRY_STATE"
	case yaml_PARSE_BLOCK_SEQUENCE_ENTRY_STATE:
		return "yaml_PARSE_BLOCK_SEQUENCE_ENTRY_STATE"
	case yaml_PARSE_INDENTLESS_SEQUENCE_ENTRY_STATE:
		return "yaml_PARSE_INDENTLESS_SEQUENCE_ENTRY_STATE"
	case yaml_PARSE_BLOCK_MAPPING_FIRST_KEY_STATE:
		return "yaml_PARSE_BLOCK_MAPPING_FIRST_KEY_STATE"
	case yaml_PARSE_BLOCK_MAPPING_KEY_STATE:
		return "yaml_PARSE_BLOCK_MAPPING_KEY_STATE"
	case yaml_PARSE_BLOCK_MAPPING_VALUE_STATE:
		return "yaml_PARSE_BLOCK_MAPPING_VALUE_STATE"
	case yaml_PARSE_FLOW_SEQUENCE_FIRST_ENTRY_STATE:
		return "yaml_PARSE_FLOW_SEQUENCE_FIRST_ENTRY_STATE"
	case yaml_PARSE_FLOW_SEQUENCE_ENTRY_STATE:
		return "yaml_PARSE_FLOW_SEQUENCE_ENTRY_STATE"
	case yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_KEY_STATE:
		return "yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_KEY_STATE"
	case yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_VALUE_STATE:
		return "yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_VALUE_STATE"
	case yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_END_STATE:
		return "yaml_PARSE_FLOW_SEQUENCE_ENTRY_MAPPING_END_STATE"
	case yaml_PARSE_FLOW_MAPPING_FIRST_KEY_STATE:
		return "yaml_PARSE_FLOW_MAPPING_FIRST_KEY_STATE"
	case yaml_PARSE_FLOW_MAPPING_KEY_STATE:
		return "yaml_PARSE_FLOW_MAPPING_KEY_STATE"
	case yaml_PARSE_FLOW_MAPPING_VALUE_STATE:
		return "yaml_PARSE_FLOW_MAPPING_VALUE_STATE"
	case yaml_PARSE_FLOW_MAPPING_EMPTY_VALUE_STATE:
		return "yaml_PARSE_FLOW_MAPPING_EMPTY_VALUE_STATE"
	case yaml_PARSE_END_STATE:
		return "yaml_PARSE_END_STATE"
	}
	return "<unknown parser state>"
}

type yaml_alias_data_t struct {
	anchor []byte
	index  int
	mark   yaml_mark_t
}

type yaml_parser_t struct {


	error yaml_error_type_t

	problem string

	problem_offset int
	problem_value  int
	problem_mark   yaml_mark_t

	context      string
	context_mark yaml_mark_t


	read_handler yaml_read_handler_t

	input_reader io.Reader
	input        []byte
	input_pos    int

	eof bool

	buffer     []byte
	buffer_pos int

	unread int

	newlines int

	raw_buffer     []byte
	raw_buffer_pos int

	encoding yaml_encoding_t

	offset int
	mark   yaml_mark_t


	head_comment []byte
	line_comment []byte
	foot_comment []byte
	tail_comment []byte
	stem_comment []byte

	comments      []yaml_comment_t
	comments_head int


	stream_start_produced bool
	stream_end_produced   bool

	flow_level int

	tokens          []yaml_token_t
	tokens_head     int
	tokens_parsed   int
	token_available bool

	indent  int
	indents []int

	simple_key_allowed bool
	simple_keys        []yaml_simple_key_t
	simple_keys_by_tok map[int]int


	state          yaml_parser_state_t
	states         []yaml_parser_state_t
	marks          []yaml_mark_t
	tag_directives []yaml_tag_directive_t


	aliases []yaml_alias_data_t

	document *yaml_document_t
}

type yaml_comment_t struct {
	scan_mark  yaml_mark_t
	token_mark yaml_mark_t
	start_mark yaml_mark_t
	end_mark   yaml_mark_t

	head []byte
	line []byte
	foot []byte
}


type yaml_write_handler_t func(emitter *yaml_emitter_t, buffer []byte) error

type yaml_emitter_state_t int

const (
	yaml_EMIT_STREAM_START_STATE yaml_emitter_state_t = iota

	yaml_EMIT_FIRST_DOCUMENT_START_STATE
	yaml_EMIT_DOCUMENT_START_STATE
	yaml_EMIT_DOCUMENT_CONTENT_STATE
	yaml_EMIT_DOCUMENT_END_STATE
	yaml_EMIT_FLOW_SEQUENCE_FIRST_ITEM_STATE
	yaml_EMIT_FLOW_SEQUENCE_TRAIL_ITEM_STATE
	yaml_EMIT_FLOW_SEQUENCE_ITEM_STATE
	yaml_EMIT_FLOW_MAPPING_FIRST_KEY_STATE
	yaml_EMIT_FLOW_MAPPING_TRAIL_KEY_STATE
	yaml_EMIT_FLOW_MAPPING_KEY_STATE
	yaml_EMIT_FLOW_MAPPING_SIMPLE_VALUE_STATE
	yaml_EMIT_FLOW_MAPPING_VALUE_STATE
	yaml_EMIT_BLOCK_SEQUENCE_FIRST_ITEM_STATE
	yaml_EMIT_BLOCK_SEQUENCE_ITEM_STATE
	yaml_EMIT_BLOCK_MAPPING_FIRST_KEY_STATE
	yaml_EMIT_BLOCK_MAPPING_KEY_STATE
	yaml_EMIT_BLOCK_MAPPING_SIMPLE_VALUE_STATE
	yaml_EMIT_BLOCK_MAPPING_VALUE_STATE
	yaml_EMIT_END_STATE
)

type yaml_emitter_t struct {


	error   yaml_error_type_t
	problem string


	write_handler yaml_write_handler_t

	output_buffer *[]byte
	output_writer io.Writer

	buffer     []byte
	buffer_pos int

	raw_buffer     []byte
	raw_buffer_pos int

	encoding yaml_encoding_t


	canonical   bool
	best_indent int
	best_width  int
	unicode     bool
	line_break  yaml_break_t

	state  yaml_emitter_state_t
	states []yaml_emitter_state_t

	events      []yaml_event_t
	events_head int

	indents []int

	tag_directives []yaml_tag_directive_t

	indent int

	compact_sequence_indent bool

	flow_level int

	root_context       bool
	sequence_context   bool
	mapping_context    bool
	simple_key_context bool

	line       int
	column     int
	whitespace bool
	indention  bool
	open_ended bool

	space_above bool
	foot_indent int

	anchor_data struct {
		anchor []byte
		alias  bool
	}

	tag_data struct {
		handle []byte
		suffix []byte
	}

	scalar_data struct {
		value                 []byte
		multiline             bool
		flow_plain_allowed    bool
		block_plain_allowed   bool
		single_quoted_allowed bool
		block_allowed         bool
		style                 yaml_scalar_style_t
	}

	head_comment []byte
	line_comment []byte
	foot_comment []byte
	tail_comment []byte

	key_line_comment []byte


	opened bool
	closed bool

	anchors *struct {
		references int
		anchor     int
		serialized bool
	}

	last_anchor_id int

	document *yaml_document_t
}
