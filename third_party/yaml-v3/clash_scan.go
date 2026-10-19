package yaml


type ClashItemStyle int

const (
	ClashPlain ClashItemStyle = iota
	ClashSingleQuoted
	ClashDoubleQuoted
	ClashLiteral
	ClashFolded
)

type ClashItem struct {
	Value      []byte
	Start, End int
	Line       int
	Style      ClashItemStyle
}

type ClashSequenceScan struct {
	Found bool
	Flow  bool
	End   int
}

func ClashScanSequence(in []byte, key string, item func(ClashItem) bool) (scan ClashSequenceScan, ok bool) {
	if len(in) >= 3 && in[0] == 0xEF && in[1] == 0xBB && in[2] == 0xBF {
		return scan, false
	}
	var parser yaml_parser_t
	if !yaml_parser_initialize(&parser) {
		return scan, false
	}
	defer yaml_parser_delete(&parser)
	yaml_parser_set_input_string(&parser, in)

	bytes, chars := 0, 0
	at := func(char int) int {
		for chars < char && bytes < len(in) {
			c := in[bytes]
			switch {
			case c < 0x80:
				bytes++
			case c < 0xE0:
				bytes += 2
			case c < 0xF0:
				bytes += 3
			default:
				bytes += 4
			}
			chars++
		}
		return bytes
	}
	documents, depth, index := 0, 0, 0
	top, wantKey, inSequence, seen := false, false, false, false
	keys := map[string]bool{}
	for {
		var event yaml_event_t
		if !yaml_parser_parse(&parser, &event) || parser.error != yaml_NO_ERROR {
			return scan, false
		}
		typ := event.typ
		if typ == yaml_STREAM_START_EVENT && event.encoding != yaml_UTF8_ENCODING {
			yaml_event_delete(&event)
			return scan, false
		}
		anchored, tagged := len(event.anchor) > 0, len(event.tag) > 0
		switch {
		case inSequence:
			switch typ {
			case yaml_SEQUENCE_END_EVENT:
				if scan.Flow {
					scan.End = at(event.start_mark.index)
				}
				inSequence, wantKey = false, true
				yaml_event_delete(&event)
				continue
			case yaml_SCALAR_EVENT:
				if anchored || tagged {
					yaml_event_delete(&event)
					return scan, false
				}
				start := at(event.start_mark.index)
				end := at(event.end_mark.index)
				style := ClashPlain
				switch event.scalar_style() {
				case yaml_SINGLE_QUOTED_SCALAR_STYLE:
					style = ClashSingleQuoted
				case yaml_DOUBLE_QUOTED_SCALAR_STYLE:
					style = ClashDoubleQuoted
				case yaml_LITERAL_SCALAR_STYLE:
					style = ClashLiteral
				case yaml_FOLDED_SCALAR_STYLE:
					style = ClashFolded
				}
				if !scan.Flow {
					scan.End = end
				}
				more := item(ClashItem{Value: event.value, Start: start, End: end, Line: event.start_mark.line + 1, Style: style})
				index++
				yaml_event_delete(&event)
				if !more {
					return scan, true
				}
				continue
			default:
				yaml_event_delete(&event)
				return scan, false
			}
		case typ == yaml_STREAM_START_EVENT, typ == yaml_DOCUMENT_END_EVENT:
		case typ == yaml_DOCUMENT_START_EVENT:
			if documents++; documents > 1 {
				yaml_event_delete(&event)
				return scan, seen
			}
		case typ == yaml_STREAM_END_EVENT:
			yaml_event_delete(&event)
			return scan, true
		case !top:
			if typ != yaml_MAPPING_START_EVENT || event.mapping_style() != yaml_BLOCK_MAPPING_STYLE || anchored {
				yaml_event_delete(&event)
				return scan, false
			}
			top, wantKey = true, true
		case depth > 0:
			switch typ {
			case yaml_MAPPING_START_EVENT, yaml_SEQUENCE_START_EVENT:
				depth++
			case yaml_MAPPING_END_EVENT, yaml_SEQUENCE_END_EVENT:
				if depth--; depth == 0 {
					wantKey = true
				}
			}
		case wantKey:
			switch typ {
			case yaml_MAPPING_END_EVENT:
				yaml_event_delete(&event)
				return scan, true
			case yaml_SCALAR_EVENT:
			default:
				yaml_event_delete(&event)
				return scan, false
			}
			value := string(event.value)
			plain := event.scalar_style() == yaml_PLAIN_SCALAR_STYLE
			wantKey = false
			if keys[value] {
				yaml_event_delete(&event)
				return scan, false
			}
			keys[value] = true
			if value == key {
				if !plain || tagged || anchored || seen {
					yaml_event_delete(&event)
					return scan, false
				}
				seen = true
				yaml_event_delete(&event)
				var next yaml_event_t
				if !yaml_parser_parse(&parser, &next) || parser.error != yaml_NO_ERROR {
					return scan, false
				}
				switch next.typ {
				case yaml_SEQUENCE_START_EVENT:
					if len(next.anchor) > 0 || len(next.tag) > 0 {
						yaml_event_delete(&next)
						return scan, false
					}
					scan.Found, scan.Flow, inSequence = true, next.sequence_style() == yaml_FLOW_SEQUENCE_STYLE, true
				case yaml_MAPPING_START_EVENT:
					depth = 1
				case yaml_SCALAR_EVENT:
					wantKey = true
				default:
					yaml_event_delete(&next)
					return scan, false
				}
				yaml_event_delete(&next)
				continue
			}
		default:
			switch typ {
			case yaml_MAPPING_START_EVENT, yaml_SEQUENCE_START_EVENT:
				depth = 1
			default:
				wantKey = true
			}
		}
		yaml_event_delete(&event)
	}
}
