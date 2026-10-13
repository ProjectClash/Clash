package yaml


type ClashSection struct {
	Key      string
	Start    int
	Anchored bool
	Aliased  bool
}

func ClashTopLevelSections(in []byte) (sections []ClashSection, ok bool) {
	if len(in) >= 3 && in[0] == 0xEF && in[1] == 0xBB && in[2] == 0xBF {
		return nil, false
	}
	var parser yaml_parser_t
	if !yaml_parser_initialize(&parser) {
		return nil, false
	}
	defer yaml_parser_delete(&parser)
	yaml_parser_set_input_string(&parser, in)

	var starts []int
	seen := map[string]bool{}
	documents, depth, keyColumn := 0, 0, 0
	top, topDone, wantKey := false, false, false
	for {
		var event yaml_event_t
		if !yaml_parser_parse(&parser, &event) || parser.error != yaml_NO_ERROR {
			return nil, false
		}
		typ, anchored, at, column := event.typ, len(event.anchor) > 0, event.start_mark.index, event.start_mark.column
		var key, tag string
		plain := false
		if typ == yaml_SCALAR_EVENT {
			key, tag, plain = string(event.value), string(event.tag), event.scalar_style() == yaml_PLAIN_SCALAR_STYLE
		}
		if typ == yaml_STREAM_START_EVENT && event.encoding != yaml_UTF8_ENCODING {
			yaml_event_delete(&event)
			return nil, false
		}
		blockMapping := event.mapping_style() == yaml_BLOCK_MAPPING_STYLE
		yaml_event_delete(&event)

		inValue := top && depth > 0
		switch typ {
		case yaml_STREAM_START_EVENT, yaml_DOCUMENT_END_EVENT:
		case yaml_DOCUMENT_START_EVENT:
			if documents++; documents > 1 {
				return nil, false
			}
		case yaml_STREAM_END_EVENT:
			if !topDone {
				return nil, false
			}
			return clashSectionBytes(in, sections, starts)
		case yaml_MAPPING_START_EVENT, yaml_SEQUENCE_START_EVENT:
			switch {
			case !top && !topDone:
				if typ != yaml_MAPPING_START_EVENT || !blockMapping || anchored {
					return nil, false
				}
				top, wantKey, keyColumn = true, true, column
			case topDone || wantKey && depth == 0:
				return nil, false
			default:
				if anchored {
					sections[len(sections)-1].Anchored = true
				}
				depth++
			}
		case yaml_MAPPING_END_EVENT, yaml_SEQUENCE_END_EVENT:
			switch {
			case inValue:
				if depth--; depth == 0 {
					wantKey = true
				}
			case top:
				top, topDone = false, true
			default:
				return nil, false
			}
		case yaml_SCALAR_EVENT:
			switch {
			case !top:
				return nil, false
			case inValue:
				if anchored {
					sections[len(sections)-1].Anchored = true
				}
			case wantKey:
				if key == "<<" || shortTag(tag) == mergeTag {
					return nil, false
				}
				if column != keyColumn {
					return nil, false
				}
				if tag != "" && shortTag(tag) != strTag {
					return nil, false
				}
				if tag == "" && plain {
					if rtag, _ := resolve("", key); rtag != strTag {
						return nil, false
					}
				}
				if seen[key] {
					return nil, false
				}
				seen[key] = true
				sections = append(sections, ClashSection{Key: key, Anchored: anchored})
				starts = append(starts, at)
				wantKey = false
			default:
				if anchored {
					sections[len(sections)-1].Anchored = true
				}
				wantKey = true
			}
		case yaml_ALIAS_EVENT:
			switch {
			case !top || !inValue && wantKey:
				return nil, false
			case !inValue:
				wantKey = true
			}
			sections[len(sections)-1].Aliased = true
		default:
			return nil, false
		}
	}
}

func clashSectionBytes(in []byte, sections []ClashSection, starts []int) ([]ClashSection, bool) {
	if len(sections) == 0 {
		return nil, false
	}
	k, chars := 0, 0
	for offset := range string(in) {
		for k < len(starts) && starts[k] == chars {
			sections[k].Start = offset
			k++
		}
		chars++
	}
	if k != len(starts) {
		return nil, false
	}
	for _, section := range sections {
		for i := section.Start - 1; i >= 0 && in[i] != '\n' && in[i] != '\r'; i-- {
			if in[i] != ' ' && in[i] != '\t' {
				return nil, false
			}
		}
	}
	return sections, true
}
