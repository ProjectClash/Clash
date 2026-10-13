package yaml


import (
	"errors"
	"reflect"
)

type ClashSequence struct {
	Key  string
	Item reflect.Type
}

func ClashUnmarshal(in []byte, out interface{}, s ClashSequence, read func(decode func(v interface{}) error)) error {
	node, err := clashParse(in, s)
	if errors.Is(err, errClashUnsafe) {
		node, err = clashParse(in, ClashSequence{})
	}
	if err != nil {
		return err
	}
	decode := func(v interface{}) error { return clashDecode(node, v) }
	if read != nil {
		read(decode)
	}
	return decode(out)
}

var errClashUnsafe = errors.New("yaml: the sequence cannot be decoded item by item")

type clashAbort struct{}

func clashParse(in []byte, s ClashSequence) (node *Node, err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(clashAbort); ok {
				node, err = nil, errClashUnsafe
				return
			}
			if e, ok := r.(yamlError); ok {
				node, err = nil, e.err
				return
			}
			panic(r)
		}
	}()
	p := newParser(in)
	defer p.destroy()
	if s.Key != "" {
		p.clash = &clashStreamState{sequence: s, decoder: newDecoder()}
	}
	return p.parse(), nil
}

func clashDecode(node *Node, v interface{}) (err error) {
	defer handleErr(&err)
	d := newDecoder()
	if node != nil {
		out := reflect.ValueOf(v)
		if out.Kind() == reflect.Ptr && !out.IsNil() {
			out = out.Elem()
		}
		d.unmarshal(node, out)
	}
	if len(d.terrors) > 0 {
		return &TypeError{d.terrors}
	}
	return nil
}

type clashStreamState struct {
	sequence ClashSequence
	decoder  *decoder
	rootNext bool
	done     bool
	aliases  int
}

type clashSequence struct {
	item    reflect.Type
	items   reflect.Value
	decodes []int32
}

func (p *parser) clashDocument() {
	if p.clash != nil {
		p.clash.rootNext = p.peek() == yaml_MAPPING_START_EVENT && len(p.event.anchor) == 0
	}
}

func (p *parser) clashRoot() bool {
	if p.clash == nil || !p.clash.rootNext {
		return false
	}
	p.clash.rootNext = false
	return true
}

func (p *parser) clashChild(n, k *Node, root bool) *Node {
	c := p.clash
	if !root || c.done || k.Kind != ScalarNode || k.ShortTag() != strTag || k.Value != c.sequence.Key {
		return p.parseChild(n)
	}
	if p.peek() != yaml_SEQUENCE_START_EVENT || len(p.event.anchor) != 0 || len(p.event.tag) != 0 {
		return p.parseChild(n)
	}
	c.done = true
	seq := p.node(SequenceNode, seqTag, string(p.event.tag), "")
	if p.event.sequence_style()&yaml_FLOW_SEQUENCE_STYLE != 0 {
		seq.Style |= FlowStyle
	}
	p.expect(yaml_SEQUENCE_START_EVENT)
	streamed := &clashSequence{item: c.sequence.Item, items: reflect.MakeSlice(reflect.SliceOf(c.sequence.Item), 0, 64)}
	for p.peek() != yaml_SEQUENCE_END_EVENT {
		aliases := c.aliases
		item := p.parse()
		if c.aliases != aliases {
			panic(clashAbort{})
		}
		streamed.items = reflect.Append(streamed.items, c.decodeItem(item, streamed))
	}
	seq.LineComment = string(p.event.line_comment)
	seq.FootComment = string(p.event.foot_comment)
	p.expect(yaml_SEQUENCE_END_EVENT)
	seq.clash = streamed
	n.Content = append(n.Content, seq)
	return seq
}

func (c *clashStreamState) decodeItem(item *Node, streamed *clashSequence) (value reflect.Value) {
	if item.Kind != MappingNode || !isStringMap(item) {
		panic(clashAbort{})
	}
	d := c.decoder
	before := d.decodeCount
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(yamlError); ok {
				panic(clashAbort{})
			}
			panic(r)
		}
	}()
	value = reflect.New(c.sequence.Item).Elem()
	if !d.unmarshal(item, value) || len(d.terrors) != 0 {
		panic(clashAbort{})
	}
	streamed.decodes = append(streamed.decodes, int32(d.decodeCount-before))
	return value
}

func (d *decoder) clashStreamed(n *Node, out reflect.Value) (good bool) {
	s := n.clash
	if out.Type() == nodeType {
		failf("the sequence at line %d was decoded item by item and cannot be decoded into a Node", n.Line)
	}
	for {
		if out.CanAddr() {
			switch out.Addr().Interface().(type) {
			case Unmarshaler, obsoleteUnmarshaler:
				failf("the sequence at line %d was decoded item by item and cannot be handed to %s", n.Line, out.Addr().Type())
			}
		}
		if out.Kind() != reflect.Ptr {
			break
		}
		if out.IsNil() {
			out.Set(reflect.New(out.Type().Elem()))
		}
		out = out.Elem()
	}
	l := s.items.Len()
	handed := (out.Kind() == reflect.Slice || out.Kind() == reflect.Array || out.Kind() == reflect.Interface)
	if handed && (d.stringMapType != stringMapType || d.generalMapType != generalMapType) {
		failf("the sequence at line %d was decoded item by item and cannot be decoded where maps decode as %s and %s", n.Line, d.stringMapType, d.generalMapType)
	}
	var iface reflect.Value
	switch {
	case out.Kind() == reflect.Slice && out.Type().Elem() == s.item:
		out.Set(reflect.MakeSlice(out.Type(), l, l))
	case out.Kind() == reflect.Array && out.Type().Elem() == s.item:
		if l != out.Len() {
			failf("invalid array: want %d elements but got %d", out.Len(), l)
		}
	case out.Kind() == reflect.Interface && out.NumMethod() == 0 && s.item == stringMapType:
		iface = out
		out = settableValueOf(make([]interface{}, l))
	case handed:
		failf("the sequence at line %d was decoded item by item into %s and cannot be decoded into %s", n.Line, s.item, out.Type())
	default:
		d.terror(n, seqTag, out)
		return false
	}
	for i := 0; i < l; i++ {
		for k := int32(0); k < s.decodes[i]; k++ {
			d.decodeCount++
			if d.aliasDepth > 0 {
				d.aliasCount++
			}
			if d.aliasCount > 100 && d.decodeCount > 1000 && float64(d.aliasCount)/float64(d.decodeCount) > allowedAliasRatio(d.decodeCount) {
				failf("document contains excessive aliasing")
			}
		}
		out.Index(i).Set(s.items.Index(i))
	}
	if iface.IsValid() {
		iface.Set(out)
	}
	return true
}

func ClashParseDocument(in []byte, s ClashSequence) (*Node, error) {
	node, err := clashParse(in, s)
	if errors.Is(err, errClashUnsafe) {
		node, err = clashParse(in, ClashSequence{})
	}
	return node, err
}
