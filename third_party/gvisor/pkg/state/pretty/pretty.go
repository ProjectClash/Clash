// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pretty

import (
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/metacubex/gvisor/pkg/state"
	"github.com/metacubex/gvisor/pkg/state/wire"
)

type printer struct {
	html      bool
	typeSpecs map[string]*wire.Type
}

func (p *printer) formatRef(x *wire.Ref, graph uint64) string {
	baseRef := fmt.Sprintf("g%dr%d", graph, x.Root)
	fullRef := baseRef
	if len(x.Dots) > 0 {
		typ, _ := p.formatType(x.Type, graph)
		var buf strings.Builder
		buf.WriteString("(*")
		buf.WriteString(typ)
		buf.WriteString(")(")
		buf.WriteString(baseRef)
		buf.WriteString(")")
		for _, component := range x.Dots {
			switch v := component.(type) {
			case *wire.FieldName:
				buf.WriteString(".")
				buf.WriteString(string(*v))
			case wire.Index:
				fmt.Fprintf(&buf, "[%d]", v)
			default:
				panic(fmt.Sprintf("unreachable: switch should be exhaustive, unhandled case %v", reflect.TypeOf(component)))
			}
		}
		fullRef = buf.String()
	}
	if p.html {
		return fmt.Sprintf("<a href=\"#%s\">%s</a>", baseRef, fullRef)
	}
	return fullRef
}

func (p *printer) formatType(t wire.TypeSpec, graph uint64) (string, bool) {
	switch x := t.(type) {
	case wire.TypeID:
		tag := fmt.Sprintf("g%dt%d", graph, x)
		desc := tag
		if spec, ok := p.typeSpecs[tag]; ok {
			desc += fmt.Sprintf("=%s", spec.Name)
		} else {
			desc += "!missing-type-spec"
		}
		if p.html {
			return fmt.Sprintf("<a href=\"#%s\">%s</a>", tag, desc), true
		}
		return desc, true
	case wire.TypeSpecNil:
		return "", false
	case *wire.TypeSpecPointer:
		element, _ := p.formatType(x.Type, graph)
		return fmt.Sprintf("(*%s)", element), true
	case *wire.TypeSpecArray:
		element, _ := p.formatType(x.Type, graph)
		return fmt.Sprintf("[%d](%s)", x.Count, element), true
	case *wire.TypeSpecSlice:
		element, _ := p.formatType(x.Type, graph)
		return fmt.Sprintf("([]%s)", element), true
	case *wire.TypeSpecMap:
		key, _ := p.formatType(x.Key, graph)
		value, _ := p.formatType(x.Value, graph)
		return fmt.Sprintf("(map[%s]%s)", key, value), true
	default:
		panic(fmt.Sprintf("unreachable: unknown type %T", t))
	}
}

func (p *printer) format(graph uint64, depth int, encoded wire.Object) (string, bool) {
	switch x := encoded.(type) {
	case wire.Nil:
		return "nil", false
	case *wire.String:
		return fmt.Sprintf("%q", *x), *x != ""
	case *wire.Complex64:
		return fmt.Sprintf("%f+%fi", real(*x), imag(*x)), *x != 0.0
	case *wire.Complex128:
		return fmt.Sprintf("%f+%fi", real(*x), imag(*x)), *x != 0.0
	case *wire.Ref:
		return p.formatRef(x, graph), x.Root != 0
	case *wire.Type:
		tabs := "\n" + strings.Repeat("\t", depth)
		items := make([]string, 0, len(x.Fields)+2)
		items = append(items, fmt.Sprintf("type %s {", x.Name))
		for i := 0; i < len(x.Fields); i++ {
			items = append(items, fmt.Sprintf("\t%d: %s,", i, x.Fields[i]))
		}
		items = append(items, "}")
		return strings.Join(items, tabs), true
	case *wire.Slice:
		return fmt.Sprintf("%s{len:%d,cap:%d}", p.formatRef(&x.Ref, graph), x.Length, x.Capacity), x.Capacity != 0
	case *wire.Array:
		if len(x.Contents) == 0 {
			return "[]", false
		}
		items := make([]string, 0, len(x.Contents)+2)
		zeros := make([]string, 0)
		items = append(items, "[")
		tabs := "\n" + strings.Repeat("\t", depth)
		for i := 0; i < len(x.Contents); i++ {
			item, ok := p.format(graph, depth+1, x.Contents[i])
			if !ok {
				zeros = append(zeros, fmt.Sprintf("\t%s,", item))
				continue
			}
			if len(zeros) > 0 {
				items = append(items, zeros...)
				zeros = nil
			}
			items = append(items, fmt.Sprintf("\t%s,", item))
		}
		if len(zeros) > 0 {
			items = append(items, fmt.Sprintf("\t... (%d zeros),", len(zeros)))
		}
		items = append(items, "]")
		return strings.Join(items, tabs), len(zeros) < len(x.Contents)
	case *wire.Struct:
		tag := fmt.Sprintf("g%dt%d", graph, x.TypeID)
		spec := p.typeSpecs[tag]
		typ, _ := p.formatType(x.TypeID, graph)
		if x.Fields() == 0 {
			return fmt.Sprintf("struct[%s]{}", typ), false
		}
		items := make([]string, 0, 2)
		items = append(items, fmt.Sprintf("struct[%s]{", typ))
		tabs := "\n" + strings.Repeat("\t", depth)
		allZero := true
		for i := 0; i < x.Fields(); i++ {
			var name string
			if spec != nil && i < len(spec.Fields) {
				name = spec.Fields[i]
			} else {
				name = fmt.Sprintf("%d", i)
			}
			element, ok := p.format(graph, depth+1, *x.Field(i))
			allZero = allZero && !ok
			items = append(items, fmt.Sprintf("\t%s: %s,", name, element))
		}
		items = append(items, "}")
		return strings.Join(items, tabs), !allZero
	case *wire.Map:
		if len(x.Keys) == 0 {
			return "map{}", false
		}
		items := make([]string, 0, len(x.Keys)+2)
		items = append(items, "map{")
		tabs := "\n" + strings.Repeat("\t", depth)
		for i := 0; i < len(x.Keys); i++ {
			key, _ := p.format(graph, depth+1, x.Keys[i])
			value, _ := p.format(graph, depth+1, x.Values[i])
			items = append(items, fmt.Sprintf("\t%s: %s,", key, value))
		}
		items = append(items, "}")
		return strings.Join(items, tabs), true
	case *wire.Interface:
		typ, typOk := p.formatType(x.Type, graph)
		element, elementOk := p.format(graph, depth+1, x.Value)
		return fmt.Sprintf("interface[%s]{%s}", typ, element), typOk || elementOk
	default:
		return fmt.Sprintf("%v", encoded), true
	}
}

func (p *printer) printStream(w io.Writer, r io.Reader) (err error) {
	wr := wire.Reader{Reader: r}

	var graph uint64

	if p.html {
		fmt.Fprintf(w, "<pre>")
		defer fmt.Fprintf(w, "</pre>")
	}

	defer func() {
		if r := recover(); r != nil {
			if rErr, ok := r.(error); ok {
				err = rErr
				return
			}
			panic(r)
		}
	}()

	p.typeSpecs = make(map[string]*wire.Type)

	for {
		length, object, err := state.ReadHeader(&wr)
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if !object {
			graph++
			if length > 0 {
				fmt.Fprintf(w, "(%d bytes non-object data)\n", length)
				io.Copy(io.Discard, &io.LimitedReader{
					R: r,
					N: int64(length),
				})
			}
			continue
		}

		type objectAndID struct {
			id  uint64
			obj wire.Object
		}
		var (
			tid     uint64 = 1
			objects []objectAndID
		)
		for i := uint64(0); i < length; {
			encoded := wire.Load(&wr)
			switch we := encoded.(type) {
			case *wire.Type:
				str, _ := p.format(graph, 0, encoded)
				tag := fmt.Sprintf("g%dt%d", graph, tid)
				p.typeSpecs[tag] = we
				if p.html {
					tag = fmt.Sprintf("<a name=\"%s\">%s</a><a href=\"#%s\">&#9875;</a>", tag, tag, tag)
				}
				if _, err := fmt.Fprintf(w, "%s = %s\n", tag, str); err != nil {
					return err
				}
				tid++
			case wire.Uint:
				objects = append(objects, objectAndID{
					id:  uint64(we),
					obj: wire.Load(&wr),
				})
				i++
			default:
				return fmt.Errorf("wanted type or object ID, got %#v", encoded)
			}
		}

		for _, objAndID := range objects {
			str, _ := p.format(graph, 0, objAndID.obj)
			tag := fmt.Sprintf("g%dr%d", graph, objAndID.id)
			if p.html {
				tag = fmt.Sprintf("<a name=\"%s\">%s</a><a href=\"#%s\">&#9875;</a>", tag, tag, tag)
			}
			if _, err := fmt.Fprintf(w, "%s = %s\n", tag, str); err != nil {
				return err
			}
		}
	}

	return nil
}

func PrintText(w io.Writer, r io.Reader) error {
	return (&printer{}).printStream(w, r)
}

func PrintHTML(w io.Writer, r io.Reader) error {
	return (&printer{html: true}).printStream(w, r)
}
