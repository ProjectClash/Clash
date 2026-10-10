// Copyright 2020 The gVisor Authors.
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

package state

import (
	"reflect"
	"sort"

	"github.com/metacubex/gvisor/pkg/state/wire"
)

func assertValidType(name string, fields []string) {
	if name == "" {
		Failf("type has empty name")
	}
	fieldsCopy := make([]string, len(fields))
	for i := 0; i < len(fields); i++ {
		if fields[i] == "" {
			Failf("field has empty name for type %q", name)
		}
		fieldsCopy[i] = fields[i]
	}
	sort.Slice(fieldsCopy, func(i, j int) bool {
		return fieldsCopy[i] < fieldsCopy[j]
	})
	for i := range fieldsCopy {
		if i > 0 && fieldsCopy[i-1] == fieldsCopy[i] {
			Failf("duplicate field %q for type %s", fieldsCopy[i], name)
		}
	}
}

type typeEntry struct {
	ID typeID
	wire.Type
}

type reconciledTypeEntry struct {
	wire.Type
	LocalType  reflect.Type
	FieldOrder []int
}

type typeEncodeDatabase struct {
	byType map[reflect.Type]*typeEntry

	lastID typeID
}

func makeTypeEncodeDatabase() typeEncodeDatabase {
	return typeEncodeDatabase{
		byType: make(map[reflect.Type]*typeEntry),
	}
}

type typeDecodeDatabase struct {
	byID []*reconciledTypeEntry

	pending []*wire.Type
}

func makeTypeDecodeDatabase() typeDecodeDatabase {
	return typeDecodeDatabase{}
}

func lookupNameFields(typ reflect.Type) (string, []string, bool) {
	v := reflect.Zero(reflect.PtrTo(typ)).Interface()
	t, ok := v.(Type)
	if !ok {
		if typ.Kind() == reflect.Interface {
			return interfaceType, nil, true
		}
		name := typ.Name()
		if _, ok := primitiveTypeDatabase[name]; !ok {
			return "", nil, false
		}
		return name, nil, true
	}
	if raceEnabled {
		if _, ok := reverseTypeDatabase[typ]; !ok {
			return "", nil, false
		}
	}
	name := t.StateTypeName()
	fields := t.StateFields()
	assertValidType(name, fields)
	return name, fields, true
}

func (tdb *typeEncodeDatabase) Lookup(typ reflect.Type) (*typeEntry, bool) {
	te, ok := tdb.byType[typ]
	if !ok {
		name, fields, ok := lookupNameFields(typ)
		if !ok {
			return nil, false
		}

		tdb.lastID++
		te = &typeEntry{
			ID: tdb.lastID,
			Type: wire.Type{
				Name:   name,
				Fields: fields,
			},
		}

		tdb.byType[typ] = te
		return te, false
	}
	return te, true
}

func (tbd *typeDecodeDatabase) Register(typ *wire.Type) {
	assertValidType(typ.Name, typ.Fields)
	tbd.pending = append(tbd.pending, typ)
}

func (tbd *typeDecodeDatabase) LookupName(id typeID) string {
	if len(tbd.pending) < int(id) {
		Failf("type ID %d not available", id)
	}
	return tbd.pending[id-1].Name
}

func (tbd *typeDecodeDatabase) LookupType(id typeID) reflect.Type {
	name := tbd.LookupName(id)
	typ, ok := globalTypeDatabase[name]
	if !ok {
		typ, ok = primitiveTypeDatabase[name]
		if !ok && name == interfaceType {
			var i any
			return reflect.TypeOf(&i).Elem()
		}
		if !ok {
			Failf("type name %q is not available", name)
		}
		return typ
	}
	return typ
}

var singleFieldOrder = []int{0}

func (tbd *typeDecodeDatabase) Lookup(id typeID, typ reflect.Type) *reconciledTypeEntry {
	if len(tbd.byID) >= int(id) && tbd.byID[id-1] != nil {
		return tbd.byID[id-1]
	}
	if len(tbd.pending) < int(id) {
		Failf("typeDatabase does not contain id %d", id)
	}
	pending := tbd.pending[id-1]
	if len(tbd.byID) < int(id) {
		tbd.byID = append(tbd.byID, make([]*reconciledTypeEntry, int(id)-len(tbd.byID))...)
	}
	name, fields, ok := lookupNameFields(typ)
	if !ok {
		Failf("unsupported type %q during decode; can't reconcile", pending.Name)
	}
	if name != pending.Name {
		Failf("typeDatabase contains conflicting definitions for id %d: %s->%v (current) and %s->%v (existing)",
			id, name, fields, pending.Name, pending.Fields)
	}
	rte := &reconciledTypeEntry{
		Type: wire.Type{
			Name:   name,
			Fields: fields,
		},
		LocalType: typ,
	}
	if len(fields) != len(pending.Fields) {
		Failf("type %q contains different fields: %v (decode) and %v (encode)",
			name, fields, pending.Fields)
	}
	if len(fields) == 0 {
		tbd.byID[id-1] = rte
		return rte
	}
	if len(fields) == 1 && fields[0] == pending.Fields[0] {
		tbd.byID[id-1] = rte
		rte.FieldOrder = singleFieldOrder
		return rte
	}
	fieldOrder := make([]int, len(fields))
	for i, name := range fields {
		fieldOrder[i] = -1
		if pending.Fields[i] == name {
			fieldOrder[i] = i
			continue
		}
		for j, otherName := range pending.Fields {
			if name == otherName {
				fieldOrder[i] = j
				break
			}
		}
		if fieldOrder[i] == -1 {
			Failf("type %q has mismatched fields: %v (decode) and %v (encode)",
				name, fields, pending.Fields)
		}
	}
	rte.FieldOrder = fieldOrder
	tbd.byID[id-1] = rte
	return rte
}

const interfaceType = "interface"

var primitiveTypeDatabase = func() map[string]reflect.Type {
	r := make(map[string]reflect.Type)
	for _, t := range []reflect.Type{
		reflect.TypeOf((*bool)(nil)).Elem(),
		reflect.TypeOf((*int)(nil)).Elem(),
		reflect.TypeOf((*int8)(nil)).Elem(),
		reflect.TypeOf((*int16)(nil)).Elem(),
		reflect.TypeOf((*int32)(nil)).Elem(),
		reflect.TypeOf((*int64)(nil)).Elem(),
		reflect.TypeOf((*uint)(nil)).Elem(),
		reflect.TypeOf((*uintptr)(nil)).Elem(),
		reflect.TypeOf((*uint8)(nil)).Elem(),
		reflect.TypeOf((*uint16)(nil)).Elem(),
		reflect.TypeOf((*uint32)(nil)).Elem(),
		reflect.TypeOf((*uint64)(nil)).Elem(),
		reflect.TypeOf((*string)(nil)).Elem(),
		reflect.TypeOf((*float32)(nil)).Elem(),
		reflect.TypeOf((*float64)(nil)).Elem(),
		reflect.TypeOf((*complex64)(nil)).Elem(),
		reflect.TypeOf((*complex128)(nil)).Elem(),
	} {
		r[t.Name()] = t
	}
	return r
}()

var globalTypeDatabase = map[string]reflect.Type{}

var reverseTypeDatabase = map[reflect.Type]string{}

func Release() {
	globalTypeDatabase = nil
	reverseTypeDatabase = nil
}

func Register(t Type) {
	name := t.StateTypeName()
	typ := reflect.TypeOf(t)
	if raceEnabled {
		assertValidType(name, t.StateFields())
		if typ.Kind() != reflect.Ptr {
			Failf("Register must be called on pointers")
		}
	}
	typ = typ.Elem()
	if raceEnabled {
		if typ.Kind() == reflect.Struct {
			if _, ok := t.(SaverLoader); !ok {
				Failf("struct %T does not implement SaverLoader", t)
			}
		} else {
			if fields := t.StateFields(); len(fields) != 0 {
				Failf("non-struct %T has non-zero fields %v", t, fields)
			}
			if _, ok := t.(SaverLoader); ok {
				Failf("non-struct %T implements SaverLoader", t)
			}
		}
		if _, ok := primitiveTypeDatabase[name]; ok {
			Failf("conflicting primitiveTypeDatabase entry for %T: used by primitive", t)
		}
		if _, ok := globalTypeDatabase[name]; ok {
			Failf("conflicting globalTypeDatabase entries for %T: name conflict", t)
		}
		if name == interfaceType {
			Failf("conflicting name for %T: matches interfaceType", t)
		}
		reverseTypeDatabase[typ] = name
	}
	globalTypeDatabase[name] = typ
}
