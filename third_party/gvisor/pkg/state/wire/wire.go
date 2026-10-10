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

package wire

import (
	"fmt"
	"io"
	"math"

	"github.com/metacubex/gvisor/pkg/gohacks"
)

type Reader struct {
	io.Reader

	buf [1]byte
}

func (r *Reader) readByte() byte {
	n, err := r.Read(r.buf[:])
	if n != 1 {
		panic(err)
	}
	return r.buf[0]
}

type Writer struct {
	io.Writer

	buf [10]byte
}

func readFull(r *Reader, p []byte) {
	for done := 0; done < len(p); {
		n, err := r.Read(p[done:])
		done += n
		if n == 0 && err != nil {
			panic(err)
		}
	}
}

type Object interface {
	save(*Writer)

	load(*Reader) Object
}

type Bool bool

func loadBool(r *Reader) Bool {
	b := loadUint(r)
	return Bool(b == 1)
}

func (b Bool) save(w *Writer) {
	var v Uint
	if b {
		v = 1
	} else {
		v = 0
	}
	v.save(w)
}

func (Bool) load(r *Reader) Object { return loadBool(r) }

type Int int64

func loadInt(r *Reader) Int {
	u := loadUint(r)
	x := Int(u >> 1)
	if u&1 != 0 {
		x = ^x
	}
	return x
}

func (i Int) save(w *Writer) {
	u := Uint(i) << 1
	if i < 0 {
		u = ^u
	}
	u.save(w)
}

func (Int) load(r *Reader) Object { return loadInt(r) }

type Uint uint64

func loadUint(r *Reader) Uint {
	var (
		u Uint
		s uint
	)
	for i := 0; i <= 9; i++ {
		b := r.readByte()
		if b < 0x80 {
			if i == 9 && b > 1 {
				panic("overflow")
			}
			u |= Uint(b) << s
			return u
		}
		u |= Uint(b&0x7f) << s
		s += 7
	}
	panic("unreachable")
}

func (u Uint) save(w *Writer) {
	i := 0
	for u >= 0x80 {
		w.buf[i] = byte(u) | 0x80
		i++
		u >>= 7
	}
	w.buf[i] = byte(u)
	if _, err := w.Write(w.buf[:i+1]); err != nil {
		panic(err)
	}
}

func (Uint) load(r *Reader) Object { return loadUint(r) }

type Float32 float32

func loadFloat32(r *Reader) Float32 {
	n := loadUint(r)
	return Float32(math.Float32frombits(uint32(n)))
}

func (f Float32) save(w *Writer) {
	n := Uint(math.Float32bits(float32(f)))
	n.save(w)
}

func (Float32) load(r *Reader) Object { return loadFloat32(r) }

type Float64 float64

func loadFloat64(r *Reader) Float64 {
	n := loadUint(r)
	return Float64(math.Float64frombits(uint64(n)))
}

func (f Float64) save(w *Writer) {
	n := Uint(math.Float64bits(float64(f)))
	n.save(w)
}

func (Float64) load(r *Reader) Object { return loadFloat64(r) }

type Complex64 complex128

func loadComplex64(r *Reader) Complex64 {
	re := loadFloat32(r)
	im := loadFloat32(r)
	return Complex64(complex(float32(re), float32(im)))
}

func (c *Complex64) save(w *Writer) {
	re := Float32(real(*c))
	im := Float32(imag(*c))
	re.save(w)
	im.save(w)
}

func (*Complex64) load(r *Reader) Object {
	c := loadComplex64(r)
	return &c
}

type Complex128 complex128

func loadComplex128(r *Reader) Complex128 {
	re := loadFloat64(r)
	im := loadFloat64(r)
	return Complex128(complex(float64(re), float64(im)))
}

func (c *Complex128) save(w *Writer) {
	re := Float64(real(*c))
	im := Float64(imag(*c))
	re.save(w)
	im.save(w)
}

func (*Complex128) load(r *Reader) Object {
	c := loadComplex128(r)
	return &c
}

type String string

func loadString(r *Reader) String {
	l := loadUint(r)
	p := make([]byte, l)
	readFull(r, p)
	return String(gohacks.StringFromImmutableBytes(p))
}

func (s *String) save(w *Writer) {
	l := Uint(len(*s))
	l.save(w)
	p := gohacks.ImmutableBytesFromString(string(*s))
	_, err := w.Write(p)
	if err != nil {
		panic(err)
	}
}

func (*String) load(r *Reader) Object {
	s := loadString(r)
	return &s
}

type Dot interface {
	isDot()
}

type Index uint32

func (Index) isDot() {}

type FieldName string

func (*FieldName) isDot() {}

type Ref struct {
	Root Uint

	Dots []Dot

	Type TypeSpec
}

func loadRef(r *Reader) Ref {
	ref := Ref{
		Root: loadUint(r),
	}
	l := loadUint(r)
	ref.Dots = make([]Dot, l)
	for i := 0; i < int(l); i++ {
		d := loadInt(r)
		if d >= 0 {
			ref.Dots[i] = Index(d)
			continue
		}
		p := make([]byte, -d)
		readFull(r, p)
		fieldName := FieldName(gohacks.StringFromImmutableBytes(p))
		ref.Dots[i] = &fieldName
	}
	if l != 0 {
		ref.Type = loadTypeSpec(r)
	}
	return ref
}

func (r *Ref) save(w *Writer) {
	r.Root.save(w)
	l := Uint(len(r.Dots))
	l.save(w)
	for _, d := range r.Dots {
		switch x := d.(type) {
		case Index:
			i := Int(x)
			i.save(w)
		case *FieldName:
			d := Int(-len(*x))
			d.save(w)
			p := gohacks.ImmutableBytesFromString(string(*x))
			if _, err := w.Write(p); err != nil {
				panic(err)
			}
		default:
			panic("unknown dot implementation")
		}
	}
	if l != 0 {
		saveTypeSpec(w, r.Type)
	}
}

func (*Ref) load(r *Reader) Object {
	ref := loadRef(r)
	return &ref
}

type Nil struct{}

func loadNil(r *Reader) Nil {
	return Nil{}
}

func (Nil) save(w *Writer) {}

func (Nil) load(r *Reader) Object { return loadNil(r) }

type Slice struct {
	Length   Uint
	Capacity Uint
	Ref      Ref
}

func loadSlice(r *Reader) Slice {
	return Slice{
		Length:   loadUint(r),
		Capacity: loadUint(r),
		Ref:      loadRef(r),
	}
}

func (s *Slice) save(w *Writer) {
	s.Length.save(w)
	s.Capacity.save(w)
	s.Ref.save(w)
}

func (*Slice) load(r *Reader) Object {
	s := loadSlice(r)
	return &s
}

type Array struct {
	Contents []Object
}

func loadArray(r *Reader) Array {
	l := loadUint(r)
	if l == 0 {
		return Array{}
	}
	contents := make([]Object, l)
	v := Load(r)
	contents[0] = v
	for i := 1; i < int(l); i++ {
		contents[i] = v.load(r)
	}
	return Array{
		Contents: contents,
	}
}

func (a *Array) save(w *Writer) {
	l := Uint(len(a.Contents))
	l.save(w)
	if l == 0 {
		return
	}
	Save(w, a.Contents[0])
	for i := 1; i < int(l); i++ {
		a.Contents[i].save(w)
	}
}

func (*Array) load(r *Reader) Object {
	a := loadArray(r)
	return &a
}

type Map struct {
	Keys   []Object
	Values []Object
}

func loadMap(r *Reader) Map {
	l := loadUint(r)
	if l == 0 {
		return Map{}
	}
	keys := make([]Object, l)
	values := make([]Object, l)
	k := Load(r)
	v := Load(r)
	keys[0] = k
	values[0] = v
	for i := 1; i < int(l); i++ {
		keys[i] = k.load(r)
		values[i] = v.load(r)
	}
	return Map{
		Keys:   keys,
		Values: values,
	}
}

func (m *Map) save(w *Writer) {
	l := Uint(len(m.Keys))
	if int(l) != len(m.Values) {
		panic(fmt.Sprintf("mismatched keys (%d) and values (%d)", len(m.Keys), len(m.Values)))
	}
	l.save(w)
	if l == 0 {
		return
	}
	Save(w, m.Keys[0])
	Save(w, m.Values[0])
	for i := 1; i < int(l); i++ {
		m.Keys[i].save(w)
		m.Values[i].save(w)
	}
}

func (*Map) load(r *Reader) Object {
	m := loadMap(r)
	return &m
}

type TypeSpec interface {
	isTypeSpec()
}

type TypeID Uint

func (TypeID) isTypeSpec() {}

type TypeSpecPointer struct {
	Type TypeSpec
}

func (*TypeSpecPointer) isTypeSpec() {}

type TypeSpecArray struct {
	Count Uint
	Type  TypeSpec
}

func (*TypeSpecArray) isTypeSpec() {}

type TypeSpecSlice struct {
	Type TypeSpec
}

func (*TypeSpecSlice) isTypeSpec() {}

type TypeSpecMap struct {
	Key   TypeSpec
	Value TypeSpec
}

func (*TypeSpecMap) isTypeSpec() {}

type TypeSpecNil struct{}

func (TypeSpecNil) isTypeSpec() {}

const (
	typeSpecTypeID Uint = iota
	typeSpecPointer
	typeSpecArray
	typeSpecSlice
	typeSpecMap
	typeSpecNil
)

func loadTypeSpec(r *Reader) TypeSpec {
	switch hdr := loadUint(r); hdr {
	case typeSpecTypeID:
		return TypeID(loadUint(r))
	case typeSpecPointer:
		return &TypeSpecPointer{
			Type: loadTypeSpec(r),
		}
	case typeSpecArray:
		return &TypeSpecArray{
			Count: loadUint(r),
			Type:  loadTypeSpec(r),
		}
	case typeSpecSlice:
		return &TypeSpecSlice{
			Type: loadTypeSpec(r),
		}
	case typeSpecMap:
		return &TypeSpecMap{
			Key:   loadTypeSpec(r),
			Value: loadTypeSpec(r),
		}
	case typeSpecNil:
		return TypeSpecNil{}
	default:
		panic(fmt.Errorf("unknown header: %d", hdr))
	}
}

func saveTypeSpec(w *Writer, t TypeSpec) {
	switch x := t.(type) {
	case TypeID:
		typeSpecTypeID.save(w)
		Uint(x).save(w)
	case *TypeSpecPointer:
		typeSpecPointer.save(w)
		saveTypeSpec(w, x.Type)
	case *TypeSpecArray:
		typeSpecArray.save(w)
		x.Count.save(w)
		saveTypeSpec(w, x.Type)
	case *TypeSpecSlice:
		typeSpecSlice.save(w)
		saveTypeSpec(w, x.Type)
	case *TypeSpecMap:
		typeSpecMap.save(w)
		saveTypeSpec(w, x.Key)
		saveTypeSpec(w, x.Value)
	case TypeSpecNil:
		typeSpecNil.save(w)
	default:
		panic(fmt.Errorf("unknown type %T", t))
	}
}

type Interface struct {
	Type  TypeSpec
	Value Object
}

func loadInterface(r *Reader) Interface {
	return Interface{
		Type:  loadTypeSpec(r),
		Value: Load(r),
	}
}

func (i *Interface) save(w *Writer) {
	saveTypeSpec(w, i.Type)
	Save(w, i.Value)
}

func (*Interface) load(r *Reader) Object {
	i := loadInterface(r)
	return &i
}

type Type struct {
	Name   string
	Fields []string
}

func loadType(r *Reader) Type {
	name := string(loadString(r))
	l := loadUint(r)
	fields := make([]string, l)
	for i := 0; i < int(l); i++ {
		fields[i] = string(loadString(r))
	}
	return Type{
		Name:   name,
		Fields: fields,
	}
}

func (t *Type) save(w *Writer) {
	s := String(t.Name)
	s.save(w)
	l := Uint(len(t.Fields))
	l.save(w)
	for i := 0; i < int(l); i++ {
		s := String(t.Fields[i])
		s.save(w)
	}
}

func (*Type) load(r *Reader) Object {
	t := loadType(r)
	return &t
}

type multipleObjects []Object

func loadMultipleObjects(r *Reader) multipleObjects {
	l := loadUint(r)
	m := make(multipleObjects, l)
	for i := 0; i < int(l); i++ {
		m[i] = Load(r)
	}
	return m
}

func (m *multipleObjects) save(w *Writer) {
	l := Uint(len(*m))
	l.save(w)
	for i := 0; i < int(l); i++ {
		Save(w, (*m)[i])
	}
}

func (*multipleObjects) load(r *Reader) Object {
	m := loadMultipleObjects(r)
	return &m
}

type noObjects struct{}

func loadNoObjects(r *Reader) noObjects { return noObjects{} }

func (noObjects) save(w *Writer) {}

func (noObjects) load(r *Reader) Object { return loadNoObjects(r) }

type Struct struct {
	TypeID TypeID
	fields Object
}

func (s *Struct) Field(i int) *Object {
	if fields, ok := s.fields.(*multipleObjects); ok {
		return &((*fields)[i])
	}
	if _, ok := s.fields.(noObjects); ok {
		panic("Field called inappropriately, wrong Alloc?")
	}
	return &s.fields
}

func (s *Struct) Alloc(slots int) {
	switch {
	case slots == 0:
		s.fields = noObjects{}
	case slots == 1:
	case slots > 1:
		fields := make(multipleObjects, slots)
		s.fields = &fields
	default:
		panic(fmt.Sprintf("Alloc called with negative slots %d?", slots))
	}
}

func (s *Struct) Fields() int {
	switch x := s.fields.(type) {
	case *multipleObjects:
		return len(*x)
	case noObjects:
		return 0
	default:
		return 1
	}
}

func loadStruct(r *Reader) Struct {
	return Struct{
		TypeID: TypeID(loadUint(r)),
		fields: Load(r),
	}
}

func (s *Struct) save(w *Writer) {
	Uint(s.TypeID).save(w)
	Save(w, s.fields)
}

func (*Struct) load(r *Reader) Object {
	s := loadStruct(r)
	return &s
}

const (
	typeBool Uint = iota
	typeInt
	typeUint
	typeFloat32
	typeFloat64
	typeNil
	typeRef
	typeString
	typeSlice
	typeArray
	typeMap
	typeStruct
	typeNoObjects
	typeMultipleObjects
	typeInterface
	typeComplex64
	typeComplex128
	typeType
)

func Save(w *Writer, obj Object) {
	switch x := obj.(type) {
	case Bool:
		typeBool.save(w)
		x.save(w)
	case Int:
		typeInt.save(w)
		x.save(w)
	case Uint:
		typeUint.save(w)
		x.save(w)
	case Float32:
		typeFloat32.save(w)
		x.save(w)
	case Float64:
		typeFloat64.save(w)
		x.save(w)
	case Nil:
		typeNil.save(w)
		x.save(w)
	case *Ref:
		typeRef.save(w)
		x.save(w)
	case *String:
		typeString.save(w)
		x.save(w)
	case *Slice:
		typeSlice.save(w)
		x.save(w)
	case *Array:
		typeArray.save(w)
		x.save(w)
	case *Map:
		typeMap.save(w)
		x.save(w)
	case *Struct:
		typeStruct.save(w)
		x.save(w)
	case noObjects:
		typeNoObjects.save(w)
		x.save(w)
	case *multipleObjects:
		typeMultipleObjects.save(w)
		x.save(w)
	case *Interface:
		typeInterface.save(w)
		x.save(w)
	case *Type:
		typeType.save(w)
		x.save(w)
	case *Complex64:
		typeComplex64.save(w)
		x.save(w)
	case *Complex128:
		typeComplex128.save(w)
		x.save(w)
	default:
		panic(fmt.Errorf("unknown type: %#v", obj))
	}
}

func Load(r *Reader) Object {
	switch hdr := loadUint(r); hdr {
	case typeBool:
		return loadBool(r)
	case typeInt:
		return loadInt(r)
	case typeUint:
		return loadUint(r)
	case typeFloat32:
		return loadFloat32(r)
	case typeFloat64:
		return loadFloat64(r)
	case typeNil:
		return loadNil(r)
	case typeRef:
		return ((*Ref)(nil)).load(r)
	case typeString:
		return ((*String)(nil)).load(r)
	case typeSlice:
		return ((*Slice)(nil)).load(r)
	case typeArray:
		return ((*Array)(nil)).load(r)
	case typeMap:
		return ((*Map)(nil)).load(r)
	case typeStruct:
		return ((*Struct)(nil)).load(r)
	case typeNoObjects:
		return loadNoObjects(r)
	case typeMultipleObjects:
		return ((*multipleObjects)(nil)).load(r)
	case typeInterface:
		return ((*Interface)(nil)).load(r)
	case typeComplex64:
		return ((*Complex64)(nil)).load(r)
	case typeComplex128:
		return ((*Complex128)(nil)).load(r)
	case typeType:
		return ((*Type)(nil)).load(r)
	default:
		panic(fmt.Errorf("unknown header: %d", hdr))
	}
}

func LoadUint(r *Reader) uint64 {
	return uint64(loadUint(r))
}

func SaveUint(w *Writer, v uint64) {
	Uint(v).save(w)
}
