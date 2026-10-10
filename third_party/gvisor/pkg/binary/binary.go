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

package binary

import (
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
)

var LittleEndian = binary.LittleEndian

var BigEndian = binary.BigEndian

func AppendUint16(buf []byte, order binary.ByteOrder, num uint16) []byte {
	buf = append(buf, make([]byte, 2)...)
	order.PutUint16(buf[len(buf)-2:], num)
	return buf
}

func AppendUint32(buf []byte, order binary.ByteOrder, num uint32) []byte {
	buf = append(buf, make([]byte, 4)...)
	order.PutUint32(buf[len(buf)-4:], num)
	return buf
}

func AppendUint64(buf []byte, order binary.ByteOrder, num uint64) []byte {
	buf = append(buf, make([]byte, 8)...)
	order.PutUint64(buf[len(buf)-8:], num)
	return buf
}

func Marshal(buf []byte, order binary.ByteOrder, data any) []byte {
	return marshal(buf, order, reflect.Indirect(reflect.ValueOf(data)))
}

func marshal(buf []byte, order binary.ByteOrder, data reflect.Value) []byte {
	switch data.Kind() {
	case reflect.Int8:
		buf = append(buf, byte(int8(data.Int())))
	case reflect.Int16:
		buf = AppendUint16(buf, order, uint16(int16(data.Int())))
	case reflect.Int32:
		buf = AppendUint32(buf, order, uint32(int32(data.Int())))
	case reflect.Int64:
		buf = AppendUint64(buf, order, uint64(data.Int()))

	case reflect.Uint8:
		buf = append(buf, byte(data.Uint()))
	case reflect.Uint16:
		buf = AppendUint16(buf, order, uint16(data.Uint()))
	case reflect.Uint32:
		buf = AppendUint32(buf, order, uint32(data.Uint()))
	case reflect.Uint64:
		buf = AppendUint64(buf, order, data.Uint())

	case reflect.Array, reflect.Slice:
		for i, l := 0, data.Len(); i < l; i++ {
			buf = marshal(buf, order, data.Index(i))
		}

	case reflect.Struct:
		for i, l := 0, data.NumField(); i < l; i++ {
			buf = marshal(buf, order, data.Field(i))
		}

	default:
		panic("invalid type: " + data.Type().String())
	}
	return buf
}

func Unmarshal(buf []byte, order binary.ByteOrder, data any) {
	value := reflect.ValueOf(data)
	switch value.Kind() {
	case reflect.Ptr:
		value = value.Elem()
	case reflect.Slice:
	default:
		panic("invalid type: " + value.Type().String())
	}
	buf = unmarshal(buf, order, value)
	if len(buf) != 0 {
		panic(fmt.Sprintf("buffer too long by %d bytes", len(buf)))
	}
}

func unmarshal(buf []byte, order binary.ByteOrder, data reflect.Value) []byte {
	switch data.Kind() {
	case reflect.Int8:
		data.SetInt(int64(int8(buf[0])))
		buf = buf[1:]
	case reflect.Int16:
		data.SetInt(int64(int16(order.Uint16(buf))))
		buf = buf[2:]
	case reflect.Int32:
		data.SetInt(int64(int32(order.Uint32(buf))))
		buf = buf[4:]
	case reflect.Int64:
		data.SetInt(int64(order.Uint64(buf)))
		buf = buf[8:]

	case reflect.Uint8:
		data.SetUint(uint64(buf[0]))
		buf = buf[1:]
	case reflect.Uint16:
		data.SetUint(uint64(order.Uint16(buf)))
		buf = buf[2:]
	case reflect.Uint32:
		data.SetUint(uint64(order.Uint32(buf)))
		buf = buf[4:]
	case reflect.Uint64:
		data.SetUint(order.Uint64(buf))
		buf = buf[8:]

	case reflect.Array, reflect.Slice:
		for i, l := 0, data.Len(); i < l; i++ {
			buf = unmarshal(buf, order, data.Index(i))
		}

	case reflect.Struct:
		for i, l := 0, data.NumField(); i < l; i++ {
			if field := data.Field(i); field.CanSet() {
				buf = unmarshal(buf, order, field)
			} else {
				buf = buf[sizeof(field):]
			}
		}

	default:
		panic("invalid type: " + data.Type().String())
	}
	return buf
}

func Size(v any) uintptr {
	return sizeof(reflect.Indirect(reflect.ValueOf(v)))
}

func sizeof(data reflect.Value) uintptr {
	switch data.Kind() {
	case reflect.Int8, reflect.Uint8:
		return 1
	case reflect.Int16, reflect.Uint16:
		return 2
	case reflect.Int32, reflect.Uint32:
		return 4
	case reflect.Int64, reflect.Uint64:
		return 8

	case reflect.Array, reflect.Slice:
		var size uintptr
		for i, l := 0, data.Len(); i < l; i++ {
			size += sizeof(data.Index(i))
		}
		return size

	case reflect.Struct:
		var size uintptr
		for i, l := 0, data.NumField(); i < l; i++ {
			size += sizeof(data.Field(i))
		}
		return size

	default:
		panic("invalid type: " + data.Type().String())
	}
}

func ReadUint16(r io.Reader, order binary.ByteOrder) (uint16, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	return order.Uint16(buf), nil
}

func ReadUint32(r io.Reader, order binary.ByteOrder) (uint32, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	return order.Uint32(buf), nil
}

func ReadUint64(r io.Reader, order binary.ByteOrder) (uint64, error) {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	return order.Uint64(buf), nil
}

func WriteUint16(w io.Writer, order binary.ByteOrder, num uint16) error {
	buf := make([]byte, 2)
	order.PutUint16(buf, num)
	_, err := w.Write(buf)
	return err
}

func WriteUint32(w io.Writer, order binary.ByteOrder, num uint32) error {
	buf := make([]byte, 4)
	order.PutUint32(buf, num)
	_, err := w.Write(buf)
	return err
}

func WriteUint64(w io.Writer, order binary.ByteOrder, num uint64) error {
	buf := make([]byte, 8)
	order.PutUint64(buf, num)
	_, err := w.Write(buf)
	return err
}

func AlignUp(length int, align uint) int {
	return (length + int(align) - 1) & ^(int(align) - 1)
}

func AlignDown(length int, align uint) int {
	return length & ^(int(align) - 1)
}
