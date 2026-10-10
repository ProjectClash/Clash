//
// Copyright (c) 2011-2019 Canonical Ltd
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

package yaml

import (
	"encoding/base64"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type resolveMapItem struct {
	value interface{}
	tag   string
}

var resolveTable = make([]byte, 256)
var resolveMap = make(map[string]resolveMapItem)

func init() {
	t := resolveTable
	t[int('+')] = 'S'
	t[int('-')] = 'S'
	for _, c := range "0123456789" {
		t[int(c)] = 'D'
	}
	for _, c := range "yYnNtTfFoO~" {
		t[int(c)] = 'M'
	}
	t[int('.')] = '.'

	var resolveMapList = []struct {
		v   interface{}
		tag string
		l   []string
	}{
		{true, boolTag, []string{"true", "True", "TRUE"}},
		{false, boolTag, []string{"false", "False", "FALSE"}},
		{nil, nullTag, []string{"", "~", "null", "Null", "NULL"}},
		{math.NaN(), floatTag, []string{".nan", ".NaN", ".NAN"}},
		{math.Inf(+1), floatTag, []string{".inf", ".Inf", ".INF"}},
		{math.Inf(+1), floatTag, []string{"+.inf", "+.Inf", "+.INF"}},
		{math.Inf(-1), floatTag, []string{"-.inf", "-.Inf", "-.INF"}},
		{"<<", mergeTag, []string{"<<"}},
	}

	m := resolveMap
	for _, item := range resolveMapList {
		for _, s := range item.l {
			m[s] = resolveMapItem{item.v, item.tag}
		}
	}
}

const (
	nullTag      = "!!null"
	boolTag      = "!!bool"
	strTag       = "!!str"
	intTag       = "!!int"
	floatTag     = "!!float"
	timestampTag = "!!timestamp"
	seqTag       = "!!seq"
	mapTag       = "!!map"
	binaryTag    = "!!binary"
	mergeTag     = "!!merge"
)

var longTags = make(map[string]string)
var shortTags = make(map[string]string)

func init() {
	for _, stag := range []string{nullTag, boolTag, strTag, intTag, floatTag, timestampTag, seqTag, mapTag, binaryTag, mergeTag} {
		ltag := longTag(stag)
		longTags[stag] = ltag
		shortTags[ltag] = stag
	}
}

const longTagPrefix = "tag:yaml.org,2002:"

func shortTag(tag string) string {
	if strings.HasPrefix(tag, longTagPrefix) {
		if stag, ok := shortTags[tag]; ok {
			return stag
		}
		return "!!" + tag[len(longTagPrefix):]
	}
	return tag
}

func longTag(tag string) string {
	if strings.HasPrefix(tag, "!!") {
		if ltag, ok := longTags[tag]; ok {
			return ltag
		}
		return longTagPrefix + tag[2:]
	}
	return tag
}

func resolvableTag(tag string) bool {
	switch tag {
	case "", strTag, boolTag, intTag, floatTag, nullTag, timestampTag:
		return true
	}
	return false
}

var yamlStyleFloat = regexp.MustCompile(`^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$`)

func resolve(tag string, in string) (rtag string, out interface{}) {
	tag = shortTag(tag)
	if !resolvableTag(tag) {
		return tag, in
	}

	defer func() {
		switch tag {
		case "", rtag, strTag, binaryTag:
			return
		case floatTag:
			if rtag == intTag {
				switch v := out.(type) {
				case int64:
					rtag = floatTag
					out = float64(v)
					return
				case int:
					rtag = floatTag
					out = float64(v)
					return
				}
			}
		}
		failf("cannot decode %s `%s` as a %s", shortTag(rtag), in, shortTag(tag))
	}()

	hint := byte('N')
	if in != "" {
		hint = resolveTable[in[0]]
	}
	if hint != 0 && tag != strTag && tag != binaryTag {
		if item, ok := resolveMap[in]; ok {
			return item.tag, item.value
		}


		switch hint {
		case 'M':

		case '.':
			floatv, err := strconv.ParseFloat(in, 64)
			if err == nil {
				return floatTag, floatv
			}

		case 'D', 'S':
			if tag == "" || tag == timestampTag {
				t, ok := parseTimestamp(in)
				if ok {
					return timestampTag, t
				}
			}

			plain := strings.Replace(in, "_", "", -1)
			intv, err := strconv.ParseInt(plain, 0, 64)
			if err == nil {
				if intv == int64(int(intv)) {
					return intTag, int(intv)
				} else {
					return intTag, intv
				}
			}
			uintv, err := strconv.ParseUint(plain, 0, 64)
			if err == nil {
				return intTag, uintv
			}
			if yamlStyleFloat.MatchString(plain) {
				floatv, err := strconv.ParseFloat(plain, 64)
				if err == nil {
					return floatTag, floatv
				}
			}
			if strings.HasPrefix(plain, "0b") {
				intv, err := strconv.ParseInt(plain[2:], 2, 64)
				if err == nil {
					if intv == int64(int(intv)) {
						return intTag, int(intv)
					} else {
						return intTag, intv
					}
				}
				uintv, err := strconv.ParseUint(plain[2:], 2, 64)
				if err == nil {
					return intTag, uintv
				}
			} else if strings.HasPrefix(plain, "-0b") {
				intv, err := strconv.ParseInt("-"+plain[3:], 2, 64)
				if err == nil {
					if true || intv == int64(int(intv)) {
						return intTag, int(intv)
					} else {
						return intTag, intv
					}
				}
			}
			if strings.HasPrefix(plain, "0o") {
				intv, err := strconv.ParseInt(plain[2:], 8, 64)
				if err == nil {
					if intv == int64(int(intv)) {
						return intTag, int(intv)
					} else {
						return intTag, intv
					}
				}
				uintv, err := strconv.ParseUint(plain[2:], 8, 64)
				if err == nil {
					return intTag, uintv
				}
			} else if strings.HasPrefix(plain, "-0o") {
				intv, err := strconv.ParseInt("-"+plain[3:], 8, 64)
				if err == nil {
					if true || intv == int64(int(intv)) {
						return intTag, int(intv)
					} else {
						return intTag, intv
					}
				}
			}
		default:
			panic("internal error: missing handler for resolver table: " + string(rune(hint)) + " (with " + in + ")")
		}
	}
	return strTag, in
}

func encodeBase64(s string) string {
	const lineLen = 70
	encLen := base64.StdEncoding.EncodedLen(len(s))
	lines := encLen/lineLen + 1
	buf := make([]byte, encLen*2+lines)
	in := buf[0:encLen]
	out := buf[encLen:]
	base64.StdEncoding.Encode(in, []byte(s))
	k := 0
	for i := 0; i < len(in); i += lineLen {
		j := i + lineLen
		if j > len(in) {
			j = len(in)
		}
		k += copy(out[k:], in[i:j])
		if lines > 1 {
			out[k] = '\n'
			k++
		}
	}
	return string(out[:k])
}

var allowedTimestampFormats = []string{
	"2006-1-2T15:4:5.999999999Z07:00",
	"2006-1-2t15:4:5.999999999Z07:00",
	"2006-1-2 15:4:5.999999999",
	"2006-1-2",
}

func parseTimestamp(s string) (time.Time, bool) {

	i := 0
	for ; i < len(s); i++ {
		if c := s[i]; c < '0' || c > '9' {
			break
		}
	}
	if i != 4 || i == len(s) || s[i] != '-' {
		return time.Time{}, false
	}
	for _, format := range allowedTimestampFormats {
		if t, err := time.Parse(format, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
