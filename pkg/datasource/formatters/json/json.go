// Copyright 2024 The Inspektor Gadget authors
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

package json

import (
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/exp/constraints"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

var (
	openerArray       = []byte("[")
	closerArray       = []byte("]")
	opener            = []byte("{")
	closer            = []byte("}")
	fieldSep          = []byte(",")
	fieldSepPretty    = []byte(",\n")
	openerPretty      = []byte("{\n")
	openerArrayPretty = []byte("[\n")
	closerArrayPretty = []byte("\n]")
)

const (
	// SkipFieldAnnotation is used to indicate that this field should be
	// skipped.
	SkipFieldAnnotation = "json.skip"
)

type Formatter struct {
	ds                datasource.DataSource
	fns               []func(e *encodeState, data datasource.Data)
	fields            []string
	showFields        map[string]struct{}
	hideFields        map[string]struct{}
	allRelativeFields bool
	useDefault        bool
	showAll           bool
	pretty            bool
	array             bool
	indent            string
	opener            []byte
	openerArray       []byte
	fieldSep          []byte
}

func New(ds datasource.DataSource, options ...Option) (*Formatter, error) {
	f := &Formatter{
		ds:         ds,
		showFields: map[string]struct{}{},
		hideFields: map[string]struct{}{},
		useDefault: true,
	}
	for _, o := range options {
		o(f)
	}
	err := f.init()
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (f *Formatter) init() error {
	f.opener = opener
	f.openerArray = openerArray
	f.fieldSep = fieldSep
	if f.pretty {
		f.opener = openerPretty
		f.openerArray = openerArrayPretty
		f.fieldSep = fieldSepPretty
	}
	for _, field := range f.fields {
		if len(field) == 0 {
			continue
		}
		switch field[0] {
		case '+':
			if _, ok := f.hideFields[field[1:]]; ok {
				return fmt.Errorf("field %q both added (+) and removed (-)", field[1:])
			}
			f.showFields[field[1:]] = struct{}{}
		case '-':
			if _, ok := f.showFields[field[1:]]; ok {
				return fmt.Errorf("field %q both added (+) and removed (-)", field[1:])
			}
			f.hideFields[field[1:]] = struct{}{}
		default:
			f.showFields[field] = struct{}{}
			f.allRelativeFields = false
		}
	}

	opener := f.opener
	indent := f.indent
	closer := closer
	if f.pretty {
		if f.array {
			opener = append([]byte(f.indent), opener...)
			indent = f.indent + f.indent
			closer = append([]byte("\n"+f.indent), closer...)
		} else {
			closer = append([]byte("\n"), closer...)
		}
	}

	f.fns = append(f.fns, func(e *encodeState, data datasource.Data) {
		e.Write(opener)
	})
	subFieldFuncs, _ := f.addSubFields(nil, "", indent)
	f.fns = append(f.fns, subFieldFuncs...)
	f.fns = append(f.fns, func(e *encodeState, data datasource.Data) {
		e.Write(closer)
	})
	return nil
}

func writeIntArrFn[T constraints.Integer](
	toArrayFn func(datasource.Data) ([]T, error),
	fieldSep []byte,
	newIndent string,
) func(e *encodeState, data datasource.Data) {
	return func(e *encodeState, data datasource.Data) {
		vals, _ := toArrayFn(data)
		for i, v := range vals {
			if i > 0 {
				e.Write(fieldSep)
			}
			e.WriteString(newIndent)
			b := strconv.AppendInt(e.scratch[:0], int64(v), 10)
			e.Write(b)
		}
	}
}

func writeFloatArrFn[T constraints.Float](
	toArrayFn func(datasource.Data) ([]T, error),
	fieldSep []byte,
	newIndent string,
) func(e *encodeState, data datasource.Data) {
	var f T
	fsize := unsafe.Sizeof(f)
	return func(e *encodeState, data datasource.Data) {
		vals, _ := toArrayFn(data)
		for i, v := range vals {
			if i > 0 {
				e.Write(fieldSep)
			}
			e.WriteString(newIndent)
			floatEncoder(fsize*8).writeFloat(e, float64(v))
		}
	}
}

func (f *Formatter) addSubFields(accessors []datasource.FieldAccessor, prefix string, indent string) (fns []func(*encodeState, datasource.Data), fieldCounter int) {
	if accessors == nil {
		accessors = f.ds.Accessors(true)
	}

	ctr := -1

	// sort lexicographically
	slices.SortFunc(accessors, func(i datasource.FieldAccessor, j datasource.FieldAccessor) int {
		return strings.Compare(i.Name(), j.Name())
	})

	for _, acc := range accessors {
		accessor := acc

		// skip unreferenced fields
		if datasource.FieldFlagUnreferenced.In(accessor.Flags()) {
			continue
		}

		if val, ok := acc.Annotations()[SkipFieldAnnotation]; ok && val == "true" {
			continue
		}

		fullFieldName := prefix + accessor.Name()

		var subFieldFuncs []func(state *encodeState, data datasource.Data)
		var subFieldCount int
		subFields := accessor.SubFields()
		if len(subFields) > 0 {
			subFieldFuncs, subFieldCount = f.addSubFields(subFields, fullFieldName+".", indent+f.indent)
			fieldCounter += subFieldCount
		}

		// If subFieldCount is > 0, a child of this field has been requested, so we also
		// need to show this parent; if not, we follow the default rules of field visibility
		if subFieldCount == 0 {
			if !f.useDefault {
				if _, ok := f.hideFields[fullFieldName]; ok {
					continue
				}
				if _, ok := f.showFields[fullFieldName]; !ok {
					if !f.allRelativeFields {
						continue
					}
					if datasource.FieldFlagHidden.In(accessor.Flags()) {
						continue
					}
				}
			} else {
				if !f.showAll && datasource.FieldFlagHidden.In(accessor.Flags()) {
					continue
				}
			}
		}

		ctr++
		fieldCounter++
		fieldName := []byte("\"" + accessor.Name() + "\":")
		if f.pretty {
			fieldName = append(append([]byte(indent), fieldName...), ' ')
		}
		if ctr > 0 {
			fns = append(fns, func(e *encodeState, data datasource.Data) {
				e.Write(f.fieldSep)
			})
		}

		closer := closer
		closerArray := closerArray
		if f.pretty {
			closer = append([]byte("\n"+indent), closer...)
			closerArray = append([]byte("\n"+indent), closerArray...)
		}

		// Field has subfields
		if len(subFields) > 0 {
			fns = append(fns, func(e *encodeState, data datasource.Data) {
				e.Write(fieldName)
				e.Write(f.opener)
			})
			fns = append(fns, subFieldFuncs...)
			fns = append(fns, func(e *encodeState, data datasource.Data) {
				e.Write(closer)
			})
			continue
		}

		var fn func(e *encodeState, data datasource.Data)

		// Field doesn't have subfields
		if accessor.Type()&api.KindFlagArray != 0 {
			newIndent := ""
			if f.pretty {
				newIndent = indent + f.indent
			}
			switch accessor.Type() {
			case api.ArrayOf(api.Kind_Int8):
				fn = writeIntArrFn(accessor.Int8Array, f.fieldSep, newIndent)
			case api.ArrayOf(api.Kind_Int16):
				fn = writeIntArrFn(accessor.Int16Array, f.fieldSep, newIndent)
			case api.ArrayOf(api.Kind_Int32):
				fn = writeIntArrFn(accessor.Int32Array, f.fieldSep, newIndent)
			case api.ArrayOf(api.Kind_Int64):
				fn = writeIntArrFn(accessor.Int64Array, f.fieldSep, newIndent)
			case api.ArrayOf(api.Kind_Uint8):
				fn = writeIntArrFn(accessor.Uint8Array, f.fieldSep, newIndent)
			case api.ArrayOf(api.Kind_Uint16):
				fn = writeIntArrFn(accessor.Uint16Array, f.fieldSep, newIndent)
			case api.ArrayOf(api.Kind_Uint32):
				fn = writeIntArrFn(accessor.Uint32Array, f.fieldSep, newIndent)
			case api.ArrayOf(api.Kind_Uint64):
				fn = writeIntArrFn(accessor.Uint64Array, f.fieldSep, newIndent)
			case api.ArrayOf(api.Kind_Float32):
				fn = writeFloatArrFn(accessor.Float32Array, f.fieldSep, newIndent)
			case api.ArrayOf(api.Kind_Float64):
				fn = writeFloatArrFn(accessor.Float64Array, f.fieldSep, newIndent)
			default:
				fn = func(e *encodeState, data datasource.Data) {
					e.Write(fieldName)
					writeString(e, hex.EncodeToString(accessor.Get(data)))
				}
				continue
			}
			fns = append(fns, func(e *encodeState, data datasource.Data) {
				e.Write(fieldName)
				e.Write(f.openerArray)
				fn(e, data)
				e.Write(closerArray)
			})
			continue
		}

		switch accessor.Type() {
		case api.Kind_Int8:
			fn = func(e *encodeState, data datasource.Data) {
				v, _ := accessor.Int8(data)
				b := strconv.AppendInt(e.scratch[:0], int64(v), 10)
				e.Write(b)
			}
		case api.Kind_Int16:
			fn = func(e *encodeState, data datasource.Data) {
				v, _ := accessor.Int16(data)
				b := strconv.AppendInt(e.scratch[:0], int64(v), 10)
				e.Write(b)
			}
		case api.Kind_Int32:
			fn = func(e *encodeState, data datasource.Data) {
				v, _ := accessor.Int32(data)
				b := strconv.AppendInt(e.scratch[:0], int64(v), 10)
				e.Write(b)
			}
		case api.Kind_Int64:
			fn = func(e *encodeState, data datasource.Data) {
				v, _ := accessor.Int64(data)
				b := strconv.AppendInt(e.scratch[:0], v, 10)
				e.Write(b)
			}
		case api.Kind_Uint8:
			fn = func(e *encodeState, data datasource.Data) {
				v, _ := accessor.Uint8(data)
				b := strconv.AppendUint(e.scratch[:0], uint64(v), 10)
				e.Write(b)
			}
		case api.Kind_Uint16:
			fn = func(e *encodeState, data datasource.Data) {
				v, _ := accessor.Uint16(data)
				b := strconv.AppendUint(e.scratch[:0], uint64(v), 10)
				e.Write(b)
			}
		case api.Kind_Uint32:
			fn = func(e *encodeState, data datasource.Data) {
				v, _ := accessor.Uint32(data)
				b := strconv.AppendUint(e.scratch[:0], uint64(v), 10)
				e.Write(b)
			}
		case api.Kind_Uint64:
			fn = func(e *encodeState, data datasource.Data) {
				v, _ := accessor.Uint64(data)
				b := strconv.AppendUint(e.scratch[:0], v, 10)
				e.Write(b)
			}
		case api.Kind_Float32:
			fn = func(e *encodeState, data datasource.Data) {
				v, _ := accessor.Float32(data)
				floatEncoder(32).writeFloat(e, float64(v))
			}
		case api.Kind_Float64:
			fn = func(e *encodeState, data datasource.Data) {
				v, _ := accessor.Float64(data)
				floatEncoder(64).writeFloat(e, v)
			}
		case api.Kind_String, api.Kind_CString:
			fn = func(e *encodeState, data datasource.Data) {
				v, _ := accessor.String(data)
				writeString(e, v)
			}
		case api.Kind_Bool:
			fn = func(e *encodeState, data datasource.Data) {
				v, _ := accessor.Bool(data)
				if v {
					e.WriteString("true")
				} else {
					e.WriteString("false")
				}
			}
		default:
			fn = func(e *encodeState, data datasource.Data) {
				writeString(e, hex.EncodeToString(accessor.Get(data)))
			}
		}
		fns = append(fns, func(e *encodeState, data datasource.Data) {
			e.Write(fieldName)
			fn(e, data)
		})
	}
	return
}

func (f *Formatter) Marshal(data datasource.Data) []byte {
	e := bufpool.Get().(*encodeState)
	e.Reset()
	defer bufpool.Put(e)
	for _, fn := range f.fns {
		fn(e, data)
	}
	return e.Bytes()
}

func (f *Formatter) MarshalArray(a datasource.DataArray) []byte {
	// If the array is empty, return an empty one-line array (no matter if
	// pretty is enabled or not)
	len := a.Len()
	if len == 0 {
		return append(openerArray, closerArray...)
	}

	e := bufpool.Get().(*encodeState)
	e.Reset()
	defer bufpool.Put(e)

	oArray := openerArray
	cArray := closerArray
	fieldSepArray := fieldSep
	if f.pretty {
		oArray = openerArrayPretty
		cArray = closerArrayPretty
		fieldSepArray = fieldSepPretty
	}

	e.Write([]byte(oArray))
	for i := 0; i < len; i++ {
		for _, fn := range f.fns {
			fn(e, a.Get(i))
		}
		// Don't add a separator after the last array element
		if i < len-1 {
			e.Write([]byte(fieldSepArray))
		}
	}
	e.Write([]byte(cArray))

	return e.Bytes()
}

type floatEncoder int // number of bits

// from encoding/json/encode.go
func (bits floatEncoder) writeFloat(e *encodeState, f float64) {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		e.err = fmt.Errorf("invalid float value")
		return
	}

	// Convert as if by ES6 number to string conversion.
	// This matches most other JSON generators.
	// See golang.org/issue/6384 and golang.org/issue/14135.
	// Like fmt %g, but the exponent cutoffs are different
	// and exponents themselves are not padded to two digits.
	b := e.scratch[:0]
	abs := math.Abs(f)
	fmt := byte('f')
	// Note: Must use float32 comparisons for underlying float32 value to get precise cutoffs right.
	if abs != 0 {
		if bits == 64 && (abs < 1e-6 || abs >= 1e21) || bits == 32 && (float32(abs) < 1e-6 || float32(abs) >= 1e21) {
			fmt = 'e'
		}
	}
	b = strconv.AppendFloat(b, f, fmt, -1, int(bits))
	if fmt == 'e' {
		// clean up e-09 to e-9
		n := len(b)
		if n >= 4 && b[n-4] == 'e' && b[n-3] == '-' && b[n-2] == '0' {
			b[n-2] = b[n-1]
			b = b[:n-1]
		}
	}

	e.Write(b)
}

// from encoding/json/encode.go
func writeString(e *encodeState, s string) {
	e.WriteByte('"')
	start := 0
	for i := 0; i < len(s); {
		if b := s[i]; b < utf8.RuneSelf {
			if safeSet[b] {
				i++
				continue
			}
			if start < i {
				e.WriteString(s[start:i])
			}
			e.WriteByte('\\')
			switch b {
			case '\\', '"':
				e.WriteByte(b)
			case '\n':
				e.WriteByte('n')
			case '\r':
				e.WriteByte('r')
			case '\t':
				e.WriteByte('t')
			default:
				// This encodes bytes < 0x20 except for \t, \n and \r.
				// If escapeHTML is set, it also escapes <, >, and &
				// because they can lead to security holes when
				// user-controlled strings are rendered into JSON
				// and served to some browsers.
				e.WriteString(`u00`)
				e.WriteByte(hexChars[b>>4])
				e.WriteByte(hexChars[b&0xF])
			}
			i++
			start = i
			continue
		}
		c, size := utf8.DecodeRuneInString(s[i:])
		if c == utf8.RuneError && size == 1 {
			if start < i {
				e.WriteString(s[start:i])
			}
			e.WriteString(`\ufffd`)
			i += size
			start = i
			continue
		}
		// U+2028 is LINE SEPARATOR.
		// U+2029 is PARAGRAPH SEPARATOR.
		// They are both technically valid characters in JSON strings,
		// but don't work in JSONP, which has to be evaluated as JavaScript,
		// and can lead to security holes there. It is valid JSON to
		// escape them, so we do so unconditionally.
		// See http://timelessrepo.com/json-isnt-a-javascript-subset for discussion.
		if c == '\u2028' || c == '\u2029' {
			if start < i {
				e.WriteString(s[start:i])
			}
			e.WriteString(`\u202`)
			e.WriteByte(hexChars[c&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	if start < len(s) {
		e.WriteString(s[start:])
	}
	e.WriteByte('"')
}

const hexChars = "0123456789abcdef"

// use safeSet from encoding/json directly
//
//go:linkname safeSet encoding/json.safeSet
var safeSet = [utf8.RuneSelf]bool{}
