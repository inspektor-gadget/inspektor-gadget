// Copyright 2023 The Inspektor Gadget authors
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
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"unicode/utf8"
	_ "unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
)

type column[T any] struct {
	name      string
	nameb     []byte
	column    *columns.Column[T]
	formatter func(*encodeState, *T)
}

type Formatter[T any] struct {
	options *Options
	columns []*column[T]
	scratch [64]byte
}

// NewFormatter returns a Formatter that will turn entries of type T into JSON representation
func NewFormatter[T any](cols columns.ColumnMap[T], options ...Option) *Formatter[T] {
	opts := DefaultOptions()
	for _, o := range options {
		o(opts)
	}

	ncols := make([]*column[T], 0)
	for _, col := range cols.GetOrderedColumns() {
		name, _ := json.Marshal(col.Name)
		key := append(name, []byte(": ")...)

		var formatter func(*encodeState, *T)
		switch col.Kind() {
		default:
			continue
		case reflect.Int,
			reflect.Int8,
			reflect.Int16,
			reflect.Int32,
			reflect.Int64:
			ff := columns.GetFieldAsNumberFunc[int64, T](col)
			formatter = func(e *encodeState, t *T) {
				e.Write(key)
				b := strconv.AppendInt(e.scratch[:0], ff(t), 10)
				e.Write(b)
			}
		case reflect.Uint,
			reflect.Uint8,
			reflect.Uint16,
			reflect.Uint32,
			reflect.Uint64:
			ff := columns.GetFieldAsNumberFunc[uint64, T](col)
			formatter = func(e *encodeState, t *T) {
				e.Write(key)
				b := strconv.AppendUint(e.scratch[:0], ff(t), 10)
				e.Write(b)
			}
		case reflect.Bool:
			ff := columns.GetFieldFunc[bool, T](col)
			formatter = func(e *encodeState, t *T) {
				e.Write(key)
				if ff(t) {
					e.WriteString("true")
					return
				}
				e.WriteString("false")
			}
		case reflect.Float32:
			ff := columns.GetFieldAsNumberFunc[float64, T](col)
			formatter = func(e *encodeState, t *T) {
				e.Write(key)
				floatEncoder(32).writeFloat(e, ff(t))
			}
		case reflect.Float64:
			ff := columns.GetFieldAsNumberFunc[float64, T](col)
			formatter = func(e *encodeState, t *T) {
				e.Write(key)
				floatEncoder(64).writeFloat(e, ff(t))
			}
		case reflect.Array:
			ff := columns.GetFieldAsString[T](col)
			formatter = func(e *encodeState, t *T) {
				e.Write(key)
				writeString(e, ff(t))
			}
		case reflect.String:
			ff := columns.GetFieldFunc[string, T](col)
			formatter = func(e *encodeState, t *T) {
				e.Write(key)
				writeString(e, ff(t))
			}
		}

		ncols = append(ncols, &column[T]{
			column:    col,
			name:      string(name) + ": ",
			nameb:     []byte(string(name) + ": "),
			formatter: formatter,
		})
	}

	tf := &Formatter[T]{
		options: opts,
		columns: ncols,
	}
	return tf
}

// FormatEntry returns an entry as a formatted string, respecting the given formatting settings
func (f *Formatter[T]) FormatEntry(entry *T) string {
	if entry == nil {
		return ""
	}

	buf := bufpool.Get().(*encodeState)
	buf.Reset()
	defer bufpool.Put(buf)

	buf.WriteByte('{')
	for i, col := range f.columns {
		if i > 0 {
			buf.WriteString(", ")
		}
		col.formatter(buf, entry)
	}
	buf.WriteByte('}')
	return buf.String()
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
				e.WriteByte(hex[b>>4])
				e.WriteByte(hex[b&0xF])
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
			e.WriteByte(hex[c&0xF])
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

var hex = "0123456789abcdef"

// use safeSet from encoding/json directly
//
//go:linkname safeSet encoding/json.safeSet
var safeSet = [utf8.RuneSelf]bool{}
