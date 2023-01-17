// Copyright 2022-2023 The Inspektor Gadget authors
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

/*
Package params provides a generic way to describe parameters used by gadgets, operators
and runtimes including validation. They can easily be serialized and handed over to different
frameworks like cobra for use in CLI or a webinterface using JSON.
*/
package params

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type (
	Params         []*Param
	ParamDescs     []*ParamDesc
	DescCollection map[string]*ParamDescs
	Collection     map[string]*Params
)

var ErrNotFound = errors.New("not found")

// ParamDesc holds parameter information and validators
type ParamDesc struct {
	// Key is the name under which this param is registered; this will also be the key when
	// getting a key/value map
	Key string `json:"key"`

	// Alias is a shortcut for this parameter, usually a single character used for command line
	// interfaces
	Alias string `json:"alias"`

	// Title is an optional (pretty) alternative to key and used in user interfaces
	Title string `json:"title"`

	// DefaultValue is the value that will be used if no other value has been assigned
	DefaultValue string `json:"defaultValue"`

	// Description holds an optional explanation for this parameter; shown in user interfaces
	Description string `json:"description"`

	// IsMandatory will be considered when validating; if the param has no value assigned and
	// also no DefaultValue is set, validation will fail
	IsMandatory bool `json:"isMandatory"`

	// Tags can be used to skip parameters not needed for a specific environment
	Tags []string `json:"tags"`

	// Validator is an optional function that will be called upon validation; may or may
	// not be called in user interfaces. Setting TypeHint is preferred, but can also be used
	// in combination with the Validator. Example: additionally to setting the TypeHint to
	// TypeInt, the validator could be used to make sure the given int is in a specific range.
	Validator ParamValidator `json:"-"`

	// TypeHint is the preferred way to set the type of this parameter as it will invoke a
	// matching validator automatically; if unset, a value of "string" is assumed
	TypeHint TypeHint `json:"type"`

	// PossibleValues holds all possible values for this parameter and will be considered
	// when validating
	PossibleValues []string `json:"possibleValues"`
}

// Param holds a ParamDesc but can additionally store a value
type Param struct {
	*ParamDesc
	value string
}

// GetTitle returns a human friendly title of the field; is no Title has been specified,
// the Key will be used with the first letter upper-cased
func (p *ParamDesc) GetTitle() string {
	if p.Title != "" {
		return p.Title
	}
	return cases.Title(language.English).String(p.Key)
}

func (p *ParamDesc) ToParam() *Param {
	return &Param{
		ParamDesc: p,
		value:     p.DefaultValue,
	}
}

// Validate validates a string against the given parameter
func (p *ParamDesc) Validate(value string) error {
	if value == "" && p.IsMandatory {
		return fmt.Errorf("expected value for %q", p.Key)
	}

	if len(p.PossibleValues) > 0 {
		for _, v := range p.PossibleValues {
			if v == value {
				return nil
			}
		}
		return fmt.Errorf("invalid value %q as %q: valid values are: %s", value, p.Key, strings.Join(p.PossibleValues, ", "))
	}
	if typeValidator, ok := typeHintValidators[p.TypeHint]; ok {
		if err := typeValidator(value); err != nil {
			return fmt.Errorf("invalid value %q as %q: %w", value, p.Key, err)
		}
	}
	if p.Validator != nil {
		if err := p.Validator(value); err != nil {
			return fmt.Errorf("invalid value %q as %q: %w", value, p.Key, err)
		}
	}

	return nil
}

// Type is a member of the pflag.Value interface, which is used by cobra
func (p *ParamDesc) Type() string {
	if p.TypeHint != "" {
		// returning a proper type here will display it as type for cobra params as well
		return string(p.TypeHint)
	}
	return "string"
}

func (p *ParamDesc) IsBoolFlag() bool {
	return p.TypeHint == TypeBool
}

func (p ParamDescs) ToParams() *Params {
	params := make(Params, 0, len(p))
	for _, param := range p {
		params = append(params, param.ToParam())
	}
	return &params
}

func (p *ParamDescs) Add(other ...*ParamDesc) {
	for _, v := range other {
		*p = append(*p, v)
	}
}

// Get returns the parameter with the given key or nil
func (p *ParamDescs) Get(key string) *ParamDesc {
	for _, param := range *p {
		if key == param.Key {
			return param
		}
	}
	return nil
}

func (p DescCollection) ToParams() Collection {
	coll := make(Collection)
	for key, param := range p {
		coll[key] = param.ToParams()
	}
	return coll
}

func (p *Params) Add(other ...*Param) {
	for _, v := range other {
		*p = append(*p, v)
	}
}

func (p *Params) AddKeyValuePair(key, value string) {
	*p = append(*p, &Param{
		ParamDesc: &ParamDesc{Key: key},
		value:     value,
	})
}

// Get returns the parameter with the given key or nil
func (p *Params) Get(key string) *Param {
	for _, param := range *p {
		if key == param.Key {
			return param
		}
	}
	return nil
}

func (p *Params) Set(key, val string) error {
	for _, e := range *p {
		if e.Key == key {
			return e.Set(val)
		}
	}
	return ErrNotFound
}

func (p *Params) ParamMap() (res map[string]string) {
	res = make(map[string]string)
	for _, v := range *p {
		res[v.Key] = v.String()
	}
	return
}

func (p *Params) ValidateStringMap(cfg map[string]string) error {
	for _, param := range *p {
		value, ok := cfg[param.Key]
		if !ok && param.IsMandatory {
			return fmt.Errorf("expected value for %q", param.Key)
		}
		if param.Validator != nil {
			if err := param.Validator(value); err != nil {
				return fmt.Errorf("invalid value %q as %q: %w", value, param.Key, err)
			}
		}
	}
	return nil
}

func (p *Params) CopyToMap(target map[string]string, prefix string) {
	for _, param := range *p {
		target[prefix+param.Key] = param.String()
	}
}

func (p *Params) CopyFromMap(source map[string]string, prefix string) error {
	for k, v := range source {
		if strings.HasPrefix(k, prefix) {
			err := p.Set(strings.TrimPrefix(k, prefix), v)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
		}
	}
	return nil
}

func (p Collection) Set(entry, key, val string) error {
	if _, ok := p[entry]; !ok {
		return fmt.Errorf("%q is not part of the collection", entry)
	}
	return p[entry].Set(key, val)
}

func (p Collection) CopyToMap(target map[string]string, prefix string) {
	for collectionKey, params := range p {
		params.CopyToMap(target, prefix+collectionKey+".")
	}
}

func (p Collection) CopyFromMap(source map[string]string, prefix string) error {
	for collectionKey, params := range p {
		err := params.CopyFromMap(source, prefix+collectionKey+".")
		if err != nil {
			return err
		}
	}
	return nil
}

// String is a member of the pflag.Value interface, which is used by cobra
func (p *Param) String() string {
	if p == nil {
		return ""
	}

	return p.value
}

// Set validates and sets the new value; it is also a member of the pflag.Value interface,
// which is used by cobra
func (p *Param) Set(val string) error {
	err := p.Validate(val)
	if err != nil {
		return err
	}
	p.value = val
	return nil
}

func (p *Param) AsFloat32() float32 {
	n, _ := strconv.ParseFloat(p.value, 32)
	return float32(n)
}

func (p *Param) AsFloat64() float64 {
	n, _ := strconv.ParseFloat(p.value, 64)
	return n
}

func (p *Param) AsInt() int {
	n, _ := strconv.ParseInt(p.value, 10, strconv.IntSize)
	return int(n)
}

func (p *Param) AsInt8() int8 {
	n, _ := strconv.ParseInt(p.value, 10, 8)
	return int8(n)
}

func (p *Param) AsInt16() int16 {
	n, _ := strconv.ParseInt(p.value, 10, 16)
	return int16(n)
}

func (p *Param) AsInt32() int32 {
	n, _ := strconv.ParseInt(p.value, 10, 32)
	return int32(n)
}

func (p *Param) AsInt64() int64 {
	n, _ := strconv.ParseInt(p.value, 10, 64)
	return int64(n)
}

func (p *Param) AsUint() uint {
	n, _ := strconv.ParseUint(p.value, 10, strconv.IntSize)
	return uint(n)
}

func (p *Param) AsUint8() uint8 {
	n, _ := strconv.ParseUint(p.value, 10, 8)
	return uint8(n)
}

func (p *Param) AsUint16() uint16 {
	n, _ := strconv.ParseUint(p.value, 10, 16)
	return uint16(n)
}

func (p *Param) AsUint32() uint32 {
	n, _ := strconv.ParseUint(p.value, 10, 32)
	return uint32(n)
}

func (p *Param) AsUint64() uint64 {
	n, _ := strconv.ParseUint(p.value, 10, 64)
	return uint64(n)
}

func (p *Param) AsString() string {
	return p.value
}

func (p *Param) AsStringSlice() []string {
	if p.value == "" {
		return []string{}
	}
	return strings.Split(p.value, ",")
}

func (p *Param) AsBool() bool {
	return strings.ToLower(p.value) == "true"
}

// AsUint16Slice is useful for handling network ports.
func (p *Param) AsUint16Slice() []uint16 {
	strs := p.AsStringSlice()
	out := make([]uint16, 0, len(strs))

	for _, entry := range strs {
		n, _ := strconv.ParseUint(entry, 10, 16)
		out = append(out, uint16(n))
	}

	return out
}

func (p *Param) AsUint64Slice() []uint64 {
	strs := p.AsStringSlice()
	out := make([]uint64, 0, len(strs))

	for _, entry := range strs {
		n, _ := strconv.ParseUint(entry, 10, 64)
		out = append(out, n)
	}

	return out
}

func (p *Param) AsInt64Slice() []int64 {
	strs := p.AsStringSlice()
	out := make([]int64, 0, len(strs))

	for _, entry := range strs {
		n, _ := strconv.ParseInt(entry, 10, 64)
		out = append(out, n)
	}

	return out
}
