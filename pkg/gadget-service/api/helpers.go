// Copyright 2023-2025 The Inspektor Gadget authors
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

package api

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type (
	Params      []*Param
	ParamValues map[string]string
)

var (
	idRegex   = regexp.MustCompile("^[a-f0-9]{32}$")
	nameRegex = regexp.MustCompile("^[a-z0-9-_]{1,32}$")
)

func IsValidInstanceID(id string) bool {
	return idRegex.MatchString(id)
}

func IsValidInstanceName(name string) bool {
	return nameRegex.MatchString(name)
}

func NewInstanceID() (string, error) {
	id := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, id)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(id), nil
}

func ParseSocketAddress(addr string) (string, string, error) {
	socketURL, err := url.Parse(addr)
	if err != nil {
		return "", "", fmt.Errorf("invalid socket address %q: %w", addr, err)
	}
	var socketPath string
	socketType := socketURL.Scheme
	switch socketType {
	default:
		return "", "", fmt.Errorf("invalid type %q for socket; please use 'unix' or 'tcp'", socketType)
	case "unix":
		socketPath = socketURL.Path
	case "tcp":
		if socketURL.Host == "" {
			return "", "", fmt.Errorf("invalid tcp socket address '%s'. Use something like 'tcp://127.0.0.1:1234'", addr)
		}
		socketPath = socketURL.Host
	}
	return socketType, socketPath, nil
}

func (p *Param) AddPrefix(prefix string) *Param {
	p.Prefix = prefix + "." + p.Prefix
	return p
}

func (pv Params) AddPrefix(prefix string) Params {
	for _, p := range pv {
		p.AddPrefix(prefix)
	}
	return pv
}

func (pv ParamValues) ExtractPrefixedValues(prefix string) ParamValues {
	prefix = prefix + "."
	res := make(ParamValues)
	for k, v := range pv {
		if strings.HasPrefix(k, prefix) {
			res[strings.TrimPrefix(k, prefix)] = v
		}
	}
	return res
}

func SplitStringWithEscape(s string, sep rune) []string {
	var result []string
	var part string
	var escape bool
	for _, c := range s {
		if escape {
			escape = false
			part += string(c)
			continue
		}
		switch c {
		case '\\':
			escape = true
		case sep:
			result = append(result, part)
			part = ""
		default:
			part += string(c)
		}
	}
	if part != "" {
		result = append(result, part)
	}
	return result
}

func (pv ParamValues) Unmarshal(target any) {
}

// Validate will validate constraints and set default values; it will return a new validated instance of ParamValues
// only containing values for the params given.
func (pv ParamValues) Validate(params Params) (ParamValues, error) {
	var err error
	values := make(ParamValues, len(pv))
	for _, param := range params {
		v := pv[param.Key]

		// if empty, set to default
		if v == "" {
			v = param.DefaultValue
		}

		values[param.Key] = v

		// Verify valid value if PossibleValues is set
		if len(param.PossibleValues) > 0 {
			if !slices.Contains(param.PossibleValues, v) {
				err = errors.Join(err, fmt.Errorf("expected value for %q to be one of %v", param.Key, param.PossibleValues))
				continue
			}
		}

		switch param.TypeHint {
		case TypeBool:
			_, err = strconv.ParseBool(v)
			if err != nil {
				err = errors.Join(err, fmt.Errorf("expected value for %q to be a boolean", param.Key))
				continue
			}
		case TypeInt:
			_, err = strconv.ParseInt(v, 10, 64)
			if err != nil {
				err = errors.Join(err, fmt.Errorf("expected value for %q to be an integer", param.Key))
				continue
			}
		case TypeDuration:
			_, err = time.ParseDuration(v)
			if err != nil {
				err = errors.Join(err, fmt.Errorf("expected value for %q to be a duration", param.Key))
				continue
			}
		case TypeInt8:
			_, err = strconv.ParseInt(v, 10, 8)
			if err != nil {
				err = errors.Join(err, fmt.Errorf("expected value for %q to be an 8-bit integer", param.Key))
				continue
			}
		case TypeInt16:
			_, err = strconv.ParseInt(v, 10, 16)
			if err != nil {
				err = errors.Join(err, fmt.Errorf("expected value for %q to be a 16-bit integer", param.Key))
				continue
			}
		case TypeInt32:
			_, err = strconv.ParseInt(v, 10, 32)
			if err != nil {
				err = errors.Join(err, fmt.Errorf("expected value for %q to be a 32-bit integer", param.Key))
				continue
			}
		case TypeInt64:
			_, err = strconv.ParseInt(v, 10, 64)
			if err != nil {
				err = errors.Join(err, fmt.Errorf("expected value for %q to be a 64-bit integer", param.Key))
				continue
			}
		case TypeUint8:
			_, err = strconv.ParseUint(v, 10, 8)
			if err != nil {
				err = errors.Join(err, fmt.Errorf("expected value for %q to be an 8-bit integer", param.Key))
				continue
			}
		case TypeUint16:
			_, err = strconv.ParseUint(v, 10, 16)
			if err != nil {
				err = errors.Join(err, fmt.Errorf("expected value for %q to be a 16-bit integer", param.Key))
				continue
			}
		case TypeUint32:
			_, err = strconv.ParseUint(v, 10, 32)
			if err != nil {
				err = errors.Join(err, fmt.Errorf("expected value for %q to be a 32-bit integer", param.Key))
				continue
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return values, nil
}

func (pv ParamValues) String(key string) string {
	return pv[key]
}

func (pv ParamValues) Int(key string) int {
	v, _ := strconv.Atoi(pv[key])
	return v
}

func (pv ParamValues) Int64(key string) int64 {
	v, _ := strconv.ParseInt(pv[key], 10, 64)
	return v
}

func (pv ParamValues) Int32(key string) int32 {
	v, _ := strconv.ParseInt(pv[key], 10, 32)
	return int32(v)
}

func (pv ParamValues) Int16(key string) int16 {
	v, _ := strconv.ParseInt(pv[key], 10, 16)
	return int16(v)
}

func (pv ParamValues) Int8(key string) int8 {
	v, _ := strconv.ParseInt(pv[key], 10, 8)
	return int8(v)
}

func (pv ParamValues) Uint64(key string) uint64 {
	v, _ := strconv.ParseUint(pv[key], 10, 64)
	return v
}

func (pv ParamValues) Uint32(key string) uint32 {
	v, _ := strconv.ParseUint(pv[key], 10, 32)
	return uint32(v)
}

func (pv ParamValues) Uint16(key string) uint16 {
	v, _ := strconv.ParseUint(pv[key], 10, 16)
	return uint16(v)
}

func (pv ParamValues) Uint8(key string) uint8 {
	v, _ := strconv.ParseUint(pv[key], 10, 8)
	return uint8(v)
}

func (pv ParamValues) Bool(key string) bool {
	return pv[key] == "true"
}

func (pv ParamValues) Float32(key string) float32 {
	v, _ := strconv.ParseFloat(pv[key], 32)
	return float32(v)
}

func (pv ParamValues) Float64(key string) float64 {
	v, _ := strconv.ParseFloat(pv[key], 64)
	return v
}

func (pv ParamValues) Duration(key string) time.Duration {
	v, _ := time.ParseDuration(pv[key])
	return v
}

func (pv ParamValues) StringSlice(key string) []string {
	return SplitStringWithEscape(key, ',')
}
