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

// Package apihelpers provides some helper functions for the API package; these were extracted into this package
// to avoid having additional dependencies on the API package itself
package apihelpers

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

func ParamDescsToParams(descs params.ParamDescs) (res api.Params) {
	if descs == nil {
		return
	}
	for _, desc := range descs {
		res = append(res, &api.Param{
			Key:            desc.Key,
			Description:    desc.Description,
			DefaultValue:   desc.DefaultValue,
			TypeHint:       string(desc.TypeHint),
			Title:          desc.Title,
			Alias:          desc.Alias,
			Tags:           desc.Tags,
			ValueHint:      string(desc.ValueHint),
			PossibleValues: desc.PossibleValues,
			IsMandatory:    desc.IsMandatory,
		})
	}
	return
}

func ParamToParamDesc(p *api.Param) *params.ParamDesc {
	return &params.ParamDesc{
		Key:            p.Key,
		Alias:          p.Alias,
		Title:          p.Title,
		DefaultValue:   p.DefaultValue,
		Description:    p.Description,
		IsMandatory:    p.IsMandatory,
		Tags:           p.Tags,
		Validator:      nil,
		TypeHint:       params.TypeHint(p.TypeHint),
		ValueHint:      params.ValueHint(p.ValueHint),
		PossibleValues: p.PossibleValues,
	}
}

func ToParamDescs(p api.Params) params.ParamDescs {
	res := make(params.ParamDescs, 0, len(p))
	for _, param := range p {
		res = append(res, ParamToParamDesc(param))
	}
	return res
}

func Validate(p api.Params, v api.ParamValues) error {
	for _, param := range p {
		if v[param.Key] == "" {
			continue
		}
		err := ParamToParamDesc(param).ToParam().Validate(v[param.Key])
		if err != nil {
			return err
		}
	}
	return nil
}

// GetStringValuesPerDataSource will separate a string and extract per-datasource values. It expects a string like
// `datasource1:value,datasource2:value` or `value` (datasource is optional - this will lead to an empty key)
func GetStringValuesPerDataSource(s string) (map[string]string, error) {
	if s == "" {
		return map[string]string{}, nil
	}
	res := make(map[string]string)
	for _, interval := range strings.Split(s, ",") {
		if interval == "" {
			continue
		}
		info := strings.SplitN(interval, ":", 2)
		dsName := ""
		val := info[0]
		if len(info) > 1 {
			dsName = info[0]
			val = info[1]
		}
		res[dsName] = val
	}
	// Check edge cases
	if _, ok := res[""]; ok {
		if len(res) > 1 {
			return nil, fmt.Errorf("mixed values with and without specifying data source")
		}
	}
	return res, nil
}

// GetIntValuesPerDataSource works like GetStringValuesPerDataSource, but will return int values instead
func GetIntValuesPerDataSource(s string) (map[string]int, error) {
	var err error
	m, err := GetStringValuesPerDataSource(s)
	if err != nil {
		return nil, fmt.Errorf("getting string values per data source: %w", err)
	}
	res := make(map[string]int, len(m))
	for k, v := range m {
		res[k], err = strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("converting %s to int: %w", v, err)
		}
	}
	return res, nil
}

// GetDurationValuesPerDataSource works like GetStringValuesPerDataSource, but will return time.Duration values instead
func GetDurationValuesPerDataSource(s string) (map[string]time.Duration, error) {
	var err error
	m, err := GetStringValuesPerDataSource(s)
	if err != nil {
		return nil, fmt.Errorf("getting string values per data source: %w", err)
	}
	res := make(map[string]time.Duration, len(m))
	for k, v := range m {
		res[k], err = time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("converting %s to duration: %w", v, err)
		}
	}
	return res, nil
}
