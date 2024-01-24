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
