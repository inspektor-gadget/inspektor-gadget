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

package tracer

import (
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
	igprometheus "github.com/inspektor-gadget/inspektor-gadget/pkg/prometheus"
)

const (
	ParamConfig = "config"
)

type fakeEvent struct{}

type GadgetDesc struct{}

func (g *GadgetDesc) Name() string {
	return "prometheus"
}

func (g *GadgetDesc) Category() string {
	return gadgets.CategoryNone
}

func (g *GadgetDesc) Type() gadgets.GadgetType {
	return gadgets.TypeOther
}

func (g *GadgetDesc) Description() string {
	return "Expose metrics using prometheus"
}

func (g *GadgetDesc) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:         ParamConfig,
			Title:       "config",
			Description: "Metrics configuration (prefix with @ to load from a file)",
			IsMandatory: true,
			TypeHint:    params.TypeBytes,
			Validator: func(value string) error {
				_, err := igprometheus.ParseConfig([]byte(value))
				return err
			},
		},
	}
}

func (g *GadgetDesc) EventPrototype() any {
	return &fakeEvent{}
}

func (g *GadgetDesc) Parser() parser.Parser {
	return nil
}

func init() {
	gadgetregistry.Register(&GadgetDesc{})
}
