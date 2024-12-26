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

package simple

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type simpleOperator struct {
	name       string
	onInit     func(gadgetCtx operators.GadgetContext) error
	onStart    func(gadgetCtx operators.GadgetContext) error
	onStop     func(gadgetCtx operators.GadgetContext) error
	onPreStart func(gadgetCtx operators.GadgetContext) error
	onPostStop func(gadgetCtx operators.GadgetContext) error
	priority   int
}

func New(name string, options ...Option) operators.DataOperator {
	s := &simpleOperator{
		name: name,
	}
	for _, o := range options {
		o(s)
	}
	return s
}

func (s *simpleOperator) Name() string {
	return s.name
}

func (s *simpleOperator) Init(params *params.Params) error {
	return nil
}

func (s *simpleOperator) GlobalParams() api.Params {
	return nil
}

func (s *simpleOperator) InstanceParams() api.Params {
	return nil
}

func (s *simpleOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	if s.onInit != nil {
		err := s.onInit(gadgetCtx)
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *simpleOperator) Priority() int {
	return s.priority
}

func (s *simpleOperator) Start(gadgetCtx operators.GadgetContext) error {
	if s.onStart != nil {
		return s.onStart(gadgetCtx)
	}
	return nil
}

func (s *simpleOperator) Stop(gadgetCtx operators.GadgetContext) error {
	if s.onStop != nil {
		return s.onStop(gadgetCtx)
	}
	return nil
}

func (s *simpleOperator) Close(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (s *simpleOperator) PreStart(gadgetCtx operators.GadgetContext) error {
	if s.onPreStart != nil {
		return s.onPreStart(gadgetCtx)
	}
	return nil
}

func (s *simpleOperator) PostStop(gadgetCtx operators.GadgetContext) error {
	if s.onPostStop != nil {
		return s.onPostStop(gadgetCtx)
	}
	return nil
}
