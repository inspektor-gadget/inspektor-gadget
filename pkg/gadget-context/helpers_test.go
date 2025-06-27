// Copyright 2025 The Inspektor Gadget authors
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

package gadgetcontext

import (
	"errors"
	"slices"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type fakeOperator struct {
	name     string
	priority int

	// list of methods that will fail
	fails []string

	// list of methods called which didn't return an error
	called *[]string
}

func (s *fakeOperator) Name() string {
	return s.name
}

func (s *fakeOperator) Init(*params.Params) error {
	return nil
}

func (s *fakeOperator) GlobalParams() api.Params {
	return nil
}

func (s *fakeOperator) InstanceParams() api.Params {
	return api.Params{
		{
			Key:          "foo",
			DefaultValue: "567",
		},
	}
}

func (s *fakeOperator) InstantiateDataOperator(operators.GadgetContext, api.ParamValues) (operators.DataOperatorInstance, error) {
	return s, nil
}

func (s *fakeOperator) Priority() int {
	return s.priority
}

func (s *fakeOperator) runMethod(name string) error {
	if slices.Contains(s.fails, name) {
		return errors.New("needs to fail")
	}

	if s.called != nil {
		*s.called = append(*s.called, s.name+"_"+name)
	}

	return nil
}

func (s *fakeOperator) PreStart(operators.GadgetContext) error {
	return s.runMethod("prestart")
}

func (s *fakeOperator) Start(operators.GadgetContext) error {
	return s.runMethod("start")
}

func (s *fakeOperator) Stop(operators.GadgetContext) error {
	return s.runMethod("stop")
}

func (s *fakeOperator) PostStop(operators.GadgetContext) error {
	return s.runMethod("poststop")
}

func (s *fakeOperator) Close(operators.GadgetContext) error {
	return s.runMethod("close")
}
