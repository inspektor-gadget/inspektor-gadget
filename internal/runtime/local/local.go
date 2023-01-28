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

package local

import (
	"errors"

	"github.com/inspektor-gadget/inspektor-gadget/internal/runtime"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type localRuntime struct {
	rc []*containerutils.RuntimeConfig

	params *params.Params
}

func (lr *localRuntime) Init() error {
	return nil
}

func (lr *localRuntime) DeInit() error {
	return nil
}

func (lr *localRuntime) RunGadget(runner runtime.Runner) error {
	logger := runner.Logger()

	logger.Debugf("running with local runtime")

	gadgetInst, ok := runner.Gadget().(gadgets.GadgetInstantiate)
	if !ok {
		return errors.New("gadget not instantiable")
	}

	if lr.params != nil {
		logger.Debugf("> Params: %+v", lr.params.ParamMap())
	} else {
		logger.Debugf("> Params: nil")
	}

	return lr.runGadget(runner, gadgetInst)
}

func (lr *localRuntime) Params() *params.Params {
	return lr.params
}

func NewRuntime() *localRuntime {
	return &localRuntime{
		// NOTE: In case of need, define params here
	}
}
