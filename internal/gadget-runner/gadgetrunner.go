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
Package gadgetrunner handles initializing gadgets and installed operators before
handing them over to a specified runtime.
*/
package gadgetrunner

import (
	"context"
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/internal/logger"
	"github.com/inspektor-gadget/inspektor-gadget/internal/operators"
	"github.com/inspektor-gadget/inspektor-gadget/internal/parser"
	"github.com/inspektor-gadget/inspektor-gadget/internal/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

// GadgetRunner handles running gadgets by the gadget interface; it orchestrates the whole lifecycle of the gadget
// instance and communicates with gadget and runtime.
type GadgetRunner struct {
	ctx          context.Context
	id           string
	gadget       gadgets.Gadget
	gadgetParams *params.Params
	runtime      runtime.Runtime
	parser       parser.Parser
	operators    operators.Operators
	logger       logger.Logger
	result       []byte
	resultError  error
}

func NewGadgetRunner(
	ctx context.Context,
	id string,
	runtime runtime.Runtime,
	gadget gadgets.Gadget,
	parser parser.Parser,
	logger logger.Logger,
) *GadgetRunner {
	return &GadgetRunner{
		ctx:     ctx,
		id:      id,
		gadget:  gadget,
		runtime: runtime,
		parser:  parser,
		logger:  logger,
	}
}

func (r *GadgetRunner) ID() string {
	return r.id
}

func (r *GadgetRunner) Context() context.Context {
	return r.ctx
}

func (r *GadgetRunner) Parser() parser.Parser {
	return r.parser
}

func (r *GadgetRunner) Runtime() runtime.Runtime {
	return r.runtime
}

func (r *GadgetRunner) Gadget() gadgets.Gadget {
	return r.gadget
}

func (r *GadgetRunner) Operators() operators.Operators {
	return r.operators
}

func (r *GadgetRunner) Logger() logger.Logger {
	return r.logger
}

func (r *GadgetRunner) SetResult(result []byte, resultError error) {
	r.result = result
	r.resultError = resultError
}

func (r *GadgetRunner) GetResult() ([]byte, error) {
	return r.result, r.resultError
}

// RunGadget is the main function of GadgetRunner and controls the lifecycle of the gadget
func (r *GadgetRunner) RunGadget(
	runtimeParams *params.Params,
	operatorParamCollection params.Collection,
	operatorPerGadgetParamCollection params.Collection,
) error {
	r.operators = operators.GetOperatorsForGadget(r.gadget)
	err := r.operators.Init(operatorParamCollection)
	if err != nil {
		return fmt.Errorf("initializing operators: %w", err)
	}
	err = r.runtime.RunGadget(r, runtimeParams, operatorPerGadgetParamCollection)
	if err != nil {
		return fmt.Errorf("running gadget: %w", err)
	}
	return nil
}
