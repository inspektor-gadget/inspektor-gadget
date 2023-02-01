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
Package gadgetcontext handles initializing gadgets and installed operators before
handing them over to a specified runtime.
*/
package gadgetcontext

import (
	"context"

	"github.com/inspektor-gadget/inspektor-gadget/internal/logger"
	"github.com/inspektor-gadget/inspektor-gadget/internal/operators"
	"github.com/inspektor-gadget/inspektor-gadget/internal/parser"
	"github.com/inspektor-gadget/inspektor-gadget/internal/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

// GadgetContext handles running gadgets by the gadget interface; it orchestrates the whole lifecycle of the gadget
// instance and communicates with gadget and runtime.
type GadgetContext struct {
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

func New(
	ctx context.Context,
	id string,
	runtime runtime.Runtime,
	gadget gadgets.Gadget,
	gadgetParams *params.Params,
	parser parser.Parser,
	logger logger.Logger,
) *GadgetContext {
	return &GadgetContext{
		ctx:          ctx,
		id:           id,
		runtime:      runtime,
		gadget:       gadget,
		gadgetParams: gadgetParams,
		parser:       parser,
		logger:       logger,
		operators:    operators.GetOperatorsForGadget(gadget),
	}
}

func (r *GadgetContext) ID() string {
	return r.id
}

func (r *GadgetContext) Context() context.Context {
	return r.ctx
}

func (r *GadgetContext) Parser() parser.Parser {
	return r.parser
}

func (r *GadgetContext) Runtime() runtime.Runtime {
	return r.runtime
}

func (r *GadgetContext) Gadget() gadgets.Gadget {
	return r.gadget
}

func (r *GadgetContext) Operators() operators.Operators {
	return r.operators
}

func (r *GadgetContext) Logger() logger.Logger {
	return r.logger
}

func (r *GadgetContext) GadgetParams() *params.Params {
	return r.gadgetParams
}
