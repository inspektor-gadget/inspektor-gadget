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
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

// GadgetContext handles running gadgets by the gadget interface; it orchestrates the whole lifecycle of the gadget
// instance and communicates with gadget and runtime.
type GadgetContext struct {
	ctx                      context.Context
	id                       string
	gadget                   gadgets.GadgetDesc
	gadgetParams             *params.Params
	runtime                  runtime.Runtime
	parser                   parser.Parser
	operators                operators.Operators
	operatorsParamCollection params.Collection
	logger                   logger.Logger
	result                   []byte
	resultError              error
	timeout                  time.Duration
}

func New(
	ctx context.Context,
	id string,
	runtime runtime.Runtime,
	gadget gadgets.GadgetDesc,
	gadgetParams *params.Params,
	operatorsParamCollection params.Collection,
	parser parser.Parser,
	logger logger.Logger,
	timeout time.Duration,
) *GadgetContext {
	return &GadgetContext{
		ctx:                      ctx,
		id:                       id,
		runtime:                  runtime,
		gadget:                   gadget,
		gadgetParams:             gadgetParams,
		parser:                   parser,
		logger:                   logger,
		operators:                operators.GetOperatorsForGadget(gadget),
		operatorsParamCollection: operatorsParamCollection,
		timeout:                  timeout,
	}
}

func (c *GadgetContext) ID() string {
	return c.id
}

func (c *GadgetContext) Context() context.Context {
	return c.ctx
}

func (c *GadgetContext) Parser() parser.Parser {
	return c.parser
}

func (c *GadgetContext) Runtime() runtime.Runtime {
	return c.runtime
}

func (c *GadgetContext) GadgetDesc() gadgets.GadgetDesc {
	return c.gadget
}

func (c *GadgetContext) Operators() operators.Operators {
	return c.operators
}

func (c *GadgetContext) Logger() logger.Logger {
	return c.logger
}

func (c *GadgetContext) GadgetParams() *params.Params {
	return c.gadgetParams
}

func (c *GadgetContext) OperatorsParamCollection() params.Collection {
	return c.operatorsParamCollection
}

func (c *GadgetContext) Timeout() time.Duration {
	return c.timeout
}

func WithTimeoutOrCancel(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout == 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func WaitForTimeoutOrDone(c gadgets.GadgetContext) {
	ctx, cancel := WithTimeoutOrCancel(c.Context(), c.Timeout())
	defer cancel()
	<-ctx.Done()
}
