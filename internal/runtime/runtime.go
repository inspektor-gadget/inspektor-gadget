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

package runtime

import (
	"context"

	"github.com/inspektor-gadget/inspektor-gadget/internal/logger"
	"github.com/inspektor-gadget/inspektor-gadget/internal/operators"
	"github.com/inspektor-gadget/inspektor-gadget/internal/parser"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type Runner interface {
	ID() string
	Parser() parser.Parser
	Runtime() Runtime
	Gadget() gadgets.Gadget
	Context() context.Context
	Operators() operators.Operators
	Logger() logger.Logger
	SetResult([]byte, error)
	GetResult() ([]byte, error)
}

// Runtime is the interface for gadget runtimes like kubectl-gadget, local-gadget
// or gadgettracermgr
type Runtime interface {
	Init(*params.Params) error
	DeInit() error
	Params() params.ParamDescs
	RunGadget(
		runner Runner,
		runtimeParams *params.Params,
		operatorPerGadgetParamCollection params.Collection,
	) error
}
