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

import "github.com/inspektor-gadget/inspektor-gadget/pkg/operators"

type Option func(op *simpleOperator)

func OnInit(cb func(gadgetCtx operators.GadgetContext) error) Option {
	return func(op *simpleOperator) {
		op.onInit = cb
	}
}

func OnStart(cb func(gadgetCtx operators.GadgetContext) error) Option {
	return func(op *simpleOperator) {
		op.onStart = cb
	}
}

func OnStop(cb func(gadgetCtx operators.GadgetContext) error) Option {
	return func(op *simpleOperator) {
		op.onStop = cb
	}
}

func WithPriority(priority int) Option {
	return func(op *simpleOperator) {
		op.priority = priority
	}
}
