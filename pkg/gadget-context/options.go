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

package gadgetcontext

import (
	"context"
	"slices"
	"time"

	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

type contextKey string

const (
	remoteKey contextKey = "gadgetRemote"
	attachKey contextKey = "gadgetAttach"
)

type Option func(gadgetCtx *GadgetContext)

func WithLogger(logger logger.Logger) Option {
	return func(gadgetCtx *GadgetContext) {
		gadgetCtx.logger = logger
	}
}

func WithDataOperators(ops ...operators.DataOperator) Option {
	return func(gadgetCtx *GadgetContext) {
		gadgetCtx.dataOperators = slices.Clone(ops)
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(gadgetCtx *GadgetContext) {
		gadgetCtx.timeout = timeout
	}
}

func WithOrasReadonlyTarget(ociStore oras.ReadOnlyTarget) Option {
	return func(c *GadgetContext) {
		c.orasTarget = ociStore
	}
}

func WithAsRemoteCall(val bool) Option {
	return func(gadgetCtx *GadgetContext) {
		gadgetCtx.ctx = context.WithValue(gadgetCtx.ctx, remoteKey, val)
	}
}

func WithUseInstance(val bool) Option {
	return func(gadgetCtx *GadgetContext) {
		gadgetCtx.useInstance = val
	}
}

func WithID(id string) Option {
	return func(gadgetCtx *GadgetContext) {
		gadgetCtx.id = id
	}
}

func WithName(name string) Option {
	return func(gadgetCtx *GadgetContext) {
		gadgetCtx.name = name
	}
}
