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

//go:build !withoutebpf

package tracer

import (
	"context"
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

type wasmHostCallContextKeyT string

var wasmHostCallContextKey = wasmHostCallContextKeyT("event")

type wasmHostCallContext struct {
	ctx context.Context

	drop bool
}

func (t *Tracer) newWasmHost(l logger.Logger) func(ctx context.Context, binding, namespace, operation string, payload []byte) ([]byte, error) {
	return func(ctx context.Context, binding, namespace, operation string, payload []byte) ([]byte, error) {
		cookie := ctx.Value(wasmHostCallContextKey).(*wasmHostCallContext)
		switch binding {
		case "ig":
			switch namespace {
			case "event":
				switch operation {
				case "drop":
					cookie.drop = true
					return nil, nil
				}
			}
		}
		l.Warnf("HostCall for %s/%s/%s not implemented", binding, namespace, operation)

		return nil, fmt.Errorf("HostCall for %s/%s/%s not implemented", binding, namespace, operation)
	}
}

func (t *Tracer) newHostCallContext() context.Context {
	return context.WithValue(
		t.gadgetCtx.Context(),
		wasmHostCallContextKey,
		&wasmHostCallContext{},
	)
}
