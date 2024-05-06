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

package wasm

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

const (
	wasmObjectMediaType = "application/vnd.gadget.wasm.program.v1+binary"
)

type wasmOperator struct{}

func (w *wasmOperator) Name() string {
	return "wasm"
}

func (w *wasmOperator) Description() string {
	return "handles wasm programs"
}

func (w *wasmOperator) InstantiateImageOperator(
	gadgetCtx operators.GadgetContext,
	target oras.ReadOnlyTarget,
	desc ocispec.Descriptor,
	paramValues api.ParamValues,
) (
	operators.ImageOperatorInstance, error,
) {
	return &wasmOperatorInstance{
		target:    target,
		desc:      desc,
		gadgetCtx: gadgetCtx,
		logger:    gadgetCtx.Logger(),
	}, nil
}

type wasmOperatorInstance struct {
	target    oras.ReadOnlyTarget
	desc      ocispec.Descriptor
	rt        wazero.Runtime
	gadgetCtx operators.GadgetContext
	mod       wapi.Module

	logger logger.Logger

	// malloc function exported by the guest
	guestMalloc wapi.Function
}

func (i *wasmOperatorInstance) Name() string {
	return "wasm"
}

func (i *wasmOperatorInstance) Prepare(gadgetCtx operators.GadgetContext) error {
	err := i.init(gadgetCtx)
	if err != nil {
		return fmt.Errorf("initializing wasm: %w", err)
	}

	err = i.callGuestFunction(gadgetCtx.Context(), "init")
	if err != nil {
		return fmt.Errorf("initializing wasm guest: %w", err)
	}

	return nil
}

func (i *wasmOperatorInstance) ExtraParams(gadgetCtx operators.GadgetContext) api.Params {
	return nil
}

func (i *wasmOperatorInstance) init(gadgetCtx operators.GadgetContext) error {
	ctx := gadgetCtx.Context()
	rtConfig := wazero.NewRuntimeConfig().
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(256) // 16MB (64KB per page)
	i.rt = wazero.NewRuntimeWithConfig(ctx, rtConfig)

	env := i.rt.NewHostModuleBuilder("env")

	if _, err := env.Instantiate(ctx); err != nil {
		return fmt.Errorf("instantiating host module: %w", err)
	}

	if _, err := wasi_snapshot_preview1.Instantiate(ctx, i.rt); err != nil {
		return fmt.Errorf("instantiating WASI: %w", err)
	}

	reader, err := oci.GetContentFromDescriptor(ctx, i.target, i.desc)
	if err != nil {
		return fmt.Errorf("getting wasm program: %w", err)
	}

	wasmProgram, err := io.ReadAll(reader)
	if err != nil {
		reader.Close()
		return fmt.Errorf("reading wasm program: %w", err)
	}
	reader.Close()

	config := wazero.NewModuleConfig()
	mod, err := i.rt.InstantiateWithConfig(ctx, wasmProgram, config)
	if err != nil {
		return fmt.Errorf("instantiating wasm: %w", err)
	}
	i.mod = mod

	// We need to call malloc on the guest to pass strings
	i.guestMalloc = mod.ExportedFunction("malloc")
	if i.guestMalloc == nil {
		return errors.New("wasm module doesn't export malloc")
	}

	return err
}

func (i *wasmOperatorInstance) callGuestFunction(ctx context.Context, name string) error {
	fn := i.mod.ExportedFunction(name)
	if fn == nil {
		return nil
	}
	ret, err := fn.Call(ctx)
	if err != nil {
		return fmt.Errorf("calling %s: %w", name, err)
	}
	if ret[0] != 0 {
		return fmt.Errorf("%s failed", name)
	}
	return nil
}

func (i *wasmOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return i.callGuestFunction(gadgetCtx.Context(), "start")
}

func (i *wasmOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	// We need a new context in here, as gadgetCtx has already been cancelled
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err := i.callGuestFunction(ctx, "stop")

	i.rt.Close(gadgetCtx.Context())
	i.mod.Close(gadgetCtx.Context())

	return err
}

func init() {
	operators.RegisterOperatorForMediaType(wasmObjectMediaType, &wasmOperator{})
}
