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
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"
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
	// Maximum number of handles a gadget can have opened at the same time
	maxHandles = 4 * 1024

	// Current version of this API. This is used to check that the wasm module
	// uses the same version.
	apiVersion = 1
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
	instance := &wasmOperatorInstance{
		gadgetCtx:   gadgetCtx,
		handleMap:   map[uint32]any{},
		logger:      gadgetCtx.Logger(),
		paramValues: paramValues,
	}

	if err := instance.init(gadgetCtx, target, desc); err != nil {
		instance.close(gadgetCtx)
		return nil, fmt.Errorf("initializing wasm: %w", err)
	}

	var config *viper.Viper
	if configVar, ok := gadgetCtx.GetVar("config"); ok {
		config, _ = configVar.(*viper.Viper)
	}

	if config != nil {
		extraParams := map[string]*api.Param{}
		err := config.UnmarshalKey("params.wasm", &extraParams)
		if err != nil {
			return nil, fmt.Errorf("unmarshalling extra params: %w", err)
		}

		for _, v := range extraParams {
			instance.extraParams = append(instance.extraParams, v)
		}
	}

	return instance, nil
}

type wasmOperatorInstance struct {
	rt        wazero.Runtime
	gadgetCtx operators.GadgetContext
	mod       wapi.Module

	logger logger.Logger

	// malloc function exported by the guest
	guestMalloc wapi.Function

	dataSourceCallback wapi.Function

	// Golang objects are exposed to the wasm module by using a handleID
	handleMap       map[uint32]any
	lastHandleIndex uint32
	handleLock      sync.RWMutex

	extraParams api.Params
	paramValues map[string]string
}

func (i *wasmOperatorInstance) Name() string {
	return "wasm"
}

func (i *wasmOperatorInstance) Prepare(gadgetCtx operators.GadgetContext) error {
	if err := i.callGuestFunction(gadgetCtx.Context(), "gadgetInit"); err != nil {
		return fmt.Errorf("initializing wasm guest: %w", err)
	}

	return nil
}

func (i *wasmOperatorInstance) ExtraParams(gadgetCtx operators.GadgetContext) api.Params {
	return i.extraParams
}

func (i *wasmOperatorInstance) addHandle(obj any) uint32 {
	if obj == nil {
		return 0
	}

	i.handleLock.Lock()
	defer i.handleLock.Unlock()

	if len(i.handleMap) == maxHandles {
		i.logger.Warnf("too many open handles")
		return 0
	}

	handleIndex := i.lastHandleIndex
	handleIndex++

	// look for a free index in the map
	for {
		// zero is reserved, handle overflow
		if handleIndex == 0 {
			handleIndex++
		}

		if _, ok := i.handleMap[handleIndex]; !ok {
			// register new entry
			i.handleMap[handleIndex] = obj
			i.lastHandleIndex = handleIndex
			return handleIndex
		}
		handleIndex++
	}
}

// getHandleTyped returns the handle with the given ID, casted to the given type.
// It can't be implemented as a generic method because it's not supported by Go yet.
func getHandle[T any](i *wasmOperatorInstance, handleID uint32) (T, bool) {
	i.handleLock.RLock()
	defer i.handleLock.RUnlock()

	var empty T // zero value

	val, ok := i.handleMap[handleID]
	if !ok {
		i.logger.Warnf("handle %d not found", handleID)
		return empty, false
	}

	t, ok := val.(T)
	if !ok {
		i.logger.Warnf("bad handle type for %d", handleID)
		return empty, false
	}

	return t, true
}

func (i *wasmOperatorInstance) delHandle(handleID uint32) {
	i.handleLock.Lock()
	defer i.handleLock.Unlock()
	delete(i.handleMap, handleID)
}

func (i *wasmOperatorInstance) init(
	gadgetCtx operators.GadgetContext,
	target oras.ReadOnlyTarget,
	desc ocispec.Descriptor,
) error {
	ctx := gadgetCtx.Context()
	rtConfig := wazero.NewRuntimeConfig().
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(256) // 16MB (64KB per page)
	i.rt = wazero.NewRuntimeWithConfig(ctx, rtConfig)

	env := i.rt.NewHostModuleBuilder("env")

	i.addLogFuncs(env)
	i.addDataSourceFuncs(env)
	i.addFieldFuncs(env)
	i.addParamsFuncs(env)

	if _, err := env.Instantiate(ctx); err != nil {
		return fmt.Errorf("instantiating host module: %w", err)
	}

	if _, err := wasi_snapshot_preview1.Instantiate(ctx, i.rt); err != nil {
		return fmt.Errorf("instantiating WASI: %w", err)
	}

	reader, err := oci.GetContentFromDescriptor(ctx, target, desc)
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

	versionF := mod.ExportedFunction("gadgetAPIVersion")
	if versionF == nil {
		return errors.New("wasm module doesn't export gadgetAPIVersion")
	}

	ret, err := versionF.Call(ctx)
	if err != nil {
		return fmt.Errorf("calling version: %w", err)
	}

	if len(ret) != 1 {
		return errors.New("version returned wrong number of values")
	}

	if ret[0] != apiVersion {
		return fmt.Errorf("unsupported gadget API version: %d, expected: %d", ret[0], apiVersion)
	}

	// We need to call malloc on the guest to pass strings
	i.guestMalloc = mod.ExportedFunction("malloc")
	if i.guestMalloc == nil {
		return errors.New("wasm module doesn't export malloc")
	}

	i.dataSourceCallback = mod.ExportedFunction("dataSourceCallback")

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
	return i.callGuestFunction(gadgetCtx.Context(), "gadgetStart")
}

func (i *wasmOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	defer func() {
		i.handleLock.Lock()
		i.handleMap = nil
		i.handleLock.Unlock()
	}()

	// We need a new context in here, as gadgetCtx has already been cancelled
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err := i.callGuestFunction(ctx, "gadgetStop")

	// TODO: This should be called directly from the outside, in case prepare or
	// start fails, this won't be called.
	i.close(gadgetCtx)

	return err
}

func (i *wasmOperatorInstance) close(gadgetCtx operators.GadgetContext) error {
	var result error

	if i.rt != nil {
		if err := i.rt.Close(gadgetCtx.Context()); err != nil {
			result = multierror.Append(result, err)
		}
	}
	if i.mod != nil {
		if err := i.mod.Close(gadgetCtx.Context()); err != nil {
			result = multierror.Append(result, err)
		}
	}

	return result
}

func init() {
	operators.RegisterOperatorForMediaType(wasmObjectMediaType, &wasmOperator{})
}
