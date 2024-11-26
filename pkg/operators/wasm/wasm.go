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

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"
	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	syscallhelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/syscall-helpers"
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

	// Indicates the handle encodes a member of a data array as index << 16 | arrayHandle
	dataArrayHandleFlag = uint32(1 << 31)
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
		createdMap:  map[uint32]struct{}{},
	}

	if err := instance.init(gadgetCtx, target, desc); err != nil {
		instance.close(gadgetCtx)
		return nil, fmt.Errorf("initializing wasm: %w", err)
	}

	if configVar, ok := gadgetCtx.GetVar("config"); ok {
		instance.config, _ = configVar.(*viper.Viper)
	}

	if instance.config != nil {
		extraParams := map[string]*api.Param{}
		err := instance.config.UnmarshalKey("params.wasm", &extraParams)
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
	ctx       context.Context
	cancel    func()
	rt        wazero.Runtime
	gadgetCtx operators.GadgetContext
	mod       wapi.Module

	logger logger.Logger

	// This mutex ensures dataSourceCallback() is never called in parallel, see:
	// https://github.com/tetratelabs/wazero/blob/610c202ec48f3a7c729f2bf11707330127ab3689/api/wasm.go#L378-L381
	dataSourceCallbackLock sync.Mutex
	dataSourceCallback     wapi.Function

	// Golang objects are exposed to the wasm module by using a handleID
	handleMap       map[uint32]any
	lastHandleIndex uint32
	handleLock      sync.RWMutex

	config *viper.Viper

	extraParams api.Params
	paramValues map[string]string

	createdMap      map[uint32]struct{}
	createdMapMutex sync.RWMutex

	syscallsDeclarations map[string]syscallhelpers.SyscallDeclaration
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

	igModuleBuilder := i.rt.NewHostModuleBuilder("ig")

	i.addLogFuncs(igModuleBuilder)
	i.addDataSourceFuncs(igModuleBuilder)
	i.addFieldFuncs(igModuleBuilder)
	i.addParamsFuncs(igModuleBuilder)
	i.addConfigFuncs(igModuleBuilder)
	i.addMapFuncs(igModuleBuilder)
	i.addHandleFuncs(igModuleBuilder)
	i.addSyscallsDeclarationsFuncs(igModuleBuilder)
	i.addPerfFuncs(igModuleBuilder)
	i.addKallsymsFuncs(igModuleBuilder)

	if _, err := igModuleBuilder.Instantiate(ctx); err != nil {
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
	reader.Close()
	if err != nil {
		return fmt.Errorf("reading wasm program: %w", err)
	}

	config := wazero.NewModuleConfig().WithStartFunctions("_initialize")
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

func (i *wasmOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	// We're creating a new context here that gets cancelled when Stop() is called; it is important to know
	// that gadgetInit uses the gadgetContext instead, which will be cancelled whenever the gadgetCtx is cancelled
	// (and so are any callbacks registered in gadgetInit)
	i.ctx, i.cancel = context.WithCancel(context.Background())
	return i.callGuestFunction(i.ctx, "gadgetPreStart")
}

func (i *wasmOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return i.callGuestFunction(i.ctx, "gadgetStart")
}

func (i *wasmOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	i.cancel()
	defer func() {
		i.handleLock.Lock()
		i.handleMap = nil
		i.handleLock.Unlock()

		i.createdMapMutex.Lock()
		i.createdMap = nil
		i.createdMapMutex.Unlock()
	}()

	// We need a new context in here, as gadgetCtx has already been cancelled
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*1500)
	defer cancel()

	err := i.callGuestFunction(ctx, "gadgetStop")

	// TODO: This should be called directly from the outside, in case prepare or
	// start fails, this won't be called.
	i.close(gadgetCtx)

	return err
}

func (i *wasmOperatorInstance) PostStop(gadgetCtx operators.GadgetContext) error {
	// TODO: reenable it when
	// https://github.com/inspektor-gadget/inspektor-gadget/pull/3778 is merged
	// return i.callGuestFunction(gadgetCtx.Context(), "gadgetPostStop")
	return nil
}

func (i *wasmOperatorInstance) close(gadgetCtx operators.GadgetContext) error {
	var errs []error

	if i.rt != nil {
		errs = append(errs, i.rt.Close(gadgetCtx.Context()))
	}
	if i.mod != nil {
		errs = append(errs, i.mod.Close(gadgetCtx.Context()))
	}

	return errors.Join(errs...)
}

func init() {
	operators.RegisterOperatorForMediaType(wasmObjectMediaType, &wasmOperator{})
}
