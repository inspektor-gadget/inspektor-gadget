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
	"fmt"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	ParamGlobalAllowHostFS = "wasm-global-allow-host-fs" // TODO
	ParamAllowHostFS       = "wasm-allow-host-fs"
)

//go:embed test/prog.wasm
var wasmBinary []byte

type wasmOperator struct{}

func (w *wasmOperator) Name() string {
	return "wasm"
}

func (w *wasmOperator) Init(params *params.Params) error {
	return nil
}

func (w *wasmOperator) GlobalParams() api.Params {
	return nil
}

func (w *wasmOperator) InstanceParams() api.Params {
	return api.Params{
		{
			Key:          ParamAllowHostFS,
			Description:  "allow access to host filesystem",
			DefaultValue: "false",
			TypeHint:     api.TypeBool,
		},
	}
}

func (w *wasmOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	inst := &wasmOperatorInstance{
		gadgetCtx:   gadgetCtx,
		memMap:      map[uint32]any{},
		allowHostFS: instanceParamValues[ParamAllowHostFS] == "true",
	}
	err := inst.init(gadgetCtx)
	if err != nil {
		return nil, fmt.Errorf("initializing wasm: %w", err)
	}
	err = inst.Init(gadgetCtx)
	if err != nil {
		return nil, fmt.Errorf("initializing wasm guest: %w", err)
	}
	return inst, nil
}

func (w *wasmOperator) Priority() int {
	return 0
}

type wasmOperatorInstance struct {
	rt          wazero.Runtime
	gadgetCtx   operators.GadgetContext
	mod         wapi.Module
	memMap      map[uint32]any
	memCtr      uint32
	memLock     sync.RWMutex
	lock        sync.Mutex
	allowHostFS bool
}

func (i *wasmOperatorInstance) addToMemMap(obj any) uint32 {
	i.memLock.Lock()
	defer i.memLock.Unlock()
	i.memCtr++
	if i.memCtr == 0 { // 0 is reserved
		i.memCtr++
	}
	xctr := 0
	for {
		if xctr > 1<<32 {
			// exhausted; TODO: report somehow
			return 0
		}
		if _, ok := i.memMap[i.memCtr]; !ok {
			// register new entry
			i.memMap[i.memCtr] = obj
			return i.memCtr
		}
		xctr++
	}
}

func (i *wasmOperatorInstance) getFromMemMap(entry uint32) any {
	i.memLock.RLock()
	defer i.memLock.RUnlock()
	return i.memMap[entry]
}

func (i *wasmOperatorInstance) freeFromMemMap(entry uint32) {
	i.memLock.Lock()
	defer i.memLock.Unlock()
	delete(i.memMap, entry)
}

func (i *wasmOperatorInstance) init(gadgetCtx operators.GadgetContext) error {
	ctx := gadgetCtx.Context()
	i.rt = wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	// TODO: add mem limits etc

	config := wazero.NewModuleConfig().
		WithStdout(os.Stdout).WithStderr(os.Stderr).WithSysWalltime()

	gadgetCtx.Logger()

	if i.allowHostFS {
		config = config.WithFS(os.DirFS("/"))
	}

	env := i.rt.NewHostModuleBuilder("env")
	env.NewFunctionBuilder().
		WithGoModuleFunction(wapi.GoModuleFunc(func(ctx context.Context, m wapi.Module, stack []uint64) {
			buf, _ := stringFromStack(m, stack, 0)
			gadgetCtx.Logger().Debug(buf)
		}), []wapi.ValueType{wapi.ValueTypeI64}, []wapi.ValueType{}).Export("xlog")

	env.NewFunctionBuilder().
		WithGoModuleFunction(
			wapi.GoModuleFunc(i.newDataSource),
			[]wapi.ValueType{wapi.ValueTypeI64}, // DataSourceName
			[]wapi.ValueType{wapi.ValueTypeI32}, // DataSource
		).
		Export("newDataSource")

	env.NewFunctionBuilder().
		WithGoModuleFunction(
			wapi.GoModuleFunc(i.getDataSource),
			[]wapi.ValueType{wapi.ValueTypeI64}, // DataSourceName
			[]wapi.ValueType{wapi.ValueTypeI32}, // DataSource
		).
		Export("getDataSource")

	env.NewFunctionBuilder().
		WithGoModuleFunction(
			wapi.GoModuleFunc(i.dataSourceSubscribe),
			[]wapi.ValueType{wapi.ValueTypeI32, wapi.ValueTypeI32, wapi.ValueTypeI64}, // DataSource, Priority, CallbackID
			[]wapi.ValueType{},
		).
		Export("dataSourceSubscribe")

	env.NewFunctionBuilder().
		WithGoModuleFunction(
			wapi.GoModuleFunc(i.free),
			[]wapi.ValueType{wapi.ValueTypeI32}, // any map entry
			[]wapi.ValueType{},
		).
		Export("freeHost")

	env.NewFunctionBuilder().
		WithGoModuleFunction(
			wapi.GoModuleFunc(i.dataSourceGetField),
			[]wapi.ValueType{wapi.ValueTypeI32, wapi.ValueTypeI64}, // DataSource, FieldName
			[]wapi.ValueType{wapi.ValueTypeI32},                    // Accessor
		).
		Export("dataSourceGetField")

	env.NewFunctionBuilder().
		WithGoModuleFunction(
			wapi.GoModuleFunc(i.dataSourceAddField),
			[]wapi.ValueType{wapi.ValueTypeI32, wapi.ValueTypeI64}, // DataSource, FieldName
			[]wapi.ValueType{wapi.ValueTypeI32},                    // Accessor
		).
		Export("dataSourceAddField")

	env.NewFunctionBuilder().
		WithGoModuleFunction(
			wapi.GoModuleFunc(i.dataSourceNewData),
			[]wapi.ValueType{wapi.ValueTypeI32}, // DataSource
			[]wapi.ValueType{wapi.ValueTypeI32}, // Data
		).
		Export("dataSourceNewData")

	env.NewFunctionBuilder().
		WithGoModuleFunction(
			wapi.GoModuleFunc(i.dataSourceEmitAndRelease),
			[]wapi.ValueType{wapi.ValueTypeI32, wapi.ValueTypeI32}, // DataSource, Data
			[]wapi.ValueType{}, // Data
		).
		Export("dataSourceEmitAndRelease")

	env.NewFunctionBuilder().
		WithGoModuleFunction(
			wapi.GoModuleFunc(i.fieldAccessorGetString),
			[]wapi.ValueType{wapi.ValueTypeI32, wapi.ValueTypeI32}, // Accessor, Data
			[]wapi.ValueType{wapi.ValueTypeI64},                    // String
		).
		Export("fieldAccessorGetString")

	env.NewFunctionBuilder().
		WithGoModuleFunction(
			wapi.GoModuleFunc(i.fieldAccessorSetString),
			[]wapi.ValueType{wapi.ValueTypeI32, wapi.ValueTypeI32, wapi.ValueTypeI64}, // Accessor, Data
			[]wapi.ValueType{},
		).
		Export("fieldAccessorSetString")

	env.NewFunctionBuilder().
		WithGoModuleFunction(
			wapi.GoModuleFunc(func(ctx context.Context, mod wapi.Module, stack []uint64) {
				free := mod.ExportedFunction("free")
				free.Call(ctx, stack[0])
			}),
			[]wapi.ValueType{wapi.ValueTypeI32}, // ptr
			[]wapi.ValueType{},
		).
		Export("mfree")

	env.Instantiate(ctx)

	wasi_snapshot_preview1.MustInstantiate(ctx, i.rt)

	mod, err := i.rt.InstantiateWithConfig(ctx, wasmBinary, config.WithArgs("wasi", os.Args[1]))
	if err != nil {
		// Note: Most compilers do not exit the module after running "_start",
		// unless there was an error. This allows you to call exported functions.
		if exitErr, ok := err.(*sys.ExitError); ok && exitErr.ExitCode() != 0 {
			fmt.Fprintf(os.Stderr, "exit_code: %d\n", exitErr.ExitCode())
		} else if !ok {
			log.Panicln(err)
		}
	}
	i.mod = mod
	return err
}

func (i *wasmOperatorInstance) Name() string {
	return "wasm"
}

func (i *wasmOperatorInstance) Init(gadgetCtx operators.GadgetContext) error {
	fn := i.mod.ExportedFunction("init")
	if fn == nil {
		return nil
	}
	_, err := fn.Call(gadgetCtx.Context())
	return err
}

func (i *wasmOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	fn := i.mod.ExportedFunction("preStart")
	if fn == nil {
		return nil
	}
	_, err := fn.Call(gadgetCtx.Context())
	return err
}

func (i *wasmOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	fn := i.mod.ExportedFunction("start")
	if fn == nil {
		return nil
	}
	_, err := fn.Call(gadgetCtx.Context())
	return err
}

func (i *wasmOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	defer func() {
		// cleanup
		i.memLock.Lock()
		i.memMap = nil
		i.memLock.Unlock()
	}()
	fn := i.mod.ExportedFunction("stop")
	if fn == nil {
		return nil
	}

	// We need a new context in here, as gadgetCtx has already been cancelled
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	_, err := fn.Call(ctx)
	return err
}

func init() {
	operators.RegisterDataOperator(&wasmOperator{})
}
