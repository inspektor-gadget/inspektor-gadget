// // Copyright 2025 The Inspektor Gadget authors
// //
// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// //     http://www.apache.org/licenses/LICENSE-2.0
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.

package oci

import (
	"context"
	"fmt"
	"io"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"oras.land/oras-go/v2"
)

type WasmInfo struct {
	APIVersion int      `json:"apiVersion" column:"apiversion"`
	Upcalls    []string `json:"upcalls" column:"upcalls"`
}

func getWasmInfo(ctx context.Context, target oras.ReadOnlyTarget, manifest *ocispec.Manifest) (*WasmInfo, error) {
	var wasmLayer *ocispec.Descriptor
	for _, layer := range manifest.Layers {
		if layer.MediaType == wasmObjectMediaType {
			wasmLayer = &layer
			break
		}
	}

	if wasmLayer == nil {
		return nil, nil
	}

	reader, err := GetContentFromDescriptor(ctx, target, *wasmLayer)
	if err != nil {
		return nil, fmt.Errorf("getting wasm content: %w", err)
	}
	defer reader.Close()

	wasmBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading wasm content: %w", err)
	}

	runtimeConfig := wazero.NewRuntimeConfig().
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(256)

	runtime := wazero.NewRuntimeWithConfig(ctx, runtimeConfig)
	defer runtime.Close(ctx)

	module, err := runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		return nil, fmt.Errorf("compiling wasm module: %w", err)
	}
	defer module.Close(ctx)

	info := &WasmInfo{
		Upcalls: make([]string, 0),
	}

	if apiVersionFunc, ok := module.ExportedFunctions()["gadgetAPIVersion"]; ok {
        if fn, ok := apiVersionFunc.GoFunction().(api.Function); ok {
            results, err := fn.Call(ctx)
            if err != nil {
                return nil, fmt.Errorf("calling gadgetAPIVersion: %w", err)
            }
            if len(results) > 0 {
                info.APIVersion = int(results[0])
            }
        }
    }

	for _, imp := range module.ImportedFunctions() {
		if strings.Contains(imp.Name(), "inspektor-gadget/wasmapi/go") {
			parts := strings.Split(imp.Name(), ".")
			if len(parts) > 0 {
				funcName := parts[len(parts)-1]
				info.Upcalls = append(info.Upcalls, funcName)
			}
		}
	}

	return info, nil
}
