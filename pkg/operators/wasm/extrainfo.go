// Copyright 2025 The Inspektor Gadget authors
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
	"encoding/json"
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func (i *wasmOperatorInstance) addExtraInfo(gadgetcontext operators.GadgetContext, version uint64, wasmProgram []byte) error {
	module, err := i.rt.CompileModule(gadgetcontext.Context(), wasmProgram)
	if err != nil {
		return err
	}
	imports := module.ImportedFunctions()
	upcalls := []string{}
	for _, imp := range imports {
		moduleName, name, isImport := imp.Import()
		if isImport && moduleName == "ig" {
			upcalls = append(upcalls, name)
		}
	}
	wasmInfo := &api.ExtraInfo{
		Data: make(map[string]*api.GadgetInspectAddendum),
	}
	wasmInfo.Data["wasm.gadgetAPIVersion"] = &api.GadgetInspectAddendum{
		ContentType: "text/plain",
		Content:     []byte(fmt.Sprintf("%d", version)),
	}
	upcallsJSON, _ := json.Marshal(upcalls)
	wasmInfo.Data["wasm.upcalls"] = &api.GadgetInspectAddendum{
		ContentType: "application/json",
		Content:     []byte(upcallsJSON),
	}
	gadgetcontext.SetVar("extraInfo.wasm", wasmInfo)

	return nil
}
