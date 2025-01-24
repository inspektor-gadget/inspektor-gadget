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

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	clioperator "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/cli"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

func do() error {
	// In this case, we need to set priority to a low value to be sure it's
	// executed before the cli operator (which prints the output)
	const opPriority = 100
	myOperator := simple.New("myHandler", simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
		for _, d := range gadgetCtx.GetDataSources() {
			// It's possible to add new fields to the datasource
			isRootF, err := d.AddField("is_root", api.Kind_Bool)
			if err != nil {
				return fmt.Errorf("adding field: %w", err)
			}

			// It's also possible to change visibility, and other attributes of fields
			timeStampF := d.GetField("timestamp")
			timeStampF.SetHidden(true, false)

			// Get accessors to some specific fields
			uidF := d.GetField("uid")

			d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
				// Error handling is omitted for brevity
				uid, _ := uidF.Uint32(data)
				// if uid is zero, set is_root to true
				if uid == 0 {
					isRootF.PutBool(data, true)

				}
				return nil
			}, opPriority)
		}
		return nil
	}))

	gadgetCtx := gadgetcontext.New(
		context.Background(),
		"ghcr.io/inspektor-gadget/gadget/trace_open:latest",
		gadgetcontext.WithDataOperators(ocihandler.OciHandler, myOperator, clioperator.CLIOperator),
	)

	runtime := local.New()
	if err := runtime.Init(nil); err != nil {
		return fmt.Errorf("runtime init: %w", err)
	}
	defer runtime.Close()

	if err := runtime.RunGadget(gadgetCtx, nil, nil); err != nil {
		return fmt.Errorf("running gadget: %w", err)
	}

	return nil
}

func main() {
	if err := do(); err != nil {
		fmt.Printf("Error running application: %s\n", err)
		os.Exit(1)
	}
}
