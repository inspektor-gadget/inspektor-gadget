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

	// The runtime is the piece that will run our gadget.
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"

	// Import the operators we need:
	// - ocihandler: to handle OCI images
	// - ebpf: handle ebpf programs
	// - simple: building block for our operator
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"

	// Datasources provide access to the data produced by gadgets and operators.
	// Import also the json formatter to format the data as json.
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"

	// The gadget context is the glue that connects all components together.
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
)

func do() error {
	// First of all, we need to define a (simple) operator that we'll use to subscribe
	// to events. We use a high priority to make sure that our operator is the last
	// to run and print the information after all operators have been run.
	const opPriority = 50000
	myOperator := simple.New("myOperator",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			// Subscribe to all datasources and print their output as json the terminal
			for _, d := range gadgetCtx.GetDataSources() {
				jsonFormatter, _ := igjson.New(d,
					// Show all fields
					igjson.WithShowAll(true),

					// Print json in a pretty format
					igjson.WithPretty(true, "  "),
				)

				d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					jsonOutput := jsonFormatter.Marshal(data)
					fmt.Printf("%s\n", jsonOutput)
					return nil
				}, opPriority)
			}
			return nil
		}),
	)

	// Then, we create a gadget context instance. This is the glue that connects
	// all operators together.
	gadgetCtx := gadgetcontext.New(
		context.Background(),
		// This is the image that contains the gadget we want to run.
		"ghcr.io/inspektor-gadget/gadget/trace_open:latest",
		// List of operators that will be run with the gadget
		gadgetcontext.WithDataOperators(
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			myOperator,
		),
	)

	// After that, we need a runtime, that's the piece that will run our gadget.
	// In this case, we use the local runtime to run the gadget in the local host.
	runtime := local.New()
	if err := runtime.Init(nil); err != nil {
		return fmt.Errorf("runtime init: %w", err)
	}
	defer runtime.Close()

	// Finally, let's run our gadget
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
