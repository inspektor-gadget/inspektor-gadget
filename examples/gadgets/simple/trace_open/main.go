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

	// Operators provide functionality like enrichment and filtering.
	// Check the operators documentation to learn more: <TODO>
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"

	// The oci-handler is responsible for handling OCI images
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"

	// The ebpf operator handles all eBPF objects: loading eBPF programs,
	// attaching them, reading maps, etc.
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"

	// The simple operator is a wrapper to make it easier to implement operators
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"

	// Datasources provide access to the data produced by gadgets and operators.
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"

	// The json formatter is used to format the data as json.
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"

	// The gadget context is the glue that connects all components together.
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"

	// The runtime is the piece that will run our gadget.
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

func do() error {
	// First of all, we need to define a (simple) operator that we'll use to subscribe
	// to events. Check the operator documentation to learn more about them.
	// TODO: documentation
	// Our operator should be the last of the chain to print information after
	// all operators have been run.
	const opPriority = 50000
	myOperator := simple.New("myHandler", simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
		// Subscribe to all datasources and print their output as json the terminal
		// Check the datasources documentation for more information
		// TODO: link to documentation
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
	}))

	// Then, we create a gadget context instance. This is the glue that connects
	// all operators together.
	// Check the documentation for the gadget context here.
	// TODO: link to documentation
	gadgetCtx := gadgetcontext.New(
		context.Background(),
		"ghcr.io/inspektor-gadget/gadget/trace_open:latest",
		gadgetcontext.WithDataOperators(
			ocihandler.OciHandler, // pass singleton instance of the oci-handler
			myOperator,
		),
	)

	// After that, we need a runtime, that's the piece that will run our gadget.
	// In this case, we use the local runtime to run the gadget in the local host.
	// Check the runtime documentation here.
	runtime := local.New()
	if err := runtime.Init(nil); err != nil {
		return fmt.Errorf("runtime init: %w", err)
	}
	defer runtime.Close()

	// Before running the gadget, let's set some parameters.
	// TODO: link to documentation with the parameters supported by this gadget
	params := map[string]string{
		// Filter only events from the root user
		"operator.oci.ebpf.uid": "0",
	}

	// Finally, let's run our gadget
	if err := runtime.RunGadget(gadgetCtx, nil, params); err != nil {
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
