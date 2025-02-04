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
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/formatters"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

func do() error {
	ctx := context.Background()

	const opPriority = 50000
	myOperator := simple.New("myOperator", simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
		for _, d := range gadgetCtx.GetDataSources() {
			jsonFormatter, _ := igjson.New(d, igjson.WithShowAll(true), igjson.WithPretty(true, "  "))
			d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
				jsonOutput := jsonFormatter.Marshal(data)
				fmt.Printf("%s\n", jsonOutput)
				return nil
			}, opPriority)
		}
		return nil
	}))

	// Configure the local manager operator
	localManagerOp := localmanager.LocalManagerOperator
	localManagerParams := localManagerOp.GlobalParamDescs().ToParams()
	localManagerParams.Get(localmanager.Runtimes).Set("docker")
	if err := localManagerOp.Init(localManagerParams); err != nil {
		return fmt.Errorf("init local manager: %w", err)
	}
	defer localManagerOp.Close()

	gadgetCtx := gadgetcontext.New(
		ctx,
		"ghcr.io/inspektor-gadget/gadget/trace_open:latest",
		gadgetcontext.WithDataOperators(
			ocihandler.OciHandler,
			localManagerOp,
			formatters.FormattersOperator,
			myOperator,
		),
	)

	runtime := local.New()
	if err := runtime.Init(nil); err != nil {
		return fmt.Errorf("runtime init: %w", err)
	}
	defer runtime.Close()

	params := map[string]string{
		// Filter events by container name
		"operator.LocalManager.containername": "mycontainer",
	}
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
