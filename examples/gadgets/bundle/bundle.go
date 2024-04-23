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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/trace_open"
)

func main() {
	myOperator := simple.New("myHandler", simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
		// Subscribe to all datasources and forward their output as JSON to wherever
		for _, d := range gadgetCtx.GetDataSources() {
			jsonEncoder, _ := igjson.New(d)
			d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
				jsonOutput := jsonEncoder.Marshal(data)
				fmt.Printf("%s\n", jsonOutput)
				return nil
			}, 50000)
		}
		return nil
	}))

	gadgetCtx := gadgetcontext.New(
		context.Background(),
		// Name is still needed because the same bundle can contain multiple images
		"trace_open",
		gadgetcontext.WithDataOperators(ocihandler.OciHandler, myOperator),
	)

	runtime := local.New()
	runtime.Init(nil)

	// Indicate where to locate the gadget, in this case, use the bundle
	// provided by the trace_open gadget
	params := map[string]string{
		"operator.oci.bundle-bytes": params.CompressAndB64Encode(string(trace_open.TraceOpenBundle)),
	}
	if err := runtime.RunGadget(gadgetCtx, nil, params); err != nil {
		panic(err)
	}
}
