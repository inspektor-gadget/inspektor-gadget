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

package gadgetapi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

type GadgetAPI struct {
	gadgetCtx *gadgetcontext.GadgetContext
	runtime   *local.Runtime
	outputCh  chan string
}

// NewGadget initializes a new GadgetAPI with the specified gadget image.
func NewGadget(image string, timeout time.Duration) (*GadgetAPI, error) {
	const opPriority = 50000

	// Create an output channel
	outputCh := make(chan string, 100)

	// Set up simple gadget operator with JSON formatting
	gadgetOperator := simple.New("gadget", simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
		fmt.Println("Initializing gadget operator...")

		for _, d := range gadgetCtx.GetDataSources() {
			jsonFormatter, _ := igjson.New(d)

			d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
				jsonOutput := jsonFormatter.Marshal(data)
				outputCh <- string(jsonOutput)
				fmt.Printf("Captured data: %s\n", jsonOutput)
				return nil
			}, opPriority)
		}
		return nil
	}))

	gadgetCtx := gadgetcontext.New(
		context.Background(),
		image,
		gadgetcontext.WithDataOperators(
			ocihandler.OciHandler,
			gadgetOperator,
		),
		gadgetcontext.WithTimeout(timeout),
	)

	runtime := local.New()
	if err := runtime.Init(nil); err != nil {
		return nil, fmt.Errorf("runtime init: %w", err)
	}

	return &GadgetAPI{
		gadgetCtx: gadgetCtx,
		runtime:   runtime,
		outputCh:  outputCh,
	}, nil
}

// StartGadget starts the gadget
func (api *GadgetAPI) StartGadget(params map[string]string) error {
	fmt.Println("Starting gadget...")
	if err := api.runtime.RunGadget(api.gadgetCtx, nil, params); err != nil {
		return fmt.Errorf("running gadget: %w", err)
	}
	return nil
}

// StopGadget stops the gadget
func (api *GadgetAPI) StopGadget() error {
	fmt.Println("Stopping gadget...")
	if err := api.runtime.Close(); err != nil {
		return fmt.Errorf("stopping runtime: %w", err)
	}
	return nil
}

// Output returns the gadget's output
func (api *GadgetAPI) Output() string {
	var output []string
	datastream := "["

	for {
		select {
		case data := <-api.outputCh:
			output = append(output, data)
		default:
			if len(output) > 0 {
				datastream += strings.Join(output, ",")
			}
			datastream += "]"
			return datastream
		}
	}
}
