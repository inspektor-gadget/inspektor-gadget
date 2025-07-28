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

package main

import (
	"context"
	"fmt"
	"os"
	"sync"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

func do() error {
	// Mutex to protect concurrent subscription callbacks from different nodes
	var nodeMu sync.Mutex
	// Create a simple operator to subscribe to events
	const opPriority = 50000
	myOperator := simple.New("myOperator",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			// Subscribe to all datasources and print their output as json
			for _, d := range gadgetCtx.GetDataSources() {
				jsonFormatter, _ := igjson.New(d)

				d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					nodeMu.Lock()
					defer nodeMu.Unlock()
					jsonOutput := jsonFormatter.Marshal(data)
					fmt.Printf("%s\n", jsonOutput)
					return nil
				}, opPriority)
			}
			return nil
		}),
	)

	// Create gadget context
	gadgetCtx := gadgetcontext.New(
		context.Background(),
		"ghcr.io/inspektor-gadget/gadget/trace_open:latest",
		gadgetcontext.WithDataOperators(
			myOperator,
		),
	)

	// Create GRPC runtime for Kubernetes
	grpcRuntime := grpcruntime.New(grpcruntime.WithConnectUsingK8SProxy)

	// Get Kubernetes REST config
	config, err := getKubernetesConfig()
	if err != nil {
		return fmt.Errorf("getting kubernetes config: %w", err)
	}
	grpcRuntime.SetRestConfig(config)

	// Initialize runtime with global parameters
	runtimeParams := grpcRuntime.GlobalParamDescs().ToParams()
	if err := grpcRuntime.Init(runtimeParams); err != nil {
		return fmt.Errorf("runtime init: %w", err)
	}
	defer grpcRuntime.Close()

	// Lets filter for a specific pod
	params := make(map[string]string)
	params["operator.KubeManager.selector"] = "k8s-app=kube-dns"

	// Run the gadget
	if err = grpcRuntime.RunGadget(gadgetCtx, nil, params); err != nil {
		return fmt.Errorf("running gadget: %w", err)
	}

	return nil
}

func getKubernetesConfig() (*rest.Config, error) {
	// Try in-cluster config first
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}

	// Fall back to kubeconfig file
	kubeconfig := clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename()
	config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("building config from kubeconfig: %w", err)
	}

	return config, nil
}

func main() {
	if err := do(); err != nil {
		fmt.Printf("Error running application: %s\n", err)
		os.Exit(1)
	}
}
