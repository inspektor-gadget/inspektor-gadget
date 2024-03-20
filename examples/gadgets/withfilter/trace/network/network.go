// Copyright 2022 The Inspektor Gadget authors
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
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	tracernetwork "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/tracer"
	tracernetworktypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubeipresolver"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubenameresolver"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s", err.Error())
		os.Exit(1)
	}
}

func run() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memory limit: %v", err)
	}

	err := host.Init(host.Config{
		AutoMountFilesystems: false,
	})
	if err != nil {
		return fmt.Errorf("initializing host filesystem: %w", err)
	}

	// Trace all containers
	containerSelector := containercollection.ContainerSelector{}

	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithContainerFanotifyEbpf(),
		containercollection.WithLinuxNamespaceEnrichment(),
		containercollection.WithMultipleContainerRuntimesEnrichment(
			[]*containerutils.RuntimeConfig{
				{Name: types.RuntimeNameDocker},
				{Name: types.RuntimeNameContainerd},
			}),
		containercollection.WithPubSub(func(event containercollection.PubSubEvent) {
			eventJson, _ := json.MarshalIndent(event, "", "  ")
			fmt.Println(string(eventJson))
		}),
	}

	containerCollection := &containercollection.ContainerCollection{}

	networkTracer, err := tracernetwork.NewTracer()
	if err != nil {
		return err
	}
	defer networkTracer.Close()

	kubeIPEnricher, err := newKubeIPEnricher()
	if err != nil {
		fmt.Printf("failed to initialize kube IP enricher: %v. It won't be available.\n", err)
	}
	if kubeIPEnricher != nil {
		defer kubeIPEnricher.PostGadgetRun()
	}

	kubeNameEnricher, err := newKubeNameEnricher()
	if err != nil {
		fmt.Printf("failed to initialize kube name enricher: %v. It won't be available.\n", err)
	}
	if kubeNameEnricher != nil {
		defer kubeNameEnricher.PostGadgetRun()
	}

	socketEnricher, err := socketenricher.NewSocketEnricher()
	if err != nil {
		return err
	}
	defer socketEnricher.Close()

	networkTracer.SetSocketEnricherMap(socketEnricher.SocketsMap())

	networkTracer.SetEventHandler(func(event *tracernetworktypes.Event) {
		if event.Type != types.NORMAL {
			return
		}

		containerCollection.EnrichByNetNs(&event.CommonData, event.NetNsID)

		// Use KubeIPResolver and KubeNameResolver to enrich event based on Namespace/Pod and IP.
		if kubeIPEnricher != nil {
			kubeIPEnricher.EnrichEvent(event)
		}

		if kubeNameEnricher != nil {
			kubeNameEnricher.EnrichEvent(event)
		}

		eventJson, _ := json.MarshalIndent(event, "", "  ")
		fmt.Println(string(eventJson))
	})

	err = containerCollection.Initialize(opts...)
	if err != nil {
		return fmt.Errorf("initializing container collection: %w", err)
	}

	config := &networktracer.ConnectToContainerCollectionConfig[tracernetworktypes.Event]{
		Tracer:   networkTracer,
		Resolver: containerCollection,
		Selector: containerSelector,
		Base:     tracernetworktypes.Base,
	}

	containerCollectionLink, err := networktracer.ConnectToContainerCollection(config)
	if err != nil {
		return fmt.Errorf("connecting network tracer to container collection package: %w", err)
	}
	defer containerCollectionLink.Close()

	if err := networkTracer.RunWorkaround(); err != nil {
		return fmt.Errorf("running network tracer workaround: %w", err)
	}

	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit

	return nil
}

func newKubeIPEnricher() (operators.OperatorInstance, error) {
	factory := operators.GetRaw(kubeipresolver.OperatorName).(*kubeipresolver.KubeIPResolver)
	err := factory.Init(nil)
	if err != nil {
		return nil, err
	}
	enricher, err := factory.Instantiate(nil, nil, nil)
	if err != nil {
		return nil, err
	}
	err = enricher.PreGadgetRun()
	if err != nil {
		return nil, err
	}
	return enricher, nil
}

func newKubeNameEnricher() (operators.OperatorInstance, error) {
	factory := operators.GetRaw(kubenameresolver.OperatorName).(*kubenameresolver.KubeNameResolver)
	err := factory.Init(nil)
	if err != nil {
		return nil, err
	}
	enricher, err := factory.Instantiate(nil, nil, nil)
	if err != nil {
		return nil, err
	}
	err = enricher.PreGadgetRun()
	if err != nil {
		return nil, err
	}
	return enricher, nil
}
