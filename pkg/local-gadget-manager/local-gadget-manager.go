// Copyright 2019-2021 The Inspektor Gadget authors
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

package localgadgetmanager

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/kinvolk/inspektor-gadget/pkg/container-utils"
	gadgetcollection "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	containersmap "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/containers-map"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/pubsub"
	tracercollection "github.com/kinvolk/inspektor-gadget/pkg/tracer-collection"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type LocalGadgetManager struct {
	containercollection.ContainerCollection

	traceFactories map[string]gadgets.TraceFactory

	// tracers
	tracerCollection *tracercollection.TracerCollection
	traceResources   map[string]*gadgetv1alpha1.Trace

	// containersMap is the global map at /sys/fs/bpf/gadget/containers
	// exposing container details for each mount namespace.
	containersMap *containersmap.ContainersMap
}

func (l *LocalGadgetManager) ListGadgets() []string {
	gadgets := []string{}
	for name := range l.traceFactories {
		gadgets = append(gadgets, name)
	}
	sort.Strings(gadgets)
	return gadgets
}

func (l *LocalGadgetManager) GadgetOutputModesSupported(gadget string) (ret []string, err error) {
	factory, ok := l.traceFactories[gadget]
	if !ok {
		return nil, fmt.Errorf("unknown gadget %q", gadget)
	}
	outputModesSupported := factory.OutputModesSupported()
	for k := range outputModesSupported {
		ret = append(ret, k)
	}
	sort.Strings(ret)
	return ret, nil
}

func (l *LocalGadgetManager) ListOperations(name string) []string {
	operations := []string{}

	traceResource, ok := l.traceResources[name]
	if !ok {
		return operations
	}

	factory, ok := l.traceFactories[traceResource.Spec.Gadget]
	if !ok {
		return operations
	}

	for opname := range factory.Operations() {
		operations = append(operations, opname)
	}

	sort.Strings(operations)
	return operations
}

func (l *LocalGadgetManager) ListTraces() []string {
	traces := []string{}
	for name := range l.traceResources {
		traces = append(traces, name)
	}
	sort.Strings(traces)
	return traces
}

func (l *LocalGadgetManager) ListContainers() []string {
	containers := []string{}
	l.ContainerCollection.ContainerRange(func(c *pb.ContainerDefinition) {
		containers = append(containers, c.Name)
	})
	sort.Strings(containers)
	return containers
}

func traceName(name string) string {
	return gadgets.TraceName("gadget", name)
}

func (l *LocalGadgetManager) AddTracer(gadget, name, containerFilter, outputMode string, params map[string]string) error {
	factory, ok := l.traceFactories[gadget]
	if !ok {
		return fmt.Errorf("unknown gadget %q", gadget)
	}
	if l.tracerCollection.TracerExists(traceName(name)) {
		return fmt.Errorf("trace %q already exists", name)
	}

	outputModesSupported := factory.OutputModesSupported()
	if outputMode == "" {
		if _, ok := outputModesSupported["Stream"]; ok {
			outputMode = "Stream"
		} else if _, ok := outputModesSupported["Status"]; ok {
			outputMode = "Status"
		} else {
			for k := range outputModesSupported {
				outputMode = k
				break
			}
		}
	}
	if _, ok := outputModesSupported[outputMode]; !ok {
		outputModesSupportedStr := ""
		for k := range outputModesSupported {
			outputModesSupportedStr += k + ", "
		}
		outputModesSupportedStr = strings.TrimSuffix(outputModesSupportedStr, ", ")
		return fmt.Errorf("unsupported output mode %q for gadget %q (must be one of: %s)", outputMode, gadget, outputModesSupportedStr)
	}

	traceResource := &gadgetv1alpha1.Trace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "gadget",
		},
		Spec: gadgetv1alpha1.TraceSpec{
			Node:       "local",
			Gadget:     gadget,
			RunMode:    "Manual",
			OutputMode: outputMode,
			Parameters: params,
		},
	}
	if containerFilter != "" {
		traceResource.Spec.Filter = &gadgetv1alpha1.ContainerFilter{
			Namespace: "default",
			Podname:   containerFilter,
			Labels:    map[string]string{},
		}
	}

	l.tracerCollection.AddTracer(traceName(name), *gadgets.ContainerSelectorFromContainerFilter(traceResource.Spec.Filter))
	l.traceResources[name] = traceResource
	return nil
}

func (l *LocalGadgetManager) Operation(name, opname string) error {
	traceResource, ok := l.traceResources[name]
	if !ok {
		return fmt.Errorf("cannot find trace %q", name)
	}

	factory, ok := l.traceFactories[traceResource.Spec.Gadget]
	if !ok {
		return fmt.Errorf("cannot find factory for %q", traceResource.Spec.Gadget)
	}

	if opname != "" {
		gadgetOperation, ok := factory.Operations()[opname]
		if !ok {
			return fmt.Errorf("unknown operation %q", opname)
		}
		tracerNamespacedName := traceResource.ObjectMeta.Namespace +
			"/" + traceResource.ObjectMeta.Name
		gadgetOperation.Operation(tracerNamespacedName, traceResource)
	}

	return nil
}

func (l *LocalGadgetManager) Show(name string) (ret string, err error) {
	traceResource, ok := l.traceResources[name]
	if !ok {
		return "", fmt.Errorf("cannot find trace %q", name)
	}
	if traceResource.Status.State != "" {
		ret += fmt.Sprintf("State: %s\n", traceResource.Status.State)
	}
	if traceResource.Status.OperationError != "" {
		ret += fmt.Sprintf("Error: %s\n", traceResource.Status.OperationError)
	}
	if traceResource.Status.Output != "" {
		ret += fmt.Sprintln(traceResource.Status.Output)
	}

	return ret, nil
}

func (l *LocalGadgetManager) CheckStatus(name, state string) error {
	traceResource, ok := l.traceResources[name]
	if !ok {
		return fmt.Errorf("cannot find trace %q", name)
	}

	if traceResource.Status.OperationError != "" {
		return errors.New(traceResource.Status.OperationError)
	}

	if traceResource.Status.State != state {
		return fmt.Errorf("trace %q is not in the expected state %q: %s",
			name, state, traceResource.Status.State)
	}

	return nil
}

func (l *LocalGadgetManager) DisplayOutput(
	name string,
	customResultsDisplay func(string, []string) error,
) error {
	traceResource, ok := l.traceResources[name]
	if !ok {
		return fmt.Errorf("cannot find trace %q", name)
	}

	return customResultsDisplay(traceResource.Spec.OutputMode, []string{traceResource.Status.Output})
}

func (l *LocalGadgetManager) Delete(name string) error {
	traceResource, ok := l.traceResources[name]
	if !ok {
		return fmt.Errorf("cannot find trace %q", name)
	}

	factory, ok := l.traceFactories[traceResource.Spec.Gadget]
	if !ok {
		return fmt.Errorf("cannot find factory for %q", traceResource.Spec.Gadget)
	}

	factory.Delete("gadget/" + name)
	delete(l.traceResources, name)
	l.tracerCollection.RemoveTracer(traceName(name))
	return nil
}

func (l *LocalGadgetManager) PublishEvent(tracerID string, line string) error {
	gadgetStream, err := l.tracerCollection.Stream(tracerID)
	if err != nil {
		return fmt.Errorf("cannot find stream for tracer %q", tracerID)
	}

	gadgetStream.Publish(line)
	return nil
}

func (l *LocalGadgetManager) TracerMountNsMap(tracerID string) (*ebpf.Map, error) {
	return l.tracerCollection.TracerMountNsMap(tracerID)
}

func (l *LocalGadgetManager) ContainersMap() *ebpf.Map {
	if l.containersMap == nil {
		return nil
	}

	return l.containersMap.ContainersMap()
}

func (l *LocalGadgetManager) Stream(name string, stop chan struct{}) (chan string, error) {
	gadgetStream, err := l.tracerCollection.Stream(traceName(name))
	if err != nil {
		return nil, fmt.Errorf("cannot find stream for %q", name)
	}

	out := make(chan string)

	ch := gadgetStream.Subscribe()

	go func() {
		if stop == nil {
			for len(ch) > 0 {
				line := <-ch
				out <- line.Line
			}
			gadgetStream.Unsubscribe(ch)
			close(out)
		} else {
			for {
				select {
				case <-stop:
					gadgetStream.Unsubscribe(ch)
					close(out)
					return
				case line := <-ch:
					out <- line.Line
				}
			}
		}
	}()
	return out, nil
}

func (l *LocalGadgetManager) Dump() string {
	out := "List of containers:\n"
	l.ContainerCollection.ContainerRange(func(c *pb.ContainerDefinition) {
		out += fmt.Sprintf("%+v\n", c)
	})
	out += "List of tracers:\n"
	for i, traceResource := range l.traceResources {
		out += fmt.Sprintf("%v -> %q\n",
			i,
			traceResource.Spec.Gadget)
		out += fmt.Sprintf("    %+v\n", traceResource)
		out += fmt.Sprintf("    %+v\n", traceResource.Spec.Filter)
	}
	return out
}

func NewManager(runtimes []*containerutils.RuntimeConfig) (*LocalGadgetManager, error) {
	l := &LocalGadgetManager{
		traceFactories: gadgetcollection.TraceFactoriesForLocalGadget(),
		traceResources: make(map[string]*gadgetv1alpha1.Trace),
	}

	var err error
	l.tracerCollection, err = tracercollection.NewTracerCollection(true, &l.ContainerCollection)
	if err != nil {
		return nil, err
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	l.containersMap, err = containersmap.NewContainersMap("")
	if err != nil {
		return nil, fmt.Errorf("error creating containers map: %w", err)
	}
	containerEventFuncs := []pubsub.FuncNotify{}
	containerEventFuncs = append(containerEventFuncs, l.containersMap.ContainersMapUpdater())
	containerEventFuncs = append(containerEventFuncs, l.tracerCollection.TracerMapsUpdater())

	err = l.ContainerCollection.ContainerCollectionInitialize(
		containercollection.WithPubSub(containerEventFuncs...),
		containercollection.WithCgroupEnrichment(),
		containercollection.WithLinuxNamespaceEnrichment(),
		containercollection.WithMultipleContainerRuntimesEnrichment(runtimes),
		containercollection.WithRuncFanotify(),
	)
	if err != nil {
		return nil, err
	}

	for _, factory := range l.traceFactories {
		factory.Initialize(l, nil)
	}

	return l, nil
}

func (l *LocalGadgetManager) Close() {
	l.ContainerCollectionClose()
	l.containersMap.Close()
}
