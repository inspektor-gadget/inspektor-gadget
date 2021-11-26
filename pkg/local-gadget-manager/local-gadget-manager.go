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
	"fmt"
	"sort"
	"strings"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	gadgetcollection "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/stream"

	"github.com/cilium/ebpf"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type LocalGadgetManager struct {
	containercollection.ContainerCollection

	traceFactories map[string]gadgets.TraceFactory

	// tracers by name
	tracers map[string]tracer
}

type tracer struct {
	gadget        string
	name          string
	factory       gadgets.TraceFactory
	traceResource *gadgetv1alpha1.Trace
	gadgetStream  *stream.GadgetStream
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

	tracer, ok := l.tracers[name]
	if !ok {
		return operations
	}

	for opname := range tracer.factory.Operations() {
		operations = append(operations, opname)
	}

	sort.Strings(operations)
	return operations
}

func (l *LocalGadgetManager) ListTraces() []string {
	traces := []string{}
	for name := range l.tracers {
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

func (l *LocalGadgetManager) AddTracer(gadget, name, containerFilter, outputMode string) error {
	factory, ok := l.traceFactories[gadget]
	if !ok {
		return fmt.Errorf("unknown gadget %q", gadget)
	}
	_, ok = l.tracers[name]
	if ok {
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
		},
	}
	if containerFilter != "" {
		traceResource.Spec.Filter = &gadgetv1alpha1.ContainerFilter{
			Namespace: "default",
			Podname:   containerFilter,
			Labels:    map[string]string{},
		}
	}

	l.tracers[name] = tracer{
		gadget:        gadget,
		name:          name,
		factory:       factory,
		traceResource: traceResource,
		gadgetStream:  stream.NewGadgetStream(),
	}
	return nil
}

func (l *LocalGadgetManager) Operation(name, opname string) error {
	tracer, ok := l.tracers[name]
	if !ok {
		return fmt.Errorf("cannot find trace %q", name)
	}

	if opname != "" {
		gadgetOperation, ok := tracer.factory.Operations()[opname]
		if !ok {
			return fmt.Errorf("Unknown operation %q", opname)
		}
		tracerNamespacedName := tracer.traceResource.ObjectMeta.Namespace +
			"/" + tracer.traceResource.ObjectMeta.Name
		gadgetOperation.Operation(tracerNamespacedName, tracer.traceResource)
	}

	return nil
}

func (l *LocalGadgetManager) Show(name string) (ret string, err error) {
	tracer, ok := l.tracers[name]
	if !ok {
		return "", fmt.Errorf("cannot find trace %q", name)
	}
	if tracer.traceResource.Status.State != "" {
		ret += fmt.Sprintf("State: %s\n", tracer.traceResource.Status.State)
	}
	if tracer.traceResource.Status.OperationError != "" {
		ret += fmt.Sprintf("Error: %s\n", tracer.traceResource.Status.OperationError)
	}
	if tracer.traceResource.Status.Output != "" {
		ret += fmt.Sprintln(tracer.traceResource.Status.Output)
	}

	return ret, nil
}

func (l *LocalGadgetManager) Delete(name string) error {
	tracer, ok := l.tracers[name]
	if !ok {
		return fmt.Errorf("cannot find trace %q", name)
	}

	tracer.factory.Delete("gadget/" + name)
	delete(l.tracers, name)
	return nil
}

func (l *LocalGadgetManager) PublishEvent(tracerID string, line string) error {
	name := strings.TrimPrefix(tracerID, "trace_gadget_")
	t, ok := l.tracers[name]
	if !ok {
		return fmt.Errorf("cannot find trace %q", name)
	}

	t.gadgetStream.Publish(line)
	return nil
}

func (l *LocalGadgetManager) Stream(name string, stop chan struct{}) (chan string, error) {
	t, ok := l.tracers[name]
	if !ok {
		return nil, fmt.Errorf("cannot find trace %q", name)
	}

	out := make(chan string)

	ch := t.gadgetStream.Subscribe()

	go func() {
		if stop == nil {
			for len(ch) > 0 {
				line := <-ch
				out <- line.Line
			}
			t.gadgetStream.Unsubscribe(ch)
			close(out)
		} else {
			for {
				select {
				case <-stop:
					t.gadgetStream.Unsubscribe(ch)
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
	for i, t := range l.tracers {
		out += fmt.Sprintf("%v -> %q %q\n",
			i,
			t.gadget,
			t.name)
		out += fmt.Sprintf("    %+v\n", t.traceResource)
		out += fmt.Sprintf("    %+v\n", t.traceResource.Spec.Filter)
	}
	return out
}

func NewManager() (*LocalGadgetManager, error) {
	if _, err := ebpf.RemoveMemlockRlimit(); err != nil {
		return nil, err
	}

	l := &LocalGadgetManager{
		traceFactories: gadgetcollection.TraceFactoriesForLocalGadget(),
		tracers:        make(map[string]tracer),
	}
	err := l.ContainerCollection.ContainerCollectionInitialize(
		containercollection.WithPubSub(),
		containercollection.WithCgroupEnrichment(),
		containercollection.WithLinuxNamespaceEnrichment(),
		containercollection.WithDockerEnrichment(),
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
