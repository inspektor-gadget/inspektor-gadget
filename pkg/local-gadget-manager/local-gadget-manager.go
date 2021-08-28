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
	"context"
	"fmt"
	"sort"
	"strings"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadget-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/containerutils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/match"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/pubsub"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/stream"
	"github.com/kinvolk/inspektor-gadget/pkg/runcfanotify"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type LocalGadgetManager struct {
	traceFactories map[string]gadgets.TraceFactory

	// tracers by name
	tracers map[string]tracer

	// containers by id
	containers map[string]pb.ContainerDefinition

	// subs contains a list of subscribers
	pubsub *pubsub.GadgetPubSub

	runcNotifier *runcfanotify.RuncNotifier

	dockercli *client.Client
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

func (l *LocalGadgetManager) ListOperations(gadget string) []string {
	return []string{"start", "stop", "generate"}
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
	for id := range l.containers {
		containers = append(containers, id)
	}
	sort.Strings(containers)
	return containers
}

func (l *LocalGadgetManager) AddTracer(gadget, name, containerFilter string) error {
	factory, ok := l.traceFactories[gadget]
	if !ok {
		return fmt.Errorf("unknown gadget")
	}
	_, ok = l.tracers[name]
	if ok {
		fmt.Printf("Error: trace already exists")
		return nil
	}

	traceResource := &gadgetv1alpha1.Trace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "gadget",
		},
		Spec: gadgetv1alpha1.TraceSpec{
			Node:   "local",
			Gadget: gadget,
			Filter: &gadgetv1alpha1.ContainerFilter{
				Namespace:     "local",
				Podname:       containerFilter,
				ContainerName: "",
				Labels:        map[string]string{},
			},
			RunMode:    "Manual",
			OutputMode: "Stream",
		},
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
		return fmt.Errorf("unknown trace")
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

	fmt.Printf("State: %s\n", tracer.traceResource.Status.State)
	fmt.Printf("OperationError: %s\n", tracer.traceResource.Status.OperationError)
	fmt.Printf("Output: %s\n", tracer.traceResource.Status.Output)

	return nil
}

func (l *LocalGadgetManager) Show(name string) error {
	return l.Operation(name, "")
}

func (l *LocalGadgetManager) Delete(name string) error {
	tracer, ok := l.tracers[name]
	if !ok {
		return fmt.Errorf("unknown trace")
	}

	factory, ok := l.traceFactories[tracer.gadget]
	if !ok {
		return fmt.Errorf("unknown gadget")
	}
	factory.Delete("gadget/" + name)
	delete(l.tracers, name)
	return nil
}

func (l *LocalGadgetManager) PublishEvent(tracerID string, line string) error {
	name := strings.TrimPrefix(tracerID, "trace_gadget_")
	t, ok := l.tracers[name]
	if !ok {
		return fmt.Errorf("cannot find tracer: unknown tracer %q", tracerID)
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

func (l *LocalGadgetManager) LookupMntnsByContainer(namespace, pod, container string) uint64 {
	for _, c := range l.containers {
		if namespace != c.Namespace {
			continue
		}
		if pod != c.Podname {
			continue
		}
		if container != c.Name {
			continue
		}
		return c.Mntns
	}
	return 0
}

func (l *LocalGadgetManager) LookupMntnsByPod(namespace, pod string) map[string]uint64 {
	ret := make(map[string]uint64)
	for _, c := range l.containers {
		if namespace != c.Namespace {
			continue
		}
		if pod != c.Podname {
			continue
		}
		ret[c.Name] = c.Mntns
	}
	return ret
}

func (l *LocalGadgetManager) LookupPIDByContainer(namespace, pod, container string) uint32 {
	for _, c := range l.containers {
		if namespace != c.Namespace {
			continue
		}
		if pod != c.Podname {
			continue
		}
		if container != c.Name {
			continue
		}
		return c.Pid
	}
	return 0
}

func (l *LocalGadgetManager) LookupPIDByPod(namespace, pod string) map[string]uint32 {
	ret := make(map[string]uint32)
	for _, c := range l.containers {
		if namespace != c.Namespace {
			continue
		}
		if pod != c.Podname {
			continue
		}
		ret[c.Name] = c.Pid
	}
	return ret
}

func (l *LocalGadgetManager) GetContainersBySelector(containerSelector *pb.ContainerSelector) []pb.ContainerDefinition {
	// TODO
	return []pb.ContainerDefinition{}
}

// Subscribe returns the list of existing containers and registers a callback
// for notifications about additions and deletions of containers
func (l *LocalGadgetManager) Subscribe(key interface{}, selector pb.ContainerSelector, f pubsub.FuncNotify) []pb.ContainerDefinition {
	l.pubsub.Subscribe(key, func(event pubsub.PubSubEvent) {
		if match.ContainerSelectorMatches(&selector, &event.Container) {
			f(event)
		}
	})
	ret := []pb.ContainerDefinition{}
	for _, c := range l.containers {
		if match.ContainerSelectorMatches(&selector, &c) {
			ret = append(ret, c)
		}
	}
	return ret
}

// Unsubscribe undoes a previous call to Subscribe
func (l *LocalGadgetManager) Unsubscribe(key interface{}) {
	l.pubsub.Unsubscribe(key)
}

func (l *LocalGadgetManager) AddContainer(notif runcfanotify.ContainerEvent) {
	pid := int(notif.ContainerPID)

	cgroupPathV1, cgroupPathV2, err := containerutils.GetCgroupPaths(pid)
	if err != nil {
		return
	}
	cgroupPathV2WithMountpoint, _ := containerutils.CgroupPathV2AddMountpoint(cgroupPathV2)
	cgroupId, _ := containerutils.GetCgroupID(cgroupPathV2WithMountpoint)
	mntns, err := containerutils.GetMntNs(pid)

	containerDefinition := pb.ContainerDefinition{
		Id:         notif.ContainerID,
		Pid:        notif.ContainerPID,
		Namespace:  "local",
		Podname:    notif.ContainerID,
		CgroupPath: cgroupPathV2WithMountpoint,
		CgroupId:   cgroupId,
		Mntns:      mntns,
		CgroupV1:   cgroupPathV1,
		CgroupV2:   cgroupPathV2,
	}

	if l.dockercli != nil {
		filter := filters.NewArgs()
		filter.Add("id", notif.ContainerID)
		containers, err := l.dockercli.ContainerList(context.Background(),
			dockertypes.ContainerListOptions{
				All:     true,
				Filters: filter,
			})
		if err != nil {
			fmt.Printf("Couldn't find docker container: %s", err)
		}
		if len(containers) == 1 {
			if len(containers[0].Names) > 0 {
				containerDefinition.Podname = strings.TrimPrefix(containers[0].Names[0], "/")
			}
		}
	}

	l.containers[notif.ContainerID] = containerDefinition

	l.pubsub.Publish(pubsub.EVENT_TYPE_ADD_CONTAINER, containerDefinition)

}

func (l *LocalGadgetManager) RemoveContainer(notif runcfanotify.ContainerEvent) {
	containerDefinition, ok := l.containers[notif.ContainerID]
	if !ok {
		return
	}
	l.pubsub.Publish(pubsub.EVENT_TYPE_REMOVE_CONTAINER, containerDefinition)
	delete(l.containers, notif.ContainerID)
}

func (l *LocalGadgetManager) Dump() string {
	out := "List of containers:\n"
	for i, c := range l.containers {
		out += fmt.Sprintf("%v -> %+v\n", i, c)
	}
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
	l := &LocalGadgetManager{
		traceFactories: gadgetcollection.TraceFactories(),
		tracers:        make(map[string]tracer),
		containers:     make(map[string]pb.ContainerDefinition),
		pubsub:         pubsub.NewGadgetPubSub(),
	}

	for _, factory := range l.traceFactories {
		factory.Initialize(l, nil)
	}

	runcNotifier, err := runcfanotify.NewRuncNotifier(func(notif runcfanotify.ContainerEvent) {
		switch notif.Type {
		case runcfanotify.EVENT_TYPE_ADD_CONTAINER:
			l.AddContainer(notif)
		case runcfanotify.EVENT_TYPE_REMOVE_CONTAINER:
			l.RemoveContainer(notif)
		}
	})
	if err != nil {
		return nil, err
	}
	l.runcNotifier = runcNotifier

	l.dockercli, _ = client.NewClientWithOpts(client.FromEnv)

	return l, nil
}
