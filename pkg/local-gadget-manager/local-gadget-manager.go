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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	containersmap "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/containers-map"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
)

type LocalGadgetManager struct {
	containercollection.ContainerCollection

	tracerCollection *tracercollection.TracerCollection

	// containersMap is the global map at /sys/fs/bpf/gadget/containers
	// exposing container details for each mount namespace.
	containersMap *containersmap.ContainersMap
}

func (l *LocalGadgetManager) ContainersMap() *ebpf.Map {
	if l.containersMap == nil {
		return nil
	}

	return l.containersMap.ContainersMap()
}

func (l *LocalGadgetManager) Dump() string {
	out := "List of containers:\n"
	l.ContainerCollection.ContainerRange(func(c *containercollection.Container) {
		out += fmt.Sprintf("%+v\n", c)
	})
	return out
}

// We are not running multiple tracers per instance so the tracer ID doesn't
// need to be unique and we can hide it from caller.
const localGadgetTracerID = "local_gadget_tracer_id"

func (l *LocalGadgetManager) CreateMountNsMap(containerSelector containercollection.ContainerSelector) (*ebpf.Map, error) {
	if err := l.tracerCollection.AddTracer(localGadgetTracerID, containerSelector); err != nil {
		return nil, err
	}

	mountnsmap, err := l.tracerCollection.TracerMountNsMap(localGadgetTracerID)
	if err != nil {
		l.tracerCollection.RemoveTracer(localGadgetTracerID)
		return nil, err
	}

	return mountnsmap, nil
}

func (l *LocalGadgetManager) RemoveMountNsMap() error {
	return l.tracerCollection.RemoveTracer(localGadgetTracerID)
}

func NewManager(runtimes []*containerutils.RuntimeConfig) (*LocalGadgetManager, error) {
	l := &LocalGadgetManager{}

	var err error
	l.tracerCollection, err = tracercollection.NewTracerCollection(&l.ContainerCollection)
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

	err = l.ContainerCollection.Initialize(
		containercollection.WithPubSub(l.containersMap.ContainersMapUpdater()),
		containercollection.WithOCIConfigEnrichment(),
		containercollection.WithCgroupEnrichment(),
		containercollection.WithLinuxNamespaceEnrichment(),
		containercollection.WithMultipleContainerRuntimesEnrichment(runtimes),
		containercollection.WithRuncFanotify(),
		containercollection.WithTracerCollection(l.tracerCollection),
	)
	if err != nil {
		return nil, err
	}

	return l, nil
}

func (l *LocalGadgetManager) Close() {
	l.ContainerCollection.Close()
	if l.tracerCollection != nil {
		l.tracerCollection.Close()
	}
	if l.containersMap != nil {
		l.containersMap.Close()
	}
}
