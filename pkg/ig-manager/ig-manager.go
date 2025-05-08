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

package igmanager

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	containersmap "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/containers-map"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type IGManager struct {
	containercollection.ContainerCollection

	tracerCollection *tracercollection.TracerCollection

	// containersMap is the global map at /sys/fs/bpf/gadget/containers
	// exposing container details for each mount namespace.
	containersMap *containersmap.ContainersMap
}

func (l *IGManager) ContainersMap() *ebpf.Map {
	if l.containersMap == nil {
		return nil
	}

	return l.containersMap.ContainersMap()
}

func (l *IGManager) Dump() string {
	out := "List of containers:\n"
	l.ContainerRange(func(c *containercollection.Container) {
		out += fmt.Sprintf("%+v\n", c)
	})
	return out
}

func (l *IGManager) CreateMountNsMap(id string, containerSelector containercollection.ContainerSelector) (*ebpf.Map, error) {
	if err := l.tracerCollection.AddTracer(id, containerSelector); err != nil {
		return nil, err
	}

	mountnsmap, err := l.tracerCollection.TracerMountNsMap(id)
	if err != nil {
		l.tracerCollection.RemoveTracer(id)
		return nil, err
	}

	return mountnsmap, nil
}

func (l *IGManager) RemoveMountNsMap(id string) error {
	return l.tracerCollection.RemoveTracer(id)
}

func NewManager(runtimes []*containerutilsTypes.RuntimeConfig, additionalOpts []containercollection.ContainerCollectionOption) (*IGManager, error) {
	l := &IGManager{}

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
		return nil, fmt.Errorf("creating containers map: %w", err)
	}

	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithPubSub(l.containersMap.ContainersMapUpdater()),
		containercollection.WithOCIConfigEnrichment(),
		containercollection.WithCgroupEnrichment(),
		containercollection.WithLinuxNamespaceEnrichment(),
		containercollection.WithMultipleContainerRuntimesEnrichment(runtimes),
		containercollection.WithContainerFanotifyEbpf(),
		containercollection.WithTracerCollection(l.tracerCollection),
		containercollection.WithProcEnrichment(),
	}
	opts = append(opts, additionalOpts...)

	if !log.IsLevelEnabled(log.DebugLevel) && isDefaultContainerRuntimeConfig(runtimes) {
		warnings := []containercollection.ContainerCollectionOption{containercollection.WithDisableContainerRuntimeWarnings()}
		opts = append(warnings, opts...)
	}

	err = l.Initialize(opts...)
	if err != nil {
		return nil, err
	}

	return l, nil
}

func (l *IGManager) Close() {
	l.ContainerCollection.Close()
	if l.tracerCollection != nil {
		l.tracerCollection.Close()
	}
	if l.containersMap != nil {
		l.containersMap.Close()
	}
}

func isDefaultContainerRuntimeConfig(runtimes []*containerutilsTypes.RuntimeConfig) bool {
	if len(runtimes) != len(containerutils.AvailableRuntimes) {
		return false
	}

	var customSocketPath bool
	for _, runtime := range runtimes {
		switch runtime.Name {
		case types.RuntimeNameDocker:
			customSocketPath = runtime.SocketPath != runtimeclient.DockerDefaultSocketPath
		case types.RuntimeNameContainerd:
			customSocketPath = runtime.SocketPath != runtimeclient.ContainerdDefaultSocketPath
		case types.RuntimeNameCrio:
			customSocketPath = runtime.SocketPath != runtimeclient.CrioDefaultSocketPath
		case types.RuntimeNamePodman:
			customSocketPath = runtime.SocketPath != runtimeclient.PodmanDefaultSocketPath
		default:
			customSocketPath = true
		}
		if customSocketPath {
			return false
		}
	}

	return true
}
