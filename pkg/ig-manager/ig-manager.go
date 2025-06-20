// Copyright 2019-2025 The Inspektor Gadget authors
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
	"context"
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

func (l *IGManager) TracerDump() string {
	return l.tracerCollection.TracerDump()
}

// TracerCount returns the number of tracers currently registered in the IGManager.
// Only for testing purposes.
func (l *IGManager) TracerCount() int {
	return l.tracerCollection.TracerCount()
}

// TracerExists checks if a tracer with the given ID exists in the IGManager.
// Only for testing purposes.
func (l *IGManager) TracerExists(id string) bool {
	return l.tracerCollection.TracerExists(id)
}

func (l *IGManager) CreateMountNsMap(id string, containerSelector containercollection.ContainerSelector) (*ebpf.Map, error) {
	if err := l.tracerCollection.AddTracer(id, containerSelector); err != nil {
		return nil, fmt.Errorf("adding tracer %q: %w", id, err)
	}

	mountnsmap, err := l.tracerCollection.TracerMountNsMap(id)
	if err != nil {
		l.tracerCollection.RemoveTracer(id)
		return nil, fmt.Errorf("getting mount namespace map for tracer %q: %w", id, err)
	}

	return mountnsmap, nil
}

func (l *IGManager) RemoveMountNsMap(id string) error {
	return l.tracerCollection.RemoveTracer(id)
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

type Config struct {
	// PinPath is the path where the containers BPF maps will be pinned.
	PinPath string
	// TestOnly indicates whether the manager is running in test mode.
	TestOnly bool
	// ContainerRuntimeConfig is the configuration for the container runtime.
	ContainerRuntimeConfig []*containerutilsTypes.RuntimeConfig
}

func NewManager(
	ctx context.Context,
	config *Config,
	additionalOpts []containercollection.ContainerCollectionOption,
) (*IGManager, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	l := &IGManager{}

	var err error
	opts := []containercollection.ContainerCollectionOption{}
	if !config.TestOnly {
		if err = rlimit.RemoveMemlock(); err != nil {
			return nil, err
		}

		l.tracerCollection, err = tracercollection.NewTracerCollection(&l.ContainerCollection)
		if err != nil {
			return nil, fmt.Errorf("creating tracer collection: %w", err)
		}

		// TODO: Do we still need the containers map?
		l.containersMap, err = containersmap.NewContainersMap(config.PinPath)
		if err != nil {
			return nil, fmt.Errorf("creating containers map: %w", err)
		}

		if !log.IsLevelEnabled(log.DebugLevel) && isDefaultContainerRuntimeConfig(config.ContainerRuntimeConfig) {
			warnings := []containercollection.ContainerCollectionOption{containercollection.WithDisableContainerRuntimeWarnings()}
			opts = append(warnings, opts...)
		}
	} else {
		l.tracerCollection, err = tracercollection.NewTracerCollectionTest(&l.ContainerCollection)
		if err != nil {
			return nil, fmt.Errorf("creating tracer collection: %w", err)
		}
	}

	opts = append(opts, []containercollection.ContainerCollectionOption{
		containercollection.WithPubSub(l.containersMap.ContainersMapUpdater()),
		containercollection.WithOCIConfigEnrichment(),
		containercollection.WithCgroupEnrichment(),
		containercollection.WithLinuxNamespaceEnrichment(),
		containercollection.WithTracerCollection(l.tracerCollection),
		containercollection.WithProcEnrichment(),
	}...)

	if config.ContainerRuntimeConfig != nil {
		opts = append(opts, containercollection.WithMultipleContainerRuntimesEnrichment(config.ContainerRuntimeConfig))
	}

	err = l.Initialize(append(opts, additionalOpts...)...)
	if err != nil {
		return nil, err
	}

	return l, nil
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
