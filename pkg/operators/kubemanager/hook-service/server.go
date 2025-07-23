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

package hookservice

import (
	"context"
	"fmt"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	pb "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager/hook-service/api"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type HookServer struct {
	pb.UnimplementedHookServiceServer

	containerCollection *containercollection.ContainerCollection
}

// NewServer creates a new HookServer instance that implements the `HookService`
// gRPC service. The caller must ensure that the `containerCollection` is
// initialized and ready to use before calling this function. Additionally, the
// caller must ensure that the `containerCollection` is closed when it is no
// longer needed.
func NewServer(cc *containercollection.ContainerCollection) *HookServer {
	return &HookServer{
		containerCollection: cc,
	}
}

func (s *HookServer) AddContainer(ctx context.Context, containerDefinition *pb.ContainerDefinition) (*pb.AddContainerResponse, error) {
	if containerDefinition.Id == "" {
		return nil, fmt.Errorf("container id not set")
	}
	if s.containerCollection.GetContainer(containerDefinition.Id) != nil {
		return nil, fmt.Errorf("container with id %s already exists", containerDefinition.Id)
	}

	container := containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
				ContainerID:  containerDefinition.Id,
				ContainerPID: containerDefinition.Pid,
			},
		},
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: eventtypes.BasicK8sMetadata{
				Namespace:     containerDefinition.Namespace,
				PodName:       containerDefinition.Podname,
				ContainerName: containerDefinition.Name,
			},
		},
		OciConfig: containerDefinition.OciConfig,
	}
	if len(containerDefinition.Labels) > 0 {
		container.K8s.PodLabels = make(map[string]string)
		for _, l := range containerDefinition.Labels {
			container.K8s.PodLabels[l.Key] = l.Value
		}
	}

	s.containerCollection.AddContainer(&container)

	return &pb.AddContainerResponse{}, nil
}

func (s *HookServer) RemoveContainer(ctx context.Context, containerDefinition *pb.ContainerDefinition) (*pb.RemoveContainerResponse, error) {
	if containerDefinition.Id == "" {
		return nil, fmt.Errorf("container Id not set")
	}

	c := s.containerCollection.GetContainer(containerDefinition.Id)
	if c == nil {
		return nil, fmt.Errorf("unknown container %q", containerDefinition.Id)
	}

	s.containerCollection.RemoveContainer(containerDefinition.Id)
	return &pb.RemoveContainerResponse{}, nil
}
