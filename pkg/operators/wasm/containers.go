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

package wasm

import (
	"context"

	"github.com/tetratelabs/wazero"
	wapi "github.com/tetratelabs/wazero/api"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	igmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/ig-manager"
)

func (i *wasmOperatorInstance) addContainersFuncs(env wazero.HostModuleBuilder) {
	exportFunction(env, "getContainers", i.getContainers,
		[]wapi.ValueType{},
		[]wapi.ValueType{wapi.ValueTypeI32}, // Containers array
	)

	exportFunction(env, "containerGetCgroupID", i.containerGetCgroupID,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Container
		},
		[]wapi.ValueType{wapi.ValueTypeI64}, // CgroupID or error
	)

	exportFunction(env, "containerGetMntns", i.containerGetMntns,
		[]wapi.ValueType{
			wapi.ValueTypeI32, // Container
		},
		[]wapi.ValueType{wapi.ValueTypeI64}, // MntNs ID or error
	)
}

// getContainers gets a list of all running containers.
// Return value:
// - Array of container handle on success, 0 on error
func (i *wasmOperatorInstance) getContainers(ctx context.Context, m wapi.Module, stack []uint64) {
	manager, ok := i.gadgetCtx.GetVar("containercollection")
	if !ok {
		i.logger.Warnf("get containers: no manager for name %q")
		stack[0] = 0
		return
	}

	var containers []*containercollection.Container
	switch igmngr := manager.(type) {
	case *igmanager.IGManager:
		containers = igmngr.GetContainersBySelector(&containercollection.ContainerSelector{})
	default:
		i.logger.Warnf("get map: manager type is %T, expected *igmanager.IGManager", manager)
		stack[0] = 0
		return
	}

	handles := make([]uint32, len(containers))
	for idx, container := range containers {
		handles[idx] = i.addHandle(container)
	}

	stack[0] = wapi.EncodeU32(i.addHandle(handles))
}

// containerGetCgroupID returns the container cgroup ID.
// Params:
// - stack[0]: Container handle
// Return value:
// - Container ID on success, 0 on error
func (i *wasmOperatorInstance) containerGetCgroupID(ctx context.Context, m wapi.Module, stack []uint64) {
	containerHandle := wapi.DecodeU32(stack[0])

	container, ok := getHandle[*containercollection.Container](i, containerHandle)
	if !ok {
		stack[0] = 1
		return
	}

	stack[0] = wapi.EncodeI64(int64(container.CgroupID))
}

// containerGetMntns returns the container mount namespace ID.
// Params:
// - stack[0]: Container handle
// Return value:
// - Container ID on success, 0 on error
func (i *wasmOperatorInstance) containerGetMntns(ctx context.Context, m wapi.Module, stack []uint64) {
	containerHandle := wapi.DecodeU32(stack[0])

	container, ok := getHandle[*containercollection.Container](i, containerHandle)
	if !ok {
		stack[0] = 1
		return
	}

	stack[0] = wapi.EncodeI64(int64(container.Mntns))
}
