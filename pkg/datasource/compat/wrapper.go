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

package compat

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type EventWrapperBase struct {
	ds                           datasource.DataSource
	MntnsidAccessor              datasource.FieldAccessor
	NetnsidAccessor              datasource.FieldAccessor
	nodeAccessor                 datasource.FieldAccessor
	namespaceAccessor            datasource.FieldAccessor
	podnameAccessor              datasource.FieldAccessor
	containernameAccessor        datasource.FieldAccessor
	runtimenameAccessor          datasource.FieldAccessor
	containeridAccessor          datasource.FieldAccessor
	containerimagenameAccessor   datasource.FieldAccessor
	containerimagedigestAccessor datasource.FieldAccessor
}

func WrapAccessors(source datasource.DataSource, mntnsidAccessor datasource.FieldAccessor, netnsidAccessor datasource.FieldAccessor) (*EventWrapperBase, error) {
	ev := &EventWrapperBase{
		ds:              source,
		MntnsidAccessor: mntnsidAccessor,
		NetnsidAccessor: netnsidAccessor,
	}

	k8s, err := source.AddField("k8s", datasource.WithFlags(datasource.FieldFlagEmpty))
	if err != nil {
		return nil, err
	}

	runtime, err := source.AddField("runtime", datasource.WithFlags(datasource.FieldFlagEmpty))
	if err != nil {
		return nil, err
	}

	ev.nodeAccessor, err = k8s.AddSubField("node", datasource.WithTags("kubernetes"))
	if err != nil {
		return nil, err
	}
	ev.namespaceAccessor, err = k8s.AddSubField("namespace", datasource.WithTags("kubernetes"))
	if err != nil {
		return nil, err
	}
	ev.podnameAccessor, err = k8s.AddSubField("podName", datasource.WithTags("kubernetes"))
	if err != nil {
		return nil, err
	}
	ev.containernameAccessor, err = runtime.AddSubField("containerName")
	if err != nil {
		return nil, err
	}
	ev.runtimenameAccessor, err = runtime.AddSubField("runtime")
	if err != nil {
		return nil, err
	}
	ev.containeridAccessor, err = runtime.AddSubField("containerId")
	if err != nil {
		return nil, err
	}
	ev.containerimagenameAccessor, err = runtime.AddSubField("containerImageName")
	if err != nil {
		return nil, err
	}
	ev.containerimagedigestAccessor, err = runtime.AddSubField("containerImageDigest")
	if err != nil {
		return nil, err
	}
	return ev, nil
}

type EventWrapper struct {
	*EventWrapperBase
	Data datasource.Data
}

func (ev *EventWrapper) GetMountNSID() uint64 {
	d := ev.MntnsidAccessor.Get(ev.Data)
	switch len(d) {
	case 4:
		return uint64(ev.ds.ByteOrder().Uint32(d))
	case 8:
		return ev.ds.ByteOrder().Uint64(d)
	}
	return 0
}

func (ev *EventWrapper) GetNetNSID() uint64 {
	d := ev.NetnsidAccessor.Get(ev.Data)
	switch len(d) {
	case 4:
		return uint64(ev.ds.ByteOrder().Uint32(d))
	case 8:
		return ev.ds.ByteOrder().Uint64(d)
	}
	return 0
}

func (ev *EventWrapper) SetPodMetadata(k8s *types.BasicK8sMetadata, rt *types.BasicRuntimeMetadata) {
	if k8s != nil {
		if ev.namespaceAccessor.IsRequested() {
			ev.namespaceAccessor.Set(ev.Data, []byte(k8s.Namespace))
		}
		if ev.podnameAccessor.IsRequested() {
			ev.podnameAccessor.Set(ev.Data, []byte(k8s.PodName))
		}
		if ev.containernameAccessor.IsRequested() {
			ev.containernameAccessor.Set(ev.Data, []byte(k8s.ContainerName))
		}
	}
	if rt != nil {
		if ev.containernameAccessor.IsRequested() {
			ev.containernameAccessor.Set(ev.Data, []byte(rt.ContainerName))
		}
		if ev.runtimenameAccessor.IsRequested() {
			ev.runtimenameAccessor.Set(ev.Data, []byte(rt.RuntimeName))
		}
		if ev.containeridAccessor.IsRequested() {
			ev.containeridAccessor.Set(ev.Data, []byte(rt.ContainerID))
		}
		if ev.containerimagenameAccessor.IsRequested() {
			ev.containerimagenameAccessor.Set(ev.Data, []byte(rt.ContainerImageName))
		}
		if ev.containerimagedigestAccessor.IsRequested() {
			ev.containerimagedigestAccessor.Set(ev.Data, []byte(rt.ContainerImageDigest))
		}
	}
}

func (ev *EventWrapper) SetContainerMetadata(k8s *types.BasicK8sMetadata, rt *types.BasicRuntimeMetadata) {
	ev.SetPodMetadata(k8s, rt)
}

func (ev *EventWrapper) SetNode(node string) {
	if ev.nodeAccessor.IsRequested() {
		ev.nodeAccessor.Set(ev.Data, []byte(node))
	}
}
