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
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/environment"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	MntNsIdType     = "type:gadget_mntns_id"
	NetNsIdType     = "type:gadget_netns_id"
	NetNsIdFallback = "name:netns"
)

type EventWrapperBase struct {
	ds                           datasource.DataSource
	MntnsidAccessor              datasource.FieldAccessor
	NetnsidAccessor              datasource.FieldAccessor
	nodeAccessor                 datasource.FieldAccessor
	namespaceAccessor            datasource.FieldAccessor
	podnameAccessor              datasource.FieldAccessor
	containernameAccessorK8s     datasource.FieldAccessor
	containernameAccessor        datasource.FieldAccessor
	runtimenameAccessor          datasource.FieldAccessor
	containeridAccessor          datasource.FieldAccessor
	containerimagenameAccessor   datasource.FieldAccessor
	containerimagedigestAccessor datasource.FieldAccessor
	hostNetworkAccessor          datasource.FieldAccessor
}

type (
	MntNsEnrichFunc func(event operators.ContainerInfoFromMountNSID)
	NetNsEnrichFunc func(event operators.ContainerInfoFromNetNSID)
)

// GetEventWrappers checks for data sources containing refererences to mntns/netns that we could enrich data for
func GetEventWrappers(gadgetCtx operators.GadgetContext) (map[datasource.DataSource]*EventWrapperBase, error) {
	res := make(map[datasource.DataSource]*EventWrapperBase)
	for _, ds := range gadgetCtx.GetDataSources() {
		mntnsFields := ds.GetFieldsWithTag(MntNsIdType)
		netnsFields := ds.GetFieldsWithTag(NetNsIdType, NetNsIdFallback)
		if len(mntnsFields) == 0 && len(netnsFields) == 0 {
			continue
		}

		gadgetCtx.Logger().Debugf("found DataSource with mntns/netns fields: %q", ds.Name())

		var err error

		var mntnsField datasource.FieldAccessor
		var netnsField datasource.FieldAccessor

		for _, f := range mntnsFields {
			gadgetCtx.Logger().Debugf("using mntns enrichment")
			mntnsField = f
			// We only support one of those per DataSource for now
			break
		}
		for _, f := range netnsFields {
			gadgetCtx.Logger().Debugf("using netns enrichment")
			netnsField = f
			// We only support one of those per DataSource for now
			break
		}

		accessors, err := WrapAccessors(ds, mntnsField, netnsField)
		if err != nil {
			return nil, fmt.Errorf("registering accessors: %w", err)
		}
		res[ds] = accessors
	}
	return res, nil
}

func Subscribe(
	eventWrappers map[datasource.DataSource]*EventWrapperBase,
	mntNsEnrichFunc MntNsEnrichFunc,
	netNsEnrichFunc NetNsEnrichFunc,
	priority int,
) {
	for ds, wrapper := range eventWrappers {
		wr := EventWrapper{
			EventWrapperBase: wrapper,
		}
		ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			wr.Data = data
			if wrapper.MntnsidAccessor != nil {
				mntNsEnrichFunc(&wr)
			}
			if wrapper.NetnsidAccessor != nil {
				netNsEnrichFunc(&wr)
			}
			return nil
		}, priority)
	}
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

	ev.nodeAccessor, err = k8s.AddSubField("node", datasource.WithTags("kubernetes"))
	if err != nil {
		return nil, err
	}
	ev.namespaceAccessor, err = k8s.AddSubField("namespace", datasource.WithTags("kubernetes"), datasource.WithAnnotations(map[string]string{
		"columns.template": "namespace",
	}), datasource.WithOrder(-30))
	if err != nil {
		return nil, err
	}
	ev.podnameAccessor, err = k8s.AddSubField("pod", datasource.WithTags("kubernetes"), datasource.WithAnnotations(map[string]string{
		"columns.template": "pod",
	}), datasource.WithOrder(-29))
	if err != nil {
		return nil, err
	}
	ev.containernameAccessorK8s, err = k8s.AddSubField("container", datasource.WithTags("kubernetes"), datasource.WithAnnotations(map[string]string{
		"columns.template": "container",
	}), datasource.WithOrder(-28))
	if err != nil {
		return nil, err
	}
	ev.hostNetworkAccessor, err = k8s.AddSubField(
		"hostnetwork",
		datasource.WithTags("kubernetes"),
		datasource.WithKind(api.Kind_Bool),
		datasource.WithFlags(datasource.FieldFlagHidden),
		datasource.WithOrder(-27),
	)
	if err != nil {
		return nil, err
	}

	// TODO: Instead of just hiding fields, we can skip adding them in the first place (integration tests don't like
	// that right now, though)
	if environment.Environment != environment.Kubernetes {
		k8s.SetHidden(true, true)
	}

	runtime, err := source.AddField("runtime", datasource.WithFlags(datasource.FieldFlagEmpty))
	if err != nil {
		return nil, err
	}
	ev.containernameAccessor, err = runtime.AddSubField(
		"containerName",
		datasource.WithAnnotations(map[string]string{
			"columns.template": "container",
		}),
		datasource.WithOrder(-26),
	)
	if err != nil {
		return nil, err
	}
	ev.runtimenameAccessor, err = runtime.AddSubField(
		"runtimeName",
		datasource.WithAnnotations(map[string]string{
			"columns.width": "19",
			"columns.fixed": "true",
		}),
		datasource.WithFlags(datasource.FieldFlagHidden),
		datasource.WithOrder(-25),
	)
	if err != nil {
		return nil, err
	}
	ev.containeridAccessor, err = runtime.AddSubField(
		"containerId",
		datasource.WithAnnotations(map[string]string{
			"columns.width":    "13",
			"columns.maxWidth": "64",
		}),
		datasource.WithFlags(datasource.FieldFlagHidden),
		datasource.WithOrder(-24))
	if err != nil {
		return nil, err
	}
	ev.containerimagenameAccessor, err = runtime.AddSubField(
		"containerImageName",
		datasource.WithFlags(datasource.FieldFlagHidden),
		datasource.WithOrder(-23),
	)
	if err != nil {
		return nil, err
	}
	ev.containerimagedigestAccessor, err = runtime.AddSubField(
		"containerImageDigest",
		datasource.WithFlags(datasource.FieldFlagHidden),
		datasource.WithOrder(-22),
	)
	if err != nil {
		return nil, err
	}

	// TODO: Instead of just hiding fields, we can skip adding them in the first place (integration tests don't like
	// that right now, though)
	if environment.Environment == environment.Kubernetes {
		runtime.SetHidden(true, true)
	}

	return ev, nil
}

type EventWrapper struct {
	*EventWrapperBase
	Data datasource.Data
}

func getUint64(accessor datasource.FieldAccessor, data datasource.Data) uint64 {
	d := accessor.Get(data)
	switch len(d) {
	case 4:
		return uint64(accessor.Uint32(data))
	case 8:
		return accessor.Uint64(data)
	}
	return 0
}

func (ev *EventWrapper) GetMountNSID() uint64 {
	return getUint64(ev.MntnsidAccessor, ev.Data)
}

func (ev *EventWrapper) GetNetNSID() uint64 {
	return getUint64(ev.NetnsidAccessor, ev.Data)
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
			ev.containernameAccessorK8s.Set(ev.Data, []byte(k8s.ContainerName))
		}
		if ev.hostNetworkAccessor.IsRequested() {
			ev.hostNetworkAccessor.Set(ev.Data, make([]byte, 1))
			ev.hostNetworkAccessor.PutInt8(ev.Data, 0) // TODO
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
	ev.nodeAccessor.Set(ev.Data, []byte(node))
}
