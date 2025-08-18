// Copyright 2022-2024 The Inspektor Gadget authors
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

package operators

import (
	"context"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type GadgetContext interface {
	ID() string
	Name() string
	Context() context.Context
	Logger() logger.Logger
	ExtraInfo() bool

	Cancel()
	SerializeGadgetInfo(requestExtraInfo bool) (*api.GadgetInfo, error)
	ImageName() string
	RegisterDataSource(datasource.Type, string) (datasource.DataSource, error)
	GetDataSources() map[string]datasource.DataSource
	SetVar(string, any)
	GetVar(string) (any, bool)
	Params() []*api.Param
	SetParams([]*api.Param)
	SetMetadata([]byte)
	OrasTarget() oras.ReadOnlyTarget
	IsRemoteCall() bool
	IsClient() bool
}

// MapPrefix is used to avoid clash with maps and other eBPF objects when added
// to gadget context.
const MapPrefix string = "map/"

type ImageOperator interface {
	Name() string

	// InstantiateImageOperator will be run to load information about a gadget and also to _possibly_
	// run the gadget afterward. It should only do things that are required to populate
	// DataSources and Params. It could use caching to speed things up, if necessary.
	InstantiateImageOperator(
		gadgetCtx GadgetContext,
		target oras.ReadOnlyTarget,
		descriptor ocispec.Descriptor,
		paramValues api.ParamValues,
	) (ImageOperatorInstance, error)
}

type ImageOperatorInstance interface {
	Name() string
	Start(gadgetCtx GadgetContext) error
	Stop(gadgetCtx GadgetContext) error
	Close(gadgetCtx GadgetContext) error
}

type DataOperator interface {
	Name() string

	// Init allows the operator to initialize itself
	Init(params *params.Params) error

	// GlobalParams should return global params (required) for this operator; these are valid globally for the process
	GlobalParams() api.Params

	// InstanceParams should return parameters valid for a single gadget run
	InstanceParams() api.Params

	// InstantiateDataOperator should create a new (lightweight) instance for the operator that can read/write
	// from and to DataSources, register Params and read/write Variables; instanceParamValues can contain values for
	// both params defined by InstanceParams() as well as params defined by DataOperatorInstance.ExtraParams())
	InstantiateDataOperator(gadgetCtx GadgetContext, instanceParamValues api.ParamValues) (DataOperatorInstance, error)

	Priority() int
}

type DataOperatorInstance interface {
	Name() string
	Start(gadgetCtx GadgetContext) error
	Stop(gadgetCtx GadgetContext) error
	Close(gadgetCtx GadgetContext) error
}

type ExtraParams interface {
	// ExtraParams can return dynamically created params
	ExtraParams(gadgetCtx GadgetContext) api.Params
}

type PreStart interface {
	PreStart(gadgetCtx GadgetContext) error
}

type PreStop interface {
	PreStop(gadgetCtx GadgetContext) error
}

type PostStop interface {
	PostStop(gadgetCtx GadgetContext) error
}

// ContainerInfoFromMountNSID is a typical kubernetes operator interface that adds node, pod, namespace and container
// information given the MountNSID
type ContainerInfoFromMountNSID interface {
	ContainerInfoSetters
	GetMountNSID() uint64
}

type ContainerInfoFromNetNSID interface {
	ContainerInfoSetters
	GetNetNSID() uint64
}

type ContainerInfoSetters interface {
	NodeSetter
	SetPodMetadata(types.Container)
	SetContainerMetadata(types.Container)
}

type NodeSetter interface {
	SetNode(string)
}

type ContainerInfoGetters interface {
	GetNode() string
	GetPod() string
	GetNamespace() string
	GetContainer() string
	GetContainerImageName() string
}
