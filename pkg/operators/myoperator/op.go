// Copyright 2023 The Inspektor Gadget authors
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

// Package kubeipresolver provides an operator that enriches events by looking
// up IP addresses in Kubernetes resources such as pods and services.
package kubeipresolver

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	runTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	OperatorName = "MyOperator"
)

type MyOperator struct {
	setter func(blob *runTypes.BlobEvent, val uint64)
}

func (k *MyOperator) Name() string {
	return OperatorName
}

func (k *MyOperator) Description() string {
	return "Test"
}

func (k *MyOperator) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (k *MyOperator) ParamDescs() params.ParamDescs {
	return nil
}

func (k *MyOperator) Dependencies() []string {
	return nil
}

func (k *MyOperator) CanOperateOn(gadget gadgets.GadgetDesc) bool {
	return false
}

func (k *MyOperator) CanOperateOnContainerizedGadget(info *runTypes.GadgetInfo) bool {
	return true
}

func (k *MyOperator) Init(params *params.Params) error {
	return nil
}

func (k *MyOperator) Close() error {
	return nil
}

func (k *MyOperator) AddFields(info *runTypes.GadgetInfo, blob *runTypes.BlobEvent) error {
	fmt.Println("add fields")

	eventStructureName := "event"
	eventStruct := info.GadgetMetadata.Structs[eventStructureName]

	fields := []types.Field{}
	var uint64col runTypes.ColumnDesc

	// any column
	uint64col, k.setter = runTypes.AddField[uint64](blob, "uint64col")
	info.Columns = append(info.Columns, uint64col)
	fields = append(fields, runTypes.Field{
		Name: "uint64col",
		Attributes: types.FieldAttributes{
			Width: 10,
		},
	})

	eventStruct.Fields = append(eventStruct.Fields, fields...)
	info.GadgetMetadata.Structs[eventStructureName] = eventStruct

	return nil
}

func (k *MyOperator) Instantiate(gadgetCtx operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	return &KubeIPResolverInstance{
		gadgetCtx:      gadgetCtx,
		manager:        k,
		gadgetInstance: gadgetInstance,
	}, nil
}

type KubeIPResolverInstance struct {
	gadgetCtx      operators.GadgetContext
	manager        *MyOperator
	gadgetInstance any
}

func (m *KubeIPResolverInstance) Name() string {
	return "MyOperatorInstance"
}

func (m *KubeIPResolverInstance) PreGadgetRun() error {

	fmt.Println("pregadgetrun")

	return nil
}

func (m *KubeIPResolverInstance) PostGadgetRun() error {

	return nil
}

func (m *KubeIPResolverInstance) EnrichEvent(ev any) error {

	// TODO: missing blob
	m.manager.setter(uint64(5000))

	return nil
}

func init() {
	operators.Register(&MyOperator{})
}
