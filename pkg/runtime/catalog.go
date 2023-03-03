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

package runtime

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

// GadgetInfo is used to store GadgetDesc information in a serializable way
type GadgetInfo struct {
	ID                       string                `json:"id"`
	Name                     string                `json:"name"`
	Category                 string                `json:"category"`
	Type                     string                `json:"type"`
	Description              string                `json:"description"`
	Params                   params.ParamDescs     `json:"params"`
	ColumnsDefinition        any                   `json:"columnsDefinition"`
	OperatorParamsCollection params.DescCollection `json:"operatorParamsCollection"`
}

// OperatorInfo is used to store operator information in a serializable way
type OperatorInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Catalog stores both data about gadgets and operators in a serializable way. This is used to handle
// gadgets and operators, even if they aren't run locally (and their code is not or only partially available)
type Catalog struct {
	Gadgets   []*GadgetInfo
	Operators []*OperatorInfo
}

func GadgetInfoFromGadgetDesc(gadgetDesc gadgets.GadgetDesc) *GadgetInfo {
	return &GadgetInfo{
		Name:                     gadgetDesc.Name(),
		Category:                 gadgetDesc.Category(),
		Type:                     string(gadgetDesc.Type()),
		Description:              gadgetDesc.Description(),
		Params:                   gadgetDesc.ParamDescs(),
		OperatorParamsCollection: operators.GetOperatorsForGadget(gadgetDesc).ParamDescCollection(),
	}
}

func OperatorToOperatorInfo(operator operators.Operator) *OperatorInfo {
	return &OperatorInfo{
		Name:        operator.Name(),
		Description: operator.Description(),
	}
}
