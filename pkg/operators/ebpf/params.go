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

package ebpfoperator

import (
	"fmt"

	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfhelpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

func getTypeHint(typ btf.Type) params.TypeHint {
	switch typedMember := typ.(type) {
	case *btf.Int:
		switch typedMember.Encoding {
		case btf.Signed:
			switch typedMember.Size {
			case 1:
				return params.TypeInt8
			case 2:
				return params.TypeInt16
			case 4:
				return params.TypeInt32
			case 8:
				return params.TypeInt64
			}
		case btf.Unsigned:
			switch typedMember.Size {
			case 1:
				return params.TypeUint8
			case 2:
				return params.TypeUint16
			case 4:
				return params.TypeUint32
			case 8:
				return params.TypeUint64
			}
		case btf.Bool:
			return params.TypeBool
		case btf.Char:
			return params.TypeUint8
		}
	case *btf.Float:
		switch typedMember.Size {
		case 4:
			return params.TypeFloat32
		case 8:
			return params.TypeFloat64
		}
	case *btf.Typedef:
		typ := btfhelpers.GetUnderlyingType(typedMember)
		if typ == nil {
			return params.TypeUnknown
		}
		return getTypeHint(typ)
	case *btf.Volatile:
		return getTypeHint(typedMember.Type)
	case *btf.Struct:
		switch typedMember.Name {
		case ebpftypes.L3EndpointTypeName:
			return params.TypeIP
		}
	}

	return params.TypeUnknown
}

func (i *ebpfInstance) populateParam(t btf.Type, varName string) error {
	if _, found := i.params[varName]; found {
		i.logger.Debugf("param %q already defined, skipping", varName)
		return nil
	}

	var btfVar *btf.Var
	err := i.collectionSpec.Types.TypeByName(varName, &btfVar)
	if err != nil {
		return fmt.Errorf("no BTF type found for: %s: %w", varName, err)
	}

	btfConst, ok := btfVar.Type.(*btf.Const)
	if !ok {
		return fmt.Errorf("type for %s is not a constant, got %s", varName, btfVar.Type)
	}

	th := getTypeHint(btfConst.Type)

	i.logger.Debugf("adding param %q (%v)", btfVar.Name, th)

	newParam := &api.Param{
		Key:      varName,
		TypeHint: string(th),
	}

	// Fill additional information from metadata
	paramInfo := i.config.Sub("params.ebpf." + varName)
	if paramInfo == nil {
		// Backward compatibility
		paramInfo = i.config.Sub("ebpfParams." + varName)
	}
	if paramInfo != nil {
		i.logger.Debugf(" filling additional information from metadata")
		if s := paramInfo.GetString("key"); s != "" {
			newParam.Key = s
		}
		if s := paramInfo.GetString("defaultValue"); s != "" {
			newParam.DefaultValue = s
		}
		if s := paramInfo.GetString("description"); s != "" {
			newParam.Description = s
		}
	}

	i.params[varName] = &param{
		Param:    newParam,
		fromEbpf: true,
	}
	return nil
}
