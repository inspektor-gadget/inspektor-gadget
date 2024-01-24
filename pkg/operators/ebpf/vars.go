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
	"reflect"

	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfhelpers"
)

type ebpfVar struct {
	name    string
	refType reflect.Type
	tags    []string
}

func (i *ebpfInstance) populateVar(t btf.Type, varName string) error {
	btfVar, ok := t.(*btf.Var)
	if !ok {
		return fmt.Errorf("%q not of type *btf.Var", varName)
	}

	btfConst, ok := btfVar.Type.(*btf.Const)
	if !ok {
		return fmt.Errorf("%q not a const", varName)
	}

	btfVolatile, ok := btfConst.Type.(*btf.Volatile)
	if !ok {
		return fmt.Errorf("%q not volatile", varName)
	}

	refType, tags := btfhelpers.GetType(btfVolatile.Type)
	if refType == nil {
		i.logger.Warnf("unknown type for variable %q: %s (%T)", varName, btfVolatile.Type.TypeName(), btfVolatile.Type)
		return nil
	}

	i.vars[varName] = &ebpfVar{
		name:    varName,
		refType: refType,
		tags:    tags,
	}

	i.gadgetCtx.Logger().Debugf("variable %q %v %+v", varName, refType, t)
	i.gadgetCtx.SetVar(varName, reflect.New(refType).Elem().Interface())
	return nil
}
