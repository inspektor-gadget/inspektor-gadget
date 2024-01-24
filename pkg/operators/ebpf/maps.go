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
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func (i *ebpfInstance) populateMap(t btf.Type, varName string) error {
	i.logger.Debugf("populating map %q", varName)

	newVar := &ebpfVar{
		name:    varName,
		refType: reflect.TypeOf(&ebpf.Map{}),
		tags:    nil,
	}

	i.vars[varName] = newVar

	// Set variable to nil pointer to map, so it's present
	var nilVal *ebpf.Map
	i.gadgetCtx.SetVar(varName, nilVal)
	return nil
}
