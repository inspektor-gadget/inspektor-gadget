// Copyright 2022-2023 The Inspektor Gadget authors
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

package gadgetregistry

import (
	"fmt"
	"sort"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
)

var gadgetRegistry = map[string]gadgets.GadgetDesc{}

func Register(gadget gadgets.GadgetDesc) {
	key := gadget.Category() + "/" + gadget.Name()
	if _, ok := gadgetRegistry[key]; ok {
		panic(fmt.Sprintf("Gadget %q already registered", key))
	}
	gadgetRegistry[key] = gadget
}

func Get(category, name string) gadgets.GadgetDesc {
	return gadgetRegistry[category+"/"+name]
}

func GetAll() (gadgets []gadgets.GadgetDesc) {
	for _, g := range gadgetRegistry {
		gadgets = append(gadgets, g)
	}

	// Return gadgets in deterministic order
	sort.Slice(gadgets, func(i, j int) bool {
		a := fmt.Sprintf("%s-%s", gadgets[i].Category(), gadgets[i].Name())
		b := fmt.Sprintf("%s-%s", gadgets[j].Category(), gadgets[j].Name())
		return a < b
	})
	return
}
