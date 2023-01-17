// Copyright 2022 The Inspektor Gadget authors
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

import "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"

var gadgetRegistry = map[string]gadgets.Gadget{}

func RegisterGadget(gadget gadgets.Gadget) {
	gadgetRegistry[gadget.Category()+"/"+gadget.Name()] = gadget
}

func GetGadget(category, name string) gadgets.Gadget {
	return gadgetRegistry[category+"/"+name]
}

func GetGadgets() (gadgets []gadgets.Gadget) {
	for _, g := range gadgetRegistry {
		gadgets = append(gadgets, g)
	}
	return
}
