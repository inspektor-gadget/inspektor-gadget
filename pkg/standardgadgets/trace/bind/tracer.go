// Copyright 2019-2022 The Inspektor Gadget authors
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

package standard

import (
	"encoding/json"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/bind/tracer"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/bind/types"
	"github.com/kinvolk/inspektor-gadget/pkg/standardgadgets/trace"
	"github.com/vishvananda/netlink"
)

func NewTracer(config *tracer.Config, eventCallback func(types.Event)) (*trace.StandardTracer[types.Event], error) {
	prepareLine := func(line string) string {
		event := map[string]interface{}{}

		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return ""
		}

		interfaceString := "0"
		if val, ok := event["if"]; ok {
			interfaceNum := int(val.(float64))
			if interfaceNum != 0 {
				// It does exist a net link which index is 0.
				// But eBPF bindsnoop code often gives 0 as interface number:
				// https://github.com/iovisor/bcc/blob/63618552f81a2631990eff59fd7460802c58c30b/tools/bindsnoop_example.txt#L16
				// So, we only use this function if interface number is different than 0.
				interf, err := netlink.LinkByIndex(interfaceNum)
				if err != nil {
					return ""
				}

				interfaceString = interf.Attrs().Name
			}

			event["if"] = interfaceString
		}

		obj, err := json.Marshal(event)
		if err != nil {
			return ""
		}

		return string(obj)
	}

	standardConfig := &trace.StandardTracerConfig[types.Event]{
		ScriptName:    "bindsnoop",
		EventCallback: eventCallback,
		BaseEvent:     types.Base,
		PrepareLine:   prepareLine,
		MntnsMap:      config.MountnsMap,
	}

	return trace.NewStandardTracer(standardConfig)
}
