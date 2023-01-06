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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/standardgadgets/trace"
)

func NewTracer(config *tracer.Config, eventCallback func(*types.Event)) (*trace.StandardTracer[types.Event], error) {
	standardConfig := &trace.StandardTracerConfig[types.Event]{
		ScriptName:    "opensnoop",
		EventCallback: eventCallback,
		BaseEvent:     types.Base,
		MntnsMap:      config.MountnsMap,
	}

	return trace.NewStandardTracer(standardConfig)
}
