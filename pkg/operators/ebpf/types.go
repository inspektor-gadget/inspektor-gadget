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

// Keep this aligned with include/gadget/macros.h
const (
	// Prefix used to mark trace maps
	tracerInfoPrefix = "gadget_tracer_"

	// Prefix used to mark eBPF params
	paramPrefix = "gadget_param_"

	// Prefix used to mark snapshotters structs
	snapshottersPrefix = "gadget_snapshotter_"

	// Prefix used to mark tracer map created with GADGET_TRACER_MAP() defined in
	// include/gadget/buffer.h.
	tracerMapPrefix = "gadget_map_tracer_"

	// Prefix used to mark variables used by operators
	varPrefix = "gadget_var_"
)
