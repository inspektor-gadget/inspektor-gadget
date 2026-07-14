// Copyright 2026 The Inspektor Gadget authors
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

package tests

import (
	"testing"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
)

// TestTraceGpuStarvation is a smoke test: it verifies the gadget loads and
// attaches without errors, which in particular exercises attaching the
// kprobe on finish_task_switch on the running kernel. With no bridge maps
// pre-populated, the gadget auto-creates its pinned maps empty and emits
// nothing. End-to-end behaviour (GPU-holder detection, CPU accounting and
// event emission) is covered by the integration test, which mocks the
// gpu-ebpf-bridge maps.
func TestTraceGpuStarvation(t *testing.T) {
	gadgettesting.DummyGadgetTest(t, "trace_gpu_starvation")
}
