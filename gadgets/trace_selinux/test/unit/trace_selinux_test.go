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

func TestTraceSelinux(t *testing.T) {
	// TODO: This is a dummy test to check that the gadget loads and runs
	// without errors. It should be extended to check that the gadget produces
	// correct data, which requires triggering a SELinux AVC denial on a host
	// with SELinux enabled.

	// The avc:selinux_audited tracepoint was added in v5.10-rc1.
	gadgettesting.MinimumKernelVersion(t, "5.10")

	gadgettesting.DummyGadgetTest(t, "trace_selinux")
}
