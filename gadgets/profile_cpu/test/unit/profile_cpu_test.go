// Copyright 2025 The Inspektor Gadget authors
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

func TestProfileCpu(t *testing.T) {
	t.Run("without GPU idle filter", func(t *testing.T) {
		gadgettesting.DummyGadgetTest(t, "profile_cpu")
	})

	t.Run("with GPU idle filter", func(t *testing.T) {
		gadgettesting.DummyGadgetTest(t, "profile_cpu",
			gadgettesting.WithParamValues(map[string]string{
				"operator.oci.ebpf.gpu-idle-only": "true",
			}))
	})

	t.Run("user stacks only", func(t *testing.T) {
		// Exercises the kernel-stack gating: --user-stacks-only drops
		// ig_kstack (GADGET_MAP_ONLY_IF "!params.user_stacks_only") and
		// poisons its dead reference.
		gadgettesting.DummyGadgetTest(t, "profile_cpu",
			gadgettesting.WithParamValues(map[string]string{
				"operator.oci.ebpf.user-stacks-only": "true",
			}))
	})
}
