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

func TestTraceTtysnoop(t *testing.T) {
	// TODO: This is a dummy test to check that the gadget runs without errors.
	// It should be extended to check that the gadget produces correct data.

	// The current implementation relies on:
	// - ITER_UBUF in enum iter_type introduced in Linux v6.0. See:
	//   https://github.com/torvalds/linux/commit/fcb14cb1bdacec5b4374fe161e83fb8208164a85
	// - ubuf_iovec in struct iov_iter introduced in Linux v6.4. See:
	//   https://github.com/torvalds/linux/commit/747b1f65d39ae729b7914075899b0c82d7f667db
	gadgettesting.MinimumKernelVersion(t, "6.4")

	gadgettesting.DummyGadgetTest(t, "ttysnoop")
}
