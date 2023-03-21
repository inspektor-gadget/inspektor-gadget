// Copyright 2023 The Inspektor Gadget authors
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

package tracer

import (
	"testing"

	"github.com/moby/moby/pkg/parsers/kernel"
	"github.com/stretchr/testify/require"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
)

func TestDropReasons(t *testing.T) {
	utilstest.RequireRoot(t)

	// The reason field was added in 5.17:
	// https://github.com/torvalds/linux/commit/c504e5c2f9648a1e5c2be01e8c3f59d394192bd3
	utilstest.RequireKernelVersion(t, &kernel.VersionInfo{Kernel: 5, Major: 17, Minor: 0})

	tracer := &Tracer{}
	err := tracer.loadDropReasons()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Do not test all values: they can change between kernel versions.
	// Just test that a few values looks ok.

	str, err := tracer.lookupDropReason(5)
	require.Nil(t, err, "unexpected error looking up drop reason: %v", err)
	require.NotEmpty(t, str, "unexpected empty drop reason")
	if len(tracer.dropReasons) < 10 {
		t.Fatalf("Too few drop reasons: %d", len(tracer.dropReasons))
	}

	str, err = tracer.lookupDropReason(999)
	if err == nil || str != "" {
		t.Fatalf("Expected error, got: %q", str)
	}
}
