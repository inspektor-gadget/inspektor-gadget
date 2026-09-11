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
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedSnapshotSocketEvent struct {
	NetNsID     uint64           `json:"netns_id"`
	InodeNumber uint64           `json:"ino"`
	SrcEndpoint utils.L4Endpoint `json:"src"`
	DstEndpoint utils.L4Endpoint `json:"dst"`
	Status      uint64           `json:"status"`
	Path        string           `json:"path"`
}

func TestSnapshotSocket(t *testing.T) {
	gadgettesting.MinimumKernelVersion(t, "5.8")
	gadgettesting.InitUnitTest(t)

	socketPath := "/tmp/test-ig-snapshot-unix.sock"
	os.Remove(socketPath)

	l, err := net.Listen("unix", socketPath)
	require.NoError(t, err, "failed to create unix socket listener")
	defer l.Close()
	defer os.Remove(socketPath)

	opts := gadgetrunner.GadgetRunnerOpts[ExpectedSnapshotSocketEvent]{
		Image:   "snapshot_socket",
		Timeout: 3 * time.Second,
	}

	gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)
	gadgetRunner.RunGadget()

	found := false
	for _, event := range gadgetRunner.CapturedEvents {
		if event.Path == socketPath {
			found = true
			break
		}
	}

	require.True(t, found, "expected unix socket path %s to be captured by snapshot_socket", socketPath)
}
