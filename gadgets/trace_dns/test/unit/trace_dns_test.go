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
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/formatters"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedTraceDnsEvent struct {
	utils.CommonData

	NetNsID uint64 `json:"netns_id"`

	Src utils.L4Endpoint `json:"src"`
	Dst utils.L4Endpoint `json:"dst"`

	Qtype string `json:"qtype"`
	Qr    string `json:"qr"`
	Name  string `json:"name"`
}

func TestTraceDns(t *testing.T) {
	// TODO: This is a dummy test to check that the gadget runs without errors.
	// It should be extended to check that the gadget produces the right events.
	paramValues := map[string]string{
		"operator.oci.ebpf.paths": "true",
	}
	gadgettesting.DummyGadgetTest(t, "trace_dns", gadgettesting.WithParamValues(paramValues))
}

// TestTraceDnsNetnsPath attaches the gadget to a network namespace given by its
// filesystem path instead of through container discovery, and checks that the
// events coming out of it carry that namespace's ID and no Kubernetes
// enrichment, as there is no container to enrich from.
func TestTraceDnsNetnsPath(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	// The runner runs in a network namespace of its own, which stands in for
	// the namespace of a pod that container discovery does not know about.
	runner := utils.NewRunnerWithTest(t, &utils.RunnerConfig{})
	netnsPath := fmt.Sprintf("/proc/%d/task/%d/ns/net", runner.Info.Pid, runner.Info.Tid)

	const queryName = "netns.path.test."

	onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
		utils.RunWithRunner(t, runner, func() error {
			return sendDNSQuery(queryName)
		})
		return nil
	}

	opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceDnsEvent]{
		Image:   "trace_dns",
		Timeout: 5 * time.Second,
		ParamValues: map[string]string{
			"operator.oci.ebpf.netns-path": netnsPath,
		},
		OnGadgetRun: onGadgetRun,
	}

	gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)
	gadgetRunner.RunGadget()

	require.NotEmpty(t, gadgetRunner.CapturedEvents,
		"no event captured from network namespace %q", netnsPath)

	found := false
	for _, event := range gadgetRunner.CapturedEvents {
		// Every event must come from the namespace we attached to, and from
		// that one only: the gadget was never attached to any container.
		require.Equal(t, runner.Info.NetworkNsID, event.NetNsID, "event from an unexpected network namespace")

		// There is no container behind this attachment, so nothing can fill in
		// the Kubernetes metadata. This is the same as attaching with --host.
		require.Empty(t, event.K8s, "events from a netns path carry no Kubernetes metadata")
		require.Empty(t, event.Src.K8s, "source endpoint carries no Kubernetes metadata")
		require.Empty(t, event.Dst.K8s, "destination endpoint carries no Kubernetes metadata")

		if event.Qr == "Q" && event.Name == queryName {
			found = true
		}
	}
	require.True(t, found, "no query for %q among the captured events: %+v", queryName, gadgetRunner.CapturedEvents)
}

// sendDNSQuery sends a DNS query for name to 127.0.0.1:53 in the current
// network namespace. Nothing is listening there; the query packet itself is
// what the gadget's socket filter sees.
func sendDNSQuery(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("creating socket: %w", err)
	}
	defer unix.Close(fd)

	addr := &unix.SockaddrInet4{Port: 53, Addr: [4]byte{127, 0, 0, 1}}
	if err := unix.Sendto(fd, dnsQuery(name), 0, addr); err != nil {
		return fmt.Errorf("sending DNS query: %w", err)
	}
	return nil
}

// dnsQuery builds a minimal DNS query packet for an A record.
func dnsQuery(name string) []byte {
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:], 0x1234) // transaction ID
	binary.BigEndian.PutUint16(query[2:], 0x0100) // standard query, recursion desired
	binary.BigEndian.PutUint16(query[4:], 1)      // one question

	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0) // root label

	query = binary.BigEndian.AppendUint16(query, 1) // QTYPE A
	query = binary.BigEndian.AppendUint16(query, 1) // QCLASS IN

	return query
}
