// Copyright 2019-2024 The Inspektor Gadget authors
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
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type traceDNSEvent struct {
	eventtypes.CommonData

	// TODO: support endpoints

	Timestamp string `json:"timestamp"`
	MountNsID uint64 `json:"mntns_id"`
	Pid       uint32 `json:"pid"`
	Tid       uint32 `json:"tid"`
	Uid       uint32 `json:"uid"`
	Gid       uint32 `json:"gid"`
	Task      string `json:"task"`
	ID        string `json:"id"`
	Qtype     string `json:"qtype"`
	PktType   string `json:"pkt_type"`
	Rcode     string `json:"rcode"`
	Latency   uint64 `json:"latency_ns"`
	Qr        string `json:"qr"`
	Name      string `json:"name"`
	Addresses string `json:"addresses"`
}

func TestTraceDNS(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	serverContainerName := "test-trace-dns-server"
	clientContainerName := "test-trace-dns-client"
	// TODO: this should be configurable
	serverImage := "ghcr.io/inspektor-gadget/dnstester:latest"
	clientImage := "docker.io/library/busybox:latest"

	// TODO: The current logic creates the namespace when running the pod, hence
	// we need a namespace for each pod
	var nsClient string
	var nsServer string
	serverContainerOpts := []containers.ContainerOption{containers.WithContainerImage(serverImage)}
	clientContainerOpts := []containers.ContainerOption{containers.WithContainerImage(clientImage)}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		nsClient = utils.GenerateTestNamespaceName(t, "test-trace-dns-client")
		clientContainerOpts = append(clientContainerOpts, containers.WithContainerNamespace(nsClient))

		nsServer = utils.GenerateTestNamespaceName(t, "test-trace-dns-server")
		serverContainerOpts = append(serverContainerOpts, containers.WithContainerNamespace(nsServer))
	}

	serverContainer := containerFactory.NewContainer(serverContainerName, "/dnstester", serverContainerOpts...)
	serverContainer.Start(t)
	t.Cleanup(func() {
		serverContainer.Stop(t)
	})

	serverIP := serverContainer.IP()
	nslookupCmds := []string{
		fmt.Sprintf("setuidgid 1000:1111 nslookup -type=a fake.test.com. %s", serverIP),
		fmt.Sprintf("setuidgid 1000:1111 nslookup -type=aaaa fake.test.com. %s", serverIP),
	}

	clientContainer := containerFactory.NewContainer(
		clientContainerName,
		fmt.Sprintf("while true; do %s; sleep 1; done", strings.Join(nslookupCmds, " ; ")),
		clientContainerOpts...,
	)
	clientContainer.Start(t)
	t.Cleanup(func() {
		clientContainer.Stop(t)
	})

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option
	commonDataOpts := []utils.CommonDataOption{utils.WithContainerImageName(clientImage), utils.WithContainerID(clientContainer.ID())}

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime), "--timeout=5"))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", nsClient), "--timeout=5"))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(nsClient)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(nsClient))
	}

	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedEntries := []*traceDNSEvent{
				// A query from client
				{
					CommonData: utils.BuildCommonData(clientContainerName, commonDataOpts...),
					Task:       "nslookup",
					Qr:         "Q",
					Uid:        1000,
					Gid:        1111,
					Name:       "fake.test.com.",
					Qtype:      "A",
					Rcode:      "",
					PktType:    "OUTGOING",

					// Check the existence of the following fields
					MountNsID: utils.NormalizedInt,
					Timestamp: utils.NormalizedStr,
					Pid:       utils.NormalizedInt,
					Tid:       utils.NormalizedInt,
					ID:        utils.NormalizedStr,
					Latency:   0,
				},
				// A response from server
				{
					CommonData: utils.BuildCommonData(clientContainerName, commonDataOpts...),
					Task:       "nslookup",
					Qr:         "R",
					Uid:        1000,
					Gid:        1111,
					Name:       "fake.test.com.",
					Qtype:      "A",
					Rcode:      "Success",
					PktType:    "HOST",
					Addresses:  "127.0.0.1",

					// Check the existence of the following fields
					MountNsID: utils.NormalizedInt,
					Timestamp: utils.NormalizedStr,
					Pid:       utils.NormalizedInt,
					Tid:       utils.NormalizedInt,
					ID:        utils.NormalizedStr,
					Latency:   utils.NormalizedInt,
				},
				// AAAA query from client
				{
					CommonData: utils.BuildCommonData(clientContainerName, commonDataOpts...),
					Task:       "nslookup",
					Qr:         "Q",
					Uid:        1000,
					Gid:        1111,
					Name:       "fake.test.com.",
					Qtype:      "AAAA",
					Rcode:      "",
					PktType:    "OUTGOING",

					// Check the existence of the following fields
					MountNsID: utils.NormalizedInt,
					Timestamp: utils.NormalizedStr,
					Pid:       utils.NormalizedInt,
					Tid:       utils.NormalizedInt,
					ID:        utils.NormalizedStr,
					Latency:   0,
				},
				// AAAA response from server
				{
					CommonData: utils.BuildCommonData(clientContainerName, commonDataOpts...),
					Task:       "nslookup",
					Qr:         "R",
					Uid:        1000,
					Gid:        1111,
					Name:       "fake.test.com.",
					Qtype:      "AAAA",
					Rcode:      "Success",
					PktType:    "HOST",
					Addresses:  "::1",

					// Check the existence of the following fields
					MountNsID: utils.NormalizedInt,
					Timestamp: utils.NormalizedStr,
					Pid:       utils.NormalizedInt,
					Tid:       utils.NormalizedInt,
					ID:        utils.NormalizedStr,
					Latency:   utils.NormalizedInt,
				},
			}

			normalize := func(e *traceDNSEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeString(&e.Timestamp)
				utils.NormalizeInt(&e.Pid)
				utils.NormalizeInt(&e.Tid)
				utils.NormalizeInt(&e.MountNsID)
				utils.NormalizeString(&e.ID)
				utils.NormalizeInt(&e.Latency)
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntries...)
		},
	))

	traceDNSCmd := igrunner.New("trace_dns", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{traceDNSCmd}, t, testingOpts...)
}
