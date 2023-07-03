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

package containercollection

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type fakeTracerMapsUpdater struct {
	containers map[string]*Container
}

func (f *fakeTracerMapsUpdater) TracerMapsUpdater() FuncNotify {
	return func(event PubSubEvent) {
		switch event.Type {
		case EventTypeAddContainer:
			f.containers[event.Container.ID] = event.Container
		case EventTypeRemoveContainer:
			delete(f.containers, event.Container.ID)
		}
	}
}

func BenchmarkCreateContainerCollection(b *testing.B) {
	b.ReportAllocs()

	for n := 0; n < b.N; n++ {
		cc := ContainerCollection{}
		cc.AddContainer(&Container{
			ID:    fmt.Sprint(n),
			Mntns: uint64(n),
		})
	}
}

const (
	TestContainerCount = 10000
)

func BenchmarkLookupContainerByMntns(b *testing.B) {
	cc := ContainerCollection{}

	for n := 0; n < TestContainerCount; n++ {
		cc.AddContainer(&Container{
			ID:    fmt.Sprint(n),
			Mntns: uint64(n),
		})
	}

	rand.Seed(time.Now().UnixNano())

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		mntnsID := uint64(rand.Intn(TestContainerCount))
		container := cc.LookupContainerByMntns(mntnsID)
		if container == nil {
			b.Fatalf("there should be a container for mount namespace ID %d", mntnsID)
		}
	}
}

func BenchmarkLookupContainerByNetns(b *testing.B) {
	cc := ContainerCollection{}

	for n := 0; n < TestContainerCount; n++ {
		cc.AddContainer(&Container{
			ID:    fmt.Sprint(n),
			Netns: uint64(n),
		})
	}

	rand.Seed(time.Now().UnixNano())

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		netnsID := uint64(rand.Intn(TestContainerCount))
		container := cc.LookupContainersByNetns(netnsID)
		if len(container) == 0 {
			b.Fatalf("there should be a container for net namespace ID %d", netnsID)
		}
	}
}

func TestWithTracerCollection(t *testing.T) {
	t.Parallel()

	// We need root to create the runners that will act as containers on this test
	utilstest.RequireRoot(t)

	cc := ContainerCollection{}
	f := &fakeTracerMapsUpdater{containers: make(map[string]*Container)}

	if err := cc.Initialize(WithTracerCollection(f)); err != nil {
		t.Fatalf("Failed to initialize container collection: %s", err)
	}

	nContainers := 5

	// We have to use real runners here as the WithTracerCollection() will drop the enricher if
	// this doesn't have a valid PID
	runners := make([]*utilstest.Runner, nContainers)
	containers := make([]*Container, nContainers)

	for i := 0; i < nContainers; i++ {
		runner, err := utilstest.NewRunner(nil)
		if err != nil {
			t.Fatalf("Creating runner: %s", err)
		}
		t.Cleanup(runner.Close)

		runners[i] = runner

		containers[i] = &Container{
			ID:        fmt.Sprintf("id%d", i),
			Name:      fmt.Sprintf("name%d", i),
			Namespace: fmt.Sprintf("namespace%d", i),
			Podname:   fmt.Sprintf("pod%d", i),
			Mntns:     runner.Info.MountNsID,
			Netns:     runner.Info.NetworkNsID,
			Pid:       uint32(runner.Info.Pid),
		}
		cc.AddContainer(containers[i])
	}

	require.Equal(t, nContainers, len(f.containers), "number of containers should be equal")

	verifyEnrichByMntNs := func() {
		for i := 0; i < nContainers; i++ {
			ev := types.CommonData{}
			expected := types.CommonData{
				Namespace: containers[i].Namespace,
				Pod:       containers[i].Podname,
				Container: containers[i].Name,
			}

			cc.EnrichByMntNs(&ev, containers[i].Mntns)

			require.Equal(t, expected, ev, "events should be equal")
		}
	}

	verifyEnrichByNetNs := func() {
		for i := 0; i < nContainers; i++ {
			ev := types.CommonData{}
			expected := types.CommonData{
				Namespace: containers[i].Namespace,
				Pod:       containers[i].Podname,
				Container: containers[i].Name,
			}

			cc.EnrichByNetNs(&ev, containers[i].Netns)

			require.Equal(t, expected, ev, "events should be equal")
		}
	}

	// Enrich by should work
	verifyEnrichByMntNs()
	verifyEnrichByNetNs()

	cc.RemoveContainer(containers[0].ID)

	// Pubsub events should be triggered immediately after container removal
	require.Equal(t, nContainers-1, len(f.containers), "number of containers should be equal")

	time.Sleep(1 * time.Second)

	// Enrich should work 1 second after removing container
	verifyEnrichByMntNs()
	verifyEnrichByNetNs()

	time.Sleep(6 * time.Second)

	// Enrich should **not** work after removing container more than 6 seconds ago
	ev := types.CommonData{}
	expected := types.CommonData{}
	cc.EnrichByMntNs(&ev, containers[0].Mntns)
	require.Equal(t, expected, ev, "events should be equal")

	// This is in a separated line to understand who is causing the issue.
	cc.EnrichByNetNs(&ev, containers[0].Netns)
	require.Equal(t, expected, ev, "events should be equal")
}
