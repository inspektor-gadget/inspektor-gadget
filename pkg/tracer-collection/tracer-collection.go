// Copyright 2022 The Inspektor Gadget authors
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

package tracercollection

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/stream"
)

const (
	MaxContainersPerNode = 1024
	MountMapPrefix       = "mntnsset_"
)

type TracerCollection struct {
	tracers             map[string]tracer
	containerCollection *containercollection.ContainerCollection
	testOnly            bool
}

type tracer struct {
	tracerID string

	containerSelector containercollection.ContainerSelector

	mntnsSetMap *ebpf.Map

	gadgetStream *stream.GadgetStream
}

func NewTracerCollection(cc *containercollection.ContainerCollection) (*TracerCollection, error) {
	return &TracerCollection{
		tracers:             make(map[string]tracer),
		containerCollection: cc,
	}, nil
}

func NewTracerCollectionTest(cc *containercollection.ContainerCollection) (*TracerCollection, error) {
	return &TracerCollection{
		tracers:             make(map[string]tracer),
		containerCollection: cc,
		testOnly:            true,
	}, nil
}

func (tc *TracerCollection) TracerMapsUpdater() containercollection.FuncNotify {
	if tc.testOnly {
		return func(event containercollection.PubSubEvent) {}
	}

	return func(event containercollection.PubSubEvent) {
		switch event.Type {
		case containercollection.EventTypeAddContainer:
			// Skip the pause container
			if event.Container.Name == "" {
				return
			}

			for _, t := range tc.tracers {
				if containercollection.ContainerSelectorMatches(&t.containerSelector, event.Container) {
					mntnsC := uint64(event.Container.Mntns)
					one := uint32(1)
					if mntnsC != 0 {
						t.mntnsSetMap.Put(mntnsC, one)
					} else {
						log.Errorf("new container with mntns=0")
					}
				}
			}

		case containercollection.EventTypeRemoveContainer:
			for _, t := range tc.tracers {
				if containercollection.ContainerSelectorMatches(&t.containerSelector, event.Container) {
					mntnsC := uint64(event.Container.Mntns)
					t.mntnsSetMap.Delete(mntnsC)
				}
			}
		}
	}
}

func (tc *TracerCollection) AddTracer(id string, containerSelector containercollection.ContainerSelector) error {
	if _, ok := tc.tracers[id]; ok {
		return fmt.Errorf("tracer id %q: %w", id, os.ErrExist)
	}
	var mntnsSetMap *ebpf.Map
	if !tc.testOnly {
		mntnsSpec := &ebpf.MapSpec{
			Name:       MountMapPrefix + id,
			Type:       ebpf.Hash,
			KeySize:    8,
			ValueSize:  4,
			MaxEntries: MaxContainersPerNode,
		}
		var err error
		mntnsSetMap, err = ebpf.NewMap(mntnsSpec)
		if err != nil {
			return fmt.Errorf("error creating mntnsset map: %w", err)
		}

		tc.containerCollection.ContainerRangeWithSelector(&containerSelector, func(c *containercollection.Container) {
			one := uint32(1)
			mntnsC := uint64(c.Mntns)
			if mntnsC != 0 {
				mntnsSetMap.Put(mntnsC, one)
			}
		})
	}
	tc.tracers[id] = tracer{
		tracerID:          id,
		containerSelector: containerSelector,
		mntnsSetMap:       mntnsSetMap,
		gadgetStream:      stream.NewGadgetStream(),
	}
	return nil
}

func (tc *TracerCollection) RemoveTracer(id string) error {
	if id == "" {
		return fmt.Errorf("cannot remove tracer: id not set")
	}

	t, ok := tc.tracers[id]
	if !ok {
		return fmt.Errorf("cannot remove tracer: unknown tracer %q", id)
	}

	if t.mntnsSetMap != nil {
		t.mntnsSetMap.Close()
	}

	t.gadgetStream.Close()

	delete(tc.tracers, id)
	return nil
}

func (tc *TracerCollection) Stream(id string) (*stream.GadgetStream, error) {
	t, ok := tc.tracers[id]
	if !ok {
		return nil, fmt.Errorf("unknown tracer %q", id)
	}
	return t.gadgetStream, nil
}

func (tc *TracerCollection) TracerCount() int {
	return len(tc.tracers)
}

func (tc *TracerCollection) TracerDump() (out string) {
	for i, t := range tc.tracers {
		out += fmt.Sprintf("%v -> %q/%q (%s) Labels: \n",
			i,
			t.containerSelector.Namespace,
			t.containerSelector.Podname,
			t.containerSelector.Name)
		for k, v := range t.containerSelector.Labels {
			out += fmt.Sprintf("                  %v: %v\n", k, v)
		}
		out += "        Matches:\n"
		tc.containerCollection.ContainerRangeWithSelector(&t.containerSelector, func(c *containercollection.Container) {
			out += fmt.Sprintf("        - %s/%s [Mntns=%v CgroupID=%v]\n", c.Namespace, c.Podname, c.Mntns, c.CgroupID)
		})
	}
	return
}

func (tc *TracerCollection) TracerExists(id string) bool {
	_, ok := tc.tracers[id]
	return ok
}

func (tc *TracerCollection) Close() {}

func (tc *TracerCollection) TracerMountNsMap(id string) (*ebpf.Map, error) {
	t, ok := tc.tracers[id]
	if !ok {
		return nil, fmt.Errorf("unknown tracer %q", id)
	}

	return t.mntnsSetMap, nil
}
