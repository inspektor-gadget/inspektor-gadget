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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"

	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/pubsub"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/stream"
)

const (
	MaxContainersPerNode = 1024
)

type TracerCollection struct {
	tracers             map[string]tracer
	containerCollection *containercollection.ContainerCollection

	withEbpf  bool
	pinPath   string
	mapPrefix string
}

type tracer struct {
	tracerID string

	containerSelector pb.ContainerSelector

	mntnsSetMap *ebpf.Map

	gadgetStream *stream.GadgetStream
}

func NewTracerCollection(pinPath, mapPrefix string, withEbpf bool, cc *containercollection.ContainerCollection) (*TracerCollection, error) {
	return &TracerCollection{
		tracers:             make(map[string]tracer),
		containerCollection: cc,
		withEbpf:            withEbpf,
		pinPath:             pinPath,
		mapPrefix:           mapPrefix,
	}, nil
}

func (tc *TracerCollection) TracerMapsUpdater() pubsub.FuncNotify {
	if !tc.withEbpf {
		return func(event pubsub.PubSubEvent) {}
	}

	return func(event pubsub.PubSubEvent) {
		switch event.Type {
		case pubsub.EventTypeAddContainer:
			// Skip the pause container
			if event.Container.Name == "" {
				return
			}

			for _, t := range tc.tracers {
				if containercollection.ContainerSelectorMatches(&t.containerSelector, &event.Container) {
					mntnsC := uint64(event.Container.Mntns)
					one := uint32(1)
					if mntnsC != 0 {
						t.mntnsSetMap.Put(mntnsC, one)
					} else {
						log.Errorf("new container with mntns=0")
					}
				}
			}

		case pubsub.EventTypeRemoveContainer:
			for _, t := range tc.tracers {
				if containercollection.ContainerSelectorMatches(&t.containerSelector, &event.Container) {
					mntnsC := uint64(event.Container.Mntns)
					t.mntnsSetMap.Delete(mntnsC)
				}
			}
		}
	}
}

func (tc *TracerCollection) AddTracer(id string, containerSelector pb.ContainerSelector) error {
	if _, ok := tc.tracers[id]; ok {
		return fmt.Errorf("tracer id %q: %w", id, os.ErrExist)
	}
	var mntnsSetMap *ebpf.Map
	if tc.withEbpf {
		if tc.pinPath != "" {
			if err := os.Mkdir(tc.pinPath, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("failed to create folder for pinning bpf maps: %w", err)
			}
		}
		mntnsSpec := &ebpf.MapSpec{
			Name:       tc.mapPrefix + id,
			Type:       ebpf.Hash,
			KeySize:    8,
			ValueSize:  4,
			MaxEntries: MaxContainersPerNode,
			Pinning:    ebpf.PinByName,
		}
		var err error
		mntnsSetMap, err = ebpf.NewMapWithOptions(mntnsSpec, ebpf.MapOptions{PinPath: tc.pinPath})
		if err != nil {
			return fmt.Errorf("error creating mntnsset map: %w", err)
		}
		tc.containerCollection.ContainerRangeWithSelector(&containerSelector, func(c *pb.ContainerDefinition) {
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

	if tc.withEbpf {
		os.Remove(filepath.Join(tc.pinPath, tc.mapPrefix+id))
	}

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
		for _, l := range t.containerSelector.Labels {
			out += fmt.Sprintf("                  %v: %v\n", l.Key, l.Value)
		}
		out += "        Matches:\n"
		tc.containerCollection.ContainerRangeWithSelector(&t.containerSelector, func(c *pb.ContainerDefinition) {
			out += fmt.Sprintf("        - %s/%s [Mntns=%v CgroupId=%v]\n", c.Namespace, c.Podname, c.Mntns, c.CgroupId)
		})
	}
	return
}

func (tc *TracerCollection) TracerExists(id string) bool {
	_, ok := tc.tracers[id]
	return ok
}

func (tc *TracerCollection) Close() {
}
