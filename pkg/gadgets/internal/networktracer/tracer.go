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

package networktracer

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/internal/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/rawsock"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type attachment struct {
	collection *ebpf.Collection
	perfRd     *perf.Reader

	plugCloser io.Closer
	sockFd int

	// users keeps track of the users' pid that have called Attach(). This can
	// happen for two reasons:
	// 1. several containers in a pod (sharing the netns)
	// 2. pods with networkHost=true
	// In both cases, we want to attach the BPF program only once.
	users map[uint32]struct{}
}

func newAttachment(
	pid uint32,
	netns uint64,
	socketEnricher *socketenricher.SocketEnricher,
	spec *ebpf.CollectionSpec,
	bpfProgName string,
	bpfPerfMapName string,
	bpfSocketAttach int,
) (_ *attachment, err error) {
	a := &attachment{
		sockFd: -1,
		users:  map[uint32]struct{}{pid: {}},
	}
	defer func() {
		if err != nil {
			if a.perfRd != nil {
				a.perfRd.Close()
			}
			if a.sockFd != -1 {
				unix.Close(a.sockFd)
			}
			if a.collection != nil {
				a.collection.Close()
			}
		}
	}()

	spec = spec.Copy()

	u32netns := uint32(netns)
	consts := map[string]interface{}{
		"current_netns": u32netns,
	}

	if err := spec.RewriteConstants(consts); err != nil && !strings.Contains(err.Error(), "spec is missing one or more constants") {
		return nil, fmt.Errorf("error RewriteConstants while attaching to pid %d: %w", pid, err)
	}

	a.collection, err = ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create BPF collection: %w", err)
	}

	a.perfRd, err = perf.NewReader(a.collection.Maps[bpfPerfMapName], gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return nil, fmt.Errorf("failed to get a perf reader: %w", err)
	}

	prog, ok := a.collection.Programs[bpfProgName]
	if !ok {
		return nil, fmt.Errorf("failed to find BPF program %q", bpfProgName)
	}

	a.sockFd, err = rawsock.OpenRawSock(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to open raw socket: %w", err)
	}

	if socketEnricher != nil {
		closer, err := socketEnricher.PlugExtension(a.collection.Programs[bpfProgName], netns)
		if err != nil {
			log.Debugf("failed to plug extension: %w", err)
		} else {
			a.plugCloser = closer
		}
	}

	if err := syscall.SetsockoptInt(a.sockFd, syscall.SOL_SOCKET, bpfSocketAttach, prog.FD()); err != nil {
		return nil, fmt.Errorf("failed to attach BPF program: %w", err)
	}

	return a, nil
}

type Tracer[Event any] struct {
	socketEnricher *socketenricher.SocketEnricher
	spec *ebpf.CollectionSpec

	// key: network namespace inode number
	// value: Tracelet
	attachments map[uint64]*attachment

	bpfProgName     string
	bpfPerfMapName  string
	bpfSocketAttach int

	baseEvent  func(ev types.Event) Event
	parseEvent func([]byte) (*Event, error)
}

func NewTracer[Event any](
	spec *ebpf.CollectionSpec,
	bpfProgName string,
	bpfPerfMapName string,
	bpfSocketAttach int,
	baseEvent func(ev types.Event) Event,
	parseEvent func([]byte) (*Event, error),
) *Tracer[Event] {
	socketEnricher, err := socketenricher.NewSocketsMap()
	if err != nil {
		log.Errorf("failed to start socket enricher: %w", err)
	}
	return &Tracer[Event]{
		socketEnricher:  socketEnricher,
		spec:            spec,
		attachments:     make(map[uint64]*attachment),
		bpfProgName:     bpfProgName,
		bpfPerfMapName:  bpfPerfMapName,
		bpfSocketAttach: bpfSocketAttach,
		baseEvent:       baseEvent,
		parseEvent:      parseEvent,
	}
}

func (t *Tracer[Event]) Attach(pid uint32, eventCallback func(Event)) error {
	netns, err := containerutils.GetNetNs(int(pid))
	if err != nil {
		return fmt.Errorf("getting network namespace of pid %d: %w", pid, err)
	}
	if a, ok := t.attachments[netns]; ok {
		a.users[pid] = struct{}{}
		return nil
	}

	a, err := newAttachment(pid, netns, t.socketEnricher, t.spec, t.bpfProgName, t.bpfPerfMapName, t.bpfSocketAttach)
	if err != nil {
		return fmt.Errorf("creating network tracer attachment for pid %d: %w", pid, err)
	}
	t.attachments[netns] = a

	go t.listen(netns, a.perfRd, t.baseEvent, t.parseEvent, eventCallback)

	return nil
}

func (t *Tracer[Event]) listen(
	netns uint64,
	rd *perf.Reader,
	baseEvent func(ev types.Event) Event,
	parseEvent func([]byte) (*Event, error),
	eventCallback func(Event),
) {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			msg := fmt.Sprintf("Error reading perf ring buffer (%d): %s", netns, err)
			eventCallback(baseEvent(types.Err(msg)))
			return
		}

		if record.LostSamples != 0 {
			msg := fmt.Sprintf("lost %d samples (%d)", record.LostSamples, netns)
			eventCallback(baseEvent(types.Warn(msg)))
			continue
		}

		event, err := parseEvent(record.RawSample)
		if err != nil {
			eventCallback(baseEvent(types.Err(err.Error())))
			continue
		}
		if event == nil {
			continue
		}
		eventCallback(*event)
	}
}

func (t *Tracer[Event]) releaseAttachment(netns uint64, a *attachment) {
	a.perfRd.Close()
	if a.plugCloser != nil {
		a.plugCloser.Close()
	}
	unix.Close(a.sockFd)
	a.collection.Close()
	delete(t.attachments, netns)
}

func (t *Tracer[Event]) Detach(pid uint32) error {
	for netns, a := range t.attachments {
		if _, ok := a.users[pid]; ok {
			delete(a.users, pid)
			if len(a.users) == 0 {
				t.releaseAttachment(netns, a)
			}
			return nil
		}
	}
	return fmt.Errorf("pid %d is not attached", pid)
}

func (t *Tracer[Event]) Close() {
	for key, l := range t.attachments {
		t.releaseAttachment(key, l)
	}
}
