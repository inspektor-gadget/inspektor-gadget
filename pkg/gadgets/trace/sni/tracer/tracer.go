// Copyright 2019-2022 The Inspektor Gadget authors
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
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/sni/types"
	"github.com/kinvolk/inspektor-gadget/pkg/rawsock"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

//go:generate bash -c "source ./clangosflags.sh; go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang snisnoop ./bpf/snisnoop.c -- $CLANG_OS_FLAGS -I./bpf/"

// #include "bpf/snisnoop.h"
import "C"

const (
	BPFProgName     = "bpf_prog1"
	BPFMapName      = "events"
	BPFSocketAttach = 50
)

type link struct {
	collection *ebpf.Collection
	perfRd     *perf.Reader

	sockFd int

	// users count how many users called Attach(). This can happen for two reasons:
	// 1. several containers in a pod (sharing the netns)
	// 2. pods with networkHost=true
	users int
}

type Tracer struct {
	mu sync.Mutex

	spec *ebpf.CollectionSpec

	// key: namespace/podname
	// value: Tracelet
	attachments map[string]*link
}

func NewTracer() (*Tracer, error) {
	spec, err := loadSnisnoop()
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %w", err)
	}

	t := &Tracer{
		spec:        spec,
		attachments: make(map[string]*link),
	}

	return t, nil
}

func (t *Tracer) Attach(
	key string,
	pid uint32,
	eventCallback func(types.Event),
	node string,
) (err error) {
	if l, ok := t.attachments[key]; ok {
		l.users++
		return nil
	}

	l := &link{
		users:  1,
		sockFd: -1,
	}
	defer func() {
		if err != nil {
			if l.perfRd != nil {
				l.perfRd.Close()
			}
			if l.sockFd != -1 {
				unix.Close(l.sockFd)
			}
			if l.collection != nil {
				l.collection.Close()
			}
		}
	}()

	l.collection, err = ebpf.NewCollection(t.spec)
	if err != nil {
		return fmt.Errorf("failed to create BPF collection: %w", err)
	}

	l.perfRd, err = perf.NewReader(l.collection.Maps[BPFMapName], gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("failed to get a perf reader: %w", err)
	}

	prog, ok := l.collection.Programs[BPFProgName]
	if !ok {
		return fmt.Errorf("failed to find BPF program %q", BPFProgName)
	}

	l.sockFd, err = rawsock.OpenRawSock(pid)
	if err != nil {
		return fmt.Errorf("failed to open raw socket: %w", err)
	}

	if err := syscall.SetsockoptInt(l.sockFd, syscall.SOL_SOCKET, BPFSocketAttach, prog.FD()); err != nil {
		return fmt.Errorf("failed to attach BPF program: %w", err)
	}

	t.attachments[key] = l

	go t.listen(key, l.perfRd, eventCallback, node)

	return nil
}

func parseSNIEvent(rawSample []byte) (ret string) {
	name := make([]byte, C.TLS_MAX_SERVER_NAME_LEN)
	copy(name, rawSample)

	str := string(name)
	i := strings.Index(str, "\x00")
	if i > 0 {
		return str[:i]
	}
	return str
}

func (t *Tracer) listen(
	key string,
	rd *perf.Reader,
	eventCallback func(types.Event),
	node string,
) {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			msg := fmt.Sprintf("Error reading perf ring buffer (%s): %s", key, err)
			eventCallback(types.Base(eventtypes.Err(msg)))
			return
		}

		if record.LostSamples != 0 {
			msg := fmt.Sprintf("lost %d samples (%s)", record.LostSamples, key)
			eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		name := parseSNIEvent(record.RawSample)

		if len(name) > 0 {
			event := types.Event{
				Event: eventtypes.Event{
					Type: eventtypes.NORMAL,
					CommonData: eventtypes.CommonData{
						Node: node,
					},
				},
				Name: name,
			}
			eventCallback(event)
		}
	}
}

func (t *Tracer) releaseLink(key string, l *link) {
	l.perfRd.Close()
	unix.Close(l.sockFd)
	l.collection.Close()
	delete(t.attachments, key)
}

func (t *Tracer) Detach(key string) error {
	if l, ok := t.attachments[key]; ok {
		l.users--
		if l.users == 0 {
			t.releaseLink(key, l)
		}
		return nil
	} else {
		return fmt.Errorf("key not attached: %q", key)
	}
}

func (t *Tracer) Close() {
	for key, l := range t.attachments {
		t.releaseLink(key, l)
	}
}
