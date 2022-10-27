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

package tracer

import (
	"fmt"
	"runtime"

	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netns"
	"golang.org/x/net/bpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpdump/tracer/compiler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpdump/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Config struct {
	FilterString string
	SnapLen      int
}

type link struct {
	tpacket *afpacket.TPacket

	// users count how many users called Attach(). This can happen for two reasons:
	// 1. several containers in a pod (sharing the netns)
	// 2. pods with networkHost=true
	users int
}

type Tracer struct {
	config  *Config
	program []bpf.RawInstruction

	// key: namespace/podname
	// value: Tracelet
	attachments map[string]*link
}

func NewTracer(config *Config) (*Tracer, error) {
	t := &Tracer{
		config:      config,
		attachments: map[string]*link{},
	}

	var err error
	t.program, err = compiler.TcpdumpExprToBPF(config.FilterString, layers.LinkTypeEthernet, config.SnapLen)
	if err != nil {
		return nil, fmt.Errorf("compile tcpdump expression to bpf: %w", err)
	}

	return t, nil
}

func (t *Tracer) releaseLink(key string, l *link) {
	if t.attachments[key].tpacket != nil {
		t.attachments[key].tpacket.Close()
	}
	delete(t.attachments, key)
}

func (t *Tracer) Close() {
	for key, l := range t.attachments {
		t.releaseLink(key, l)
	}
}

func runWithNamespaceFromPid(pid uint32, fn func() error) error {
	if pid != 0 {
		// Lock the OS Thread so we don't accidentally switch namespaces
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Save the current network namespace
		origns, _ := netns.Get()
		defer origns.Close()

		netnsHandle, err := netns.GetFromPid(int(pid))
		if err != nil {
			return err
		}
		defer netnsHandle.Close()
		err = netns.Set(netnsHandle)
		if err != nil {
			return err
		}

		// Switch back to the original namespace
		defer netns.Set(origns)
	}
	return fn()
}

func (t *Tracer) Attach(
	key string,
	pid uint32,
	eventCallback func(*types.Event),
) (err error) {
	if l, ok := t.attachments[key]; ok {
		l.users++
		return nil
	}

	l := &link{
		users: 1,
	}

	err = runWithNamespaceFromPid(pid, func() error {
		tpacket, err := afpacket.NewTPacket()
		if err != nil {
			return err
		}
		l.tpacket = tpacket
		return nil
	})
	defer func() {
		if err != nil {
			if l.tpacket != nil {
				l.tpacket.Close()
			}
		}
	}()
	if err != nil {
		return fmt.Errorf("open raw socket: %w", err)
	}

	err = l.tpacket.SetBPF(t.program)
	if err != nil {
		return fmt.Errorf("set bpf filter: %w", err)
	}

	t.attachments[key] = l

	go t.run(l, eventCallback)

	return nil
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

func (t *Tracer) run(
	l *link,
	eventCallback func(*types.Event),
) {
	ctr := uint32(1)
	for {
		d, info, err := l.tpacket.ZeroCopyReadPacketData()
		if err != nil {
			break
		}
		if t.config.SnapLen != 0 && len(d) > t.config.SnapLen {
			// This can happen for packets received before the filter has been installed, so we need to manually adjust
			d = d[:t.config.SnapLen]
			info.CaptureLength = t.config.SnapLen
		}
		// eventCallback MUST serialize payload d directly as the next call to ZeroCopyReadPacketData() will invalidate
		// the buffer.
		eventCallback(&types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
			},
			Time:    info.Timestamp.UnixNano(),
			Counter: ctr,
			Payload: d,
			OLen:    uint32(info.Length),
		})
	}
	return
}
