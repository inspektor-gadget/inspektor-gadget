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

package piditer

import (
	"errors"
	"fmt"
	"io"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -type pid_iter_entry piditer ./bpf/pid_iter.bpf.c -- -I./bpf/ -I../../../../${TARGET}

type PidIter struct {
	objs   piditerObjects
	iter   *link.Iter
	logger logger.Logger
}

type PidIterEntry struct {
	ProgID uint32
	Pid    uint32
	Comm   string
}

var iterEntrySize = int(unsafe.Sizeof(piditerPidIterEntry{}))

func NewTracer() (iter *PidIter, err error) {
	p := &PidIter{}
	defer func() {
		if err != nil {
			if p.iter != nil {
				p.iter.Close()
			}
			p.objs.Close()
		}
	}()

	spec, err := loadPiditer()
	if err != nil {
		return nil, fmt.Errorf("failed to load ebpf program: %w", err)
	}

	if err := kallsyms.SpecUpdateAddresses(spec, []string{"bpf_prog_fops"}); err != nil {
		return nil, fmt.Errorf("error RewriteConstants: %w", err)
	}

	opts := ebpf.CollectionOptions{}

	if err = spec.LoadAndAssign(&p.objs, &opts); err != nil {
		return nil, fmt.Errorf("failed to load ebpf program: %w", err)
	}

	p.iter, err = link.AttachIter(link.IterOptions{
		Program: p.objs.IgTopEbpfIt,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach iter: %w", err)
	}

	return p, nil
}

// DumpPids returns an array of PidIterEntry containing information
// on which pid (and comm) has an open fd to which eBPF Program ID.
func (p *PidIter) DumpPids() ([]*PidIterEntry, error) {
	rc, err := p.iter.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open iter: %w", err)
	}
	defer rc.Close()

	res := make([]*PidIterEntry, 0)

	buf := make([]byte, 4096/iterEntrySize*iterEntrySize)
	for {
		n, err := io.ReadFull(rc, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) {
				continue
			}
		}
		if n == 0 {
			break
		}
		if n%iterEntrySize != 0 {
			return nil, fmt.Errorf("invalid format: %d", n)
		}
		for i := 0; i < n/iterEntrySize; i++ {
			entry := (*piditerPidIterEntry)(unsafe.Pointer(&buf[i*iterEntrySize]))
			res = append(res, &PidIterEntry{
				ProgID: entry.Id,
				Pid:    entry.Pid,
				Comm:   gadgets.FromCString(entry.Comm[:]),
			})
		}
	}

	return res, nil
}

func (p *PidIter) Close() (err error) {
	// If there's an error, return the last one
	if tmpErr := p.iter.Close(); tmpErr != nil {
		err = tmpErr
	}
	if tmpErr := p.objs.Close(); tmpErr != nil {
		err = tmpErr
	}
	return
}
