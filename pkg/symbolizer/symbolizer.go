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

// Package symbolizer parses ELF programs and resolves stack addresses to
// symbol names.
package symbolizer

import (
	"time"
)

const (
	pruneObjTTL     = time.Minute
	pruneTickerTime = time.Minute
)

type SymbolizerOptions struct {
	UseSymtab           bool
	UseDebugInfodCache  bool
	DebuginfodCachePath string
}

type Symbolizer struct {
	options SymbolizerOptions

	resolvers []ResolverInstance

	pruneLoopStarted bool
	pruneTickerTime  time.Duration
	pruneObjTTL      time.Duration
	exit             chan struct{}
}

// SymbolTable is a cache of symbols for a specific executable.
type SymbolTable struct {
	// Symbols is a slice of symbols. Order is preserved for binary search.
	Symbols []*Symbol

	// PIE (Position Independent Executable). Useful information for debugging.
	IsPIE bool

	// ElfBaseAddr is the link-time base address as defined in the ELF headers.
	// Typical values:
	// - 0 for C PIE programs
	// - 0x400000 for C non-PIE programs (unless chosen otherwise with
	//   flag "-Wl,-Ttext=0x1234")
	// - 0x400000 for all Go programs, regardless of PIE.
	ElfBaseAddr uint64

	// RuntimeBaseAddrCache caches the base address for a given BaseAddrHash.
	// This avoids re-reading /proc/pid/maps for every stack trace resolution.
	// The BaseAddrHash is similar to pids, except that it changes during execve
	// and it might be shared by several processes sharing mm_struct (e.g.
	// CLONE_VM or CLONE_THREADS).
	RuntimeBaseAddrCache map[BaseAddrCacheKey]uint64

	Timestamp time.Time
}

func NewSymbolizer(opts SymbolizerOptions) (*Symbolizer, error) {
	r, err := newResolverInstances(opts)
	if err != nil {
		return nil, err
	}
	s := &Symbolizer{
		options:         opts,
		resolvers:       r,
		pruneTickerTime: pruneTickerTime,
		pruneObjTTL:     pruneObjTTL,
		exit:            make(chan struct{}),
	}
	return s, nil
}

type Symbol struct {
	Name        string
	Value, Size uint64
}

type SymbolTableKey struct {
	Major     uint32
	Minor     uint32
	Ino       uint64
	MtimeSec  int64
	MtimeNsec uint32
}

type BaseAddrCacheKey struct {
	// TgidLevel0 is the thread group ID of the process in top-level pid
	// namespace. IG might not have access to a procfs of the top-level pid
	// namespace, so TgidLevel0 cannot be used to lookup procfs entries. This is
	// just to ensure that unrelated tasks are not poisoning the cache for each
	// others.
	TgidLevel0 uint32

	// BaseAddrHash is an opaque hash provided by eBPF to identify the
	// executable and its base address. It changes on execve and is shared by
	// threads of the same process.
	BaseAddrHash uint32
}

func (s *Symbolizer) Close() {
	close(s.exit)
}

func (s *Symbolizer) pruneLoop() {
	ticker := time.NewTicker(s.pruneTickerTime)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			for _, r := range s.resolvers {
				r.PruneOldObjects(now, s.pruneObjTTL)
			}
		case <-s.exit:
			return
		}
	}
}

type PidNumbers struct {
	Pid     uint32
	PidNsId uint32
}

type Task struct {
	// Pids of the process that we want to resolve symbols for.
	Tgid       uint32
	PidNumbers []PidNumbers

	// Name of the task for logging purposes. Optional.
	Name string

	// ContainerPid is the pid 1 of the container that the process is in. Optional.
	ContainerPid uint32

	// Properties of the executable to check if the symbol table is still valid.
	Exe SymbolTableKey

	// Opaque hash from ebpf representing the base address to check if it needs to be recalculated.
	BaseAddrHash uint32
}

// StackItemQuery is one item of the stack. It contains the data found from BPF.
// The build id comes from struct bpf_stack_build_id from the Linux UAPI:
// https://github.com/torvalds/linux/blob/v6.14/include/uapi/linux/bpf.h#L1451
type StackItemQuery struct {
	Addr         uint64
	ValidBuildID bool
	BuildID      [20]byte
	Offset       uint64
	IP           uint64
}

type StackItemResponse struct {
	Found  bool
	Symbol string
}

func (s *Symbolizer) Resolve(task Task, stackQueries []StackItemQuery) ([]StackItemResponse, error) {
	if len(stackQueries) == 0 || len(s.resolvers) == 0 {
		return nil, nil
	}
	res := make([]StackItemResponse, len(stackQueries))

	// Iterate over all resolvers in order of priority.
	for _, r := range s.resolvers {
		err := r.Resolve(task, stackQueries, res)
		if err != nil {
			return nil, err
		}
	}

	// Most gadgets won't use the symbolizer, so don't start the prune loop until we need it.
	if !s.pruneLoopStarted {
		isPruningNeeded := false

		for _, r := range s.resolvers {
			if r.IsPruningNeeded() {
				isPruningNeeded = true
				break
			}
		}

		if isPruningNeeded {
			s.pruneLoopStarted = true
			go s.pruneLoop()
		}
	}

	return res, nil
}
