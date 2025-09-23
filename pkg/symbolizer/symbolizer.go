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
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	symbolTableTTL  = time.Minute
	pruneTickerTime = time.Minute
)

type SymbolizerOptions struct {
	UseSymtab bool
}

type Symbolizer struct {
	options SymbolizerOptions

	lockSymbolTables sync.RWMutex
	symbolTables     map[SymbolTableKey]*symbolTable
	symbolCountTotal int

	// hostProcFsPidNs is the pid namespace of /host/proc/1/ns/pid.
	hostProcFsPidNs uint32

	pruneLoopStarted bool
	pruneTickerTime  time.Duration
	symbolTableTTL   time.Duration
	exit             chan struct{}
}

// symbolTable is a cache of symbols for a specific executable.
type symbolTable struct {
	// symbols is a slice of symbols. Order is preserved for binary search.
	symbols []*symbol

	// PIE (Position Independent Executable). Useful information for debugging.
	isPIE bool

	// elfBaseAddr is the link-time base address as defined in the ELF headers.
	// Typical values:
	// - 0 for C PIE programs
	// - 0x400000 for C non-PIE programs (unless chosen otherwise with
	//   flag "-Wl,-Ttext=0x1234")
	// - 0x400000 for all Go programs, regardless of PIE.
	elfBaseAddr uint64

	// runtimeBaseAddrCache caches the base address for a given BaseAddrHash.
	// This avoids re-reading /proc/pid/maps for every stack trace resolution.
	// The BaseAddrHash is similar to pids, except that it changes during execve
	// and it might be shared by several processes sharing mm_struct (e.g.
	// CLONE_VM or CLONE_THREADS).
	runtimeBaseAddrCache map[baseAddrCacheKey]uint64

	timestamp time.Time
}

type symbol struct {
	name        string
	value, size uint64
}

type SymbolTableKey struct {
	Major     uint32
	Minor     uint32
	Ino       uint64
	MtimeSec  int64
	MtimeNsec uint32
}

type baseAddrCacheKey struct {
	// tgidLevel0 is the thread group ID of the process in top-level pid
	// namespace. IG might not have access to a procfs of the top-level pid
	// namespace, so tgidLevel0 cannot be used to lookup procfs entries. This is
	// just to ensure that unrelated tasks are not poisoning the cache for each
	// others.
	tgidLevel0 uint32

	// baseAddrHash is an opaque hash provided by eBPF to identify the
	// executable and its base address. It changes on execve and is shared by
	// threads of the same process.
	baseAddrHash uint32
}

func NewSymbolizer(opts SymbolizerOptions) (*Symbolizer, error) {
	var hostProcFsPidNs uint32
	if opts.UseSymtab {
		var err error
		hostProcFsPidNs, err = getHostProcFsPidNs()
		if err != nil {
			return nil, err
		}
	}

	s := &Symbolizer{
		options:         opts,
		symbolTables:    make(map[SymbolTableKey]*symbolTable),
		hostProcFsPidNs: hostProcFsPidNs,
		pruneTickerTime: pruneTickerTime,
		symbolTableTTL:  symbolTableTTL,
		exit:            make(chan struct{}),
	}
	return s, nil
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
			s.pruneOldObjects()
		case <-s.exit:
			return
		}
	}
}

func (s *Symbolizer) pruneOldObjects() {
	s.lockSymbolTables.Lock()
	defer s.lockSymbolTables.Unlock()
	now := time.Now()
	tableRemovedCount := 0
	symbolRemovedCount := 0
	for key, table := range s.symbolTables {
		if now.Sub(table.timestamp) > s.symbolTableTTL {
			s.symbolCountTotal -= len(table.symbols)
			delete(s.symbolTables, key)
			tableRemovedCount++
			symbolRemovedCount += len(table.symbols)
		}
	}
	if tableRemovedCount > 0 {
		log.Debugf("symbol tables pruned: %d symbol tables with %d symbols removed (remaining: %d symbol tables with %d symbols)",
			tableRemovedCount, symbolRemovedCount,
			len(s.symbolTables), s.symbolCountTotal)
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
type StackItemQuery struct {
	Addr uint64
}

type StackItemResponse struct {
	Found  bool
	Symbol string
}

func (s *Symbolizer) Resolve(task Task, stackQueries []StackItemQuery) ([]StackItemResponse, error) {
	if len(stackQueries) == 0 {
		return nil, nil
	}
	res := make([]StackItemResponse, len(stackQueries))

	if s.options.UseSymtab {
		err := s.resolveWithSymtab(task, stackQueries, res)
		if err != nil {
			return nil, err
		}
	}

	// Most gadgets won't use the symbolizer, so don't start the prune loop until we need it.
	if !s.pruneLoopStarted && s.options.UseSymtab {
		count := 0

		s.lockSymbolTables.RLock()
		count += len(s.symbolTables)
		s.lockSymbolTables.RUnlock()

		if count > 0 {
			s.pruneLoopStarted = true
			go s.pruneLoop()
		}
	}

	return res, nil
}
