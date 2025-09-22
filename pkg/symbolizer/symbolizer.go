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
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	symbolTableTTL  = time.Minute
	pruneTickerTime = time.Minute
)

var defaultDebuginfodCachePath string

func init() {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		defaultDebuginfodCachePath = "/root/.cache/debuginfod_client"
		return
	}
	defaultDebuginfodCachePath = filepath.Join(cacheDir, "debuginfod_client")
}

type SymbolizerOptions struct {
	UseSymtab           bool
	UseDebugInfodCache  bool
	DebuginfodCachePath string
}

type Symbolizer struct {
	options SymbolizerOptions

	lockSymbolTables sync.RWMutex
	symbolTables     map[exeKey]*symbolTable
	symbolCountTotal int

	lockSymbolTablesFromBuildID sync.RWMutex
	symbolTablesFromBuildID     map[string]*symbolTable
	missingBuildIDs             map[string]bool

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

	// PIE (Position Independent Executable) needs addresses to be adjusted with
	// base address.
	isPIE bool

	timestamp time.Time
}

type symbol struct {
	name        string
	value, size uint64
}

// exeKey is an unique key for an executable given inode and mtime.
// This key is used to cache symbol tables.
type exeKey struct {
	ino       uint64
	mtimeSec  int64
	mtimeNsec uint32
}

func (k exeKey) String() string {
	return fmt.Sprintf("ino=%d mtime=%d.%d", k.ino, k.mtimeSec, k.mtimeNsec)
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
	if opts.DebuginfodCachePath == "" {
		opts.DebuginfodCachePath = defaultDebuginfodCachePath
	}

	s := &Symbolizer{
		options:                 opts,
		symbolTables:            make(map[exeKey]*symbolTable),
		symbolTablesFromBuildID: make(map[string]*symbolTable),
		missingBuildIDs:         make(map[string]bool),
		hostProcFsPidNs:         hostProcFsPidNs,
		pruneTickerTime:         pruneTickerTime,
		symbolTableTTL:          symbolTableTTL,
		exit:                    make(chan struct{}),
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
	now := time.Now()

	// Clean symbolTables
	s.lockSymbolTables.Lock()
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
	s.lockSymbolTables.Unlock()

	// Clean symbolTablesFromBuildID
	s.lockSymbolTablesFromBuildID.Lock()
	buildIDRemovedCount := 0
	buildIDSymbolRemovedCount := 0
	for buildID, table := range s.symbolTablesFromBuildID {
		if now.Sub(table.timestamp) > s.symbolTableTTL {
			delete(s.symbolTablesFromBuildID, buildID)
			buildIDRemovedCount++
			buildIDSymbolRemovedCount += len(table.symbols)
		}
	}
	if buildIDRemovedCount > 0 {
		log.Debugf("symbol tables from build ID pruned: %d symbol tables with %d symbols removed (remaining: %d symbol tables with %d symbols)",
			buildIDRemovedCount, buildIDSymbolRemovedCount,
			len(s.symbolTablesFromBuildID), s.symbolCountTotal)
	}
	s.lockSymbolTablesFromBuildID.Unlock()
}

type PidNumbers struct {
	Pid     uint32
	PidNsId uint32
}

type Task struct {
	// Pids of the process that we want to resolve symbols for.
	PidNumbers []PidNumbers

	// Name of the task for logging purposes. Optional.
	Name string

	// ContainerPid is the pid 1 of the container that the process is in. Optional.
	ContainerPid uint32

	// Properties of the executable to check if the symbol table is still valid.
	Ino       uint64
	MtimeSec  int64
	MtimeNsec uint32
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

	if s.options.UseDebugInfodCache {
		err := s.resolveWithDebuginfodCache(task, stackQueries, res)
		if err != nil {
			return nil, err
		}
	}

	// Most gadgets won't use the symbolizer, so don't start the prune loop until we need it.
	if !s.pruneLoopStarted && (s.options.UseSymtab || s.options.UseDebugInfodCache) {
		count := 0

		s.lockSymbolTables.RLock()
		count += len(s.symbolTables)
		s.lockSymbolTables.RUnlock()

		s.lockSymbolTablesFromBuildID.RLock()
		count += len(s.symbolTablesFromBuildID)
		s.lockSymbolTablesFromBuildID.RUnlock()

		if count > 0 {
			s.pruneLoopStarted = true
			go s.pruneLoop()
		}
	}

	return res, nil
}
