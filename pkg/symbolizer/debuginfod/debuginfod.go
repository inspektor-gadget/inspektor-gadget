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

package debuginfod

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/symbolizer"
)

var defaultDebuginfodCachePath string

func init() {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		defaultDebuginfodCachePath = "/root/.cache/debuginfod_client"
		return
	}
	defaultDebuginfodCachePath = filepath.Join(cacheDir, "debuginfod_client")

	symbolizer.RegisterResolver(&debuginfodResolver{})
}

type debuginfodResolver struct{}

func (d *debuginfodResolver) NewInstance(options symbolizer.SymbolizerOptions) (symbolizer.ResolverInstance, error) {
	if !options.UseDebugInfodCache {
		return nil, nil
	}

	if options.DebuginfodCachePath == "" {
		options.DebuginfodCachePath = defaultDebuginfodCachePath
	}

	return &debuginfodResolverInstance{
		options:                 options,
		symbolTablesFromBuildID: make(map[string]*symbolizer.SymbolTable),
		missingBuildIDs:         make(map[string]bool),
	}, nil
}

func (d *debuginfodResolver) Priority() int {
	return 5000
}

type debuginfodResolverInstance struct {
	options symbolizer.SymbolizerOptions

	lockSymbolTablesFromBuildID sync.RWMutex
	symbolTablesFromBuildID     map[string]*symbolizer.SymbolTable
	missingBuildIDs             map[string]bool
}

func (d *debuginfodResolverInstance) IsPruningNeeded() bool {
	d.lockSymbolTablesFromBuildID.Lock()
	defer d.lockSymbolTablesFromBuildID.Unlock()

	return len(d.symbolTablesFromBuildID) > 0
}

func (d *debuginfodResolverInstance) PruneOldObjects(now time.Time, ttl time.Duration) {
	d.lockSymbolTablesFromBuildID.Lock()
	defer d.lockSymbolTablesFromBuildID.Unlock()

	buildIDRemovedCount := 0
	buildIDSymbolRemovedCount := 0
	for buildID, table := range d.symbolTablesFromBuildID {
		if now.Sub(table.Timestamp) > ttl {
			delete(d.symbolTablesFromBuildID, buildID)
			buildIDRemovedCount++
			buildIDSymbolRemovedCount += len(table.Symbols)
		}
	}
	if buildIDRemovedCount > 0 {
		log.Debugf("symbol tables from build ID pruned: %d symbol tables with %d symbols removed (remaining: %d symbol tables)",
			buildIDRemovedCount, buildIDSymbolRemovedCount,
			len(d.symbolTablesFromBuildID))
	}
}

func (d *debuginfodResolverInstance) newSymbolTableFromPath(path string, buildIDStr string, task symbolizer.Task) (*symbolizer.SymbolTable, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			if !d.missingBuildIDs[buildIDStr] {
				d.missingBuildIDs[buildIDStr] = true
				suggestedCmd := fmt.Sprintf("DEBUGINFOD_CACHE_PATH=%s DEBUGINFOD_URLS=https://debuginfod.elfutils.org debuginfod-find debuginfo %s",
					d.options.DebuginfodCachePath, buildIDStr)
				log.Warnf("Debuginfo %s for %s not found in %s. Suggested remedial: %q", buildIDStr, task.Name, path, suggestedCmd)
			}
			return nil, nil
		}
		log.Warnf("Failed to open debuginfo file %s for %s: %v", path, task.Name, err)
		return nil, nil
	}
	defer file.Close()

	// Check if the file is empty
	if fi, err := file.Stat(); err != nil {
		log.Warnf("Failed to stat debuginfo file %s: %v", path, err)
		return nil, nil
	} else if fi.Size() == 0 {
		suggestedCmd := fmt.Sprintf("rm -f %s", path)
		log.Warnf("Debuginfo %s for %s in %s is empty. Suggested remedial: %q", buildIDStr, task.Name, path, suggestedCmd)
		return nil, nil
	}

	return symbolizer.NewSymbolTableFromFile(file)
}

func (d *debuginfodResolverInstance) GetEbpfReplacements() map[string]interface{} {
	return nil
}

func (d *debuginfodResolverInstance) Resolve(task symbolizer.Task, stackQueries []symbolizer.StackItemQuery, stackResponses []symbolizer.StackItemResponse) error {
	for i, query := range stackQueries {
		if !query.ValidBuildID {
			continue
		}

		buildIDStr := hex.EncodeToString(query.BuildID[:])

		d.lockSymbolTablesFromBuildID.RLock()
		table, ok := d.symbolTablesFromBuildID[buildIDStr]
		if ok {
			table.Timestamp = time.Now()
			symbol := table.LookupByAddr(stackQueries[i].Offset)
			if symbol != "" {
				stackResponses[i].Found = true
				stackResponses[i].Symbol = symbol
			}
			d.lockSymbolTablesFromBuildID.RUnlock()
			continue
		}
		d.lockSymbolTablesFromBuildID.RUnlock()

		debuginfoPath := filepath.Join(d.options.DebuginfodCachePath, buildIDStr, "debuginfo")

		var err error
		table, err = d.newSymbolTableFromPath(debuginfoPath, buildIDStr, task)
		if err != nil {
			return err
		}
		if table == nil {
			// The debuginfo file was not available, but it is not a fatal error.
			continue
		}

		d.lockSymbolTablesFromBuildID.Lock()

		d.symbolTablesFromBuildID[buildIDStr] = table
		delete(d.missingBuildIDs, buildIDStr)

		table.Timestamp = time.Now()
		symbol := table.LookupByAddr(stackQueries[i].Offset)
		if symbol != "" {
			stackResponses[i].Found = true
			stackResponses[i].Symbol = symbol
		}
		d.lockSymbolTablesFromBuildID.Unlock()
	}

	return nil
}
