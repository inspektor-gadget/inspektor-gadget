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

package symbolizer

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

func (s *Symbolizer) resolveWithDebuginfodCache(task Task, stackQueries []StackItemQuery, res []StackItemResponse) error {
	for i, query := range stackQueries {
		if !query.ValidBuildID {
			continue
		}

		buildIDStr := hex.EncodeToString(query.BuildID[:])

		s.lockSymbolTablesFromBuildID.RLock()
		table, ok := s.symbolTablesFromBuildID[buildIDStr]
		if ok {
			table.timestamp = time.Now()
			symbol := table.lookupByAddr(stackQueries[i].Offset)
			if symbol != "" {
				res[i].Found = true
				res[i].Symbol = symbol
			}
			s.lockSymbolTablesFromBuildID.RUnlock()
			continue
		}
		s.lockSymbolTablesFromBuildID.RUnlock()

		debuginfoPath := filepath.Join(s.options.DebuginfodCachePath, buildIDStr, "debuginfo")
		file, err := os.Open(debuginfoPath)
		if err != nil {
			if os.IsNotExist(err) {
				if !s.missingBuildIDs[buildIDStr] {
					s.missingBuildIDs[buildIDStr] = true
					suggestedCmd := fmt.Sprintf("DEBUGINFOD_CACHE_PATH=%s DEBUGINFOD_URLS=https://debuginfod.elfutils.org debuginfod-find debuginfo %s",
						s.options.DebuginfodCachePath, buildIDStr)
					log.Warnf("Debuginfo %s for %s not found in %s. Suggested remedial: %q", buildIDStr, task.Name, debuginfoPath, suggestedCmd)
				}
				continue
			}
			log.Warnf("Failed to open debuginfo file %s for %s: %v", debuginfoPath, task.Name, err)
			continue
		}
		defer file.Close()

		// Check if the file is empty
		if fi, err := file.Stat(); err != nil {
			log.Warnf("Failed to stat debuginfo file %s: %v", debuginfoPath, err)
			continue
		} else if fi.Size() == 0 {
			suggestedCmd := fmt.Sprintf("rm -f %s", debuginfoPath)
			log.Warnf("Debuginfo %s for %s in %s is empty. Suggested remedial: %q", buildIDStr, task.Name, debuginfoPath, suggestedCmd)
			continue
		}

		table, err = s.newSymbolTableFromFile(file)
		if err != nil {
			return err
		}

		s.lockSymbolTablesFromBuildID.Lock()

		s.symbolTablesFromBuildID[buildIDStr] = table
		delete(s.missingBuildIDs, buildIDStr)

		table.timestamp = time.Now()
		symbol := table.lookupByAddr(stackQueries[i].Offset)
		if symbol != "" {
			res[i].Found = true
			res[i].Symbol = symbol
		}
		s.lockSymbolTablesFromBuildID.Unlock()
	}

	return nil
}
