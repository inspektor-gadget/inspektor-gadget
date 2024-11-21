// Copyright 2024 The Inspektor Gadget authors
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

package main

import (
	"fmt"
	"sort"
	"strings"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"

	"deadlock/digraph"
)

// ProcInfo stores process information.
type ProcInfo struct {
	comm    string
	mntnsId uint64
}

// The pidInfo map stores information about each process ID.
var pidInfo map[uint32]ProcInfo

// The graphs map stores a directed graph for each process ID.
var graphs map[uint32]*digraph.DiGraph

// The detectedCycles map stores the set of detected cycles for each PID.
var detectedCycles map[uint32]map[string]struct{}

//export gadgetInit
func gadgetInit() int {
	pidInfo = make(map[uint32]ProcInfo)
	graphs = make(map[uint32]*digraph.DiGraph)
	detectedCycles = make(map[uint32]map[string]struct{})

	// Get the `mutex` datasource and its fields
	dsMutex, err := api.GetDataSource("mutex")
	if err != nil {
		api.Warnf("failed to get datasource: %s", err)
		return 1
	}
	mutex1F, err := dsMutex.GetField("mutex1")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}
	mutex2F, err := dsMutex.GetField("mutex2")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}
	tidF, err := dsMutex.GetField("tid")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}
	pidF, err := dsMutex.GetField("pid")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}
	mutex1StackF, err := dsMutex.GetField("mutex1_stack_id")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}
	mutex2StackF, err := dsMutex.GetField("mutex2_stack_id")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}
	commF, err := dsMutex.GetField("comm")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}
	mntnsIdF, err := dsMutex.GetField("mntns_id")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}
	err = dsMutex.Unreference()
	if err != nil {
		api.Warnf("failed to unreference datasource: %s", err)
		return 1
	}

	// Get the `process_exit` datasource and its fields
	dsProcessExit, err := api.GetDataSource("process_exit")
	if err != nil {
		api.Warnf("failed to get datasource: %s", err)
		return 1
	}
	deadPidF, err := dsProcessExit.GetField("pid")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}
	err = dsProcessExit.Unreference()
	if err != nil {
		api.Warnf("failed to unreference datasource: %s", err)
		return 1
	}

	// Create the `deadlock` datasource and its fields
	dsDeadlock, err := api.NewDataSource("deadlock", api.DataSourceTypeSingle)
	if err != nil {
		api.Warnf("failed to create datasource: %s", err)
		return 1
	}
	deadlockPidF, err := dsDeadlock.AddField("pid", api.Kind_Uint32)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}
	deadlockNodesF, err := dsDeadlock.AddField("nodes", api.Kind_Uint64)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}
	deadlockStackIdsF, err := dsDeadlock.AddField("stack_ids", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}
	deadlockCommF, err := dsDeadlock.AddField("comm", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}
	deadlockMntnsIdF, err := dsDeadlock.AddField("mntns_id", api.Kind_Uint64)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}
	err = deadlockMntnsIdF.AddTag("type:gadget_mntns_id") // enrich mntns id
	if err != nil {
		api.Warnf("failed to add tag to field: %s", err)
		return 1
	}

	// Build the graph for deadlock detection using edges from the `mutex` datasource
	dsMutex.SubscribeArray(func(source api.DataSource, data api.DataArray) error {
		affectedPIDs := make(map[uint32]struct{})
		for i := 0; i < data.Len(); i++ {
			datum := data.Get(i)
			mutex1, err := mutex1F.Uint64(datum)
			if err != nil {
				api.Warnf("failed to get mutex1: %s", err)
				continue
			}
			mutex2, err := mutex2F.Uint64(datum)
			if err != nil {
				api.Warnf("failed to get mutex2: %s", err)
				continue
			}
			tid, err := tidF.Uint32(datum)
			if err != nil {
				api.Warnf("failed to get tid: %s", err)
				continue
			}
			pid, err := pidF.Uint32(datum)
			if err != nil {
				api.Warnf("failed to get pid: %s", err)
				continue
			}
			mutex1Stack, err := mutex1StackF.Uint64(datum)
			if err != nil {
				api.Warnf("failed to get mutex1_stack_id: %s", err)
				continue
			}
			mutex2Stack, err := mutex2StackF.Uint64(datum)
			if err != nil {
				api.Warnf("failed to get mutex2_stack_id: %s", err)
				continue
			}

			// Record process information for the PID
			if _, exists := pidInfo[pid]; !exists {
				comm, err := commF.String(datum)
				if err != nil {
					api.Warnf("failed to get comm: %s", err)
					continue
				}
				mntnsId, err := mntnsIdF.Uint64(datum)
				if err != nil {
					api.Warnf("failed to get mntns_id: %s", err)
					continue
				}
				pidInfo[pid] = ProcInfo{
					comm:    comm,
					mntnsId: mntnsId,
				}
			}
			// Update the graph for the PID
			g, exists := graphs[pid]
			if !exists {
				g = digraph.NewDiGraph()
				graphs[pid] = g
			}
			g.AddEdge(mutex1, mutex2, map[string]interface{}{
				"tid":           tid,
				"mutex1StackId": mutex1Stack,
				"mutex2StackId": mutex2Stack,
			})
			affectedPIDs[pid] = struct{}{}
		}

		// Check for cycles only in the affected PIDs
		for pid := range affectedPIDs {
			g := graphs[pid]
			cycles := digraph.FindCycles(g)
			if _, exists := detectedCycles[pid]; !exists {
				// Create entry for the PID
				detectedCycles[pid] = make(map[string]struct{})
			}
			if len(cycles) == 0 || len(cycles) == len(detectedCycles[pid]) {
				continue // no new cycles detected
			}
			for _, cycle := range cycles {
				cycleKey := cycleToKeyString(cycle)
				if _, exists := detectedCycles[pid][cycleKey]; !exists {
					// New cycle detected
					detectedCycles[pid][cycleKey] = struct{}{}

					// Build the stack IDs string
					var stackIds []string
					for _, edge := range cycle {
						attrs := g.Attributes(edge[0], edge[1])
						stackId1 := attrs["mutex1StackId"].(uint64)
						stackId2 := attrs["mutex2StackId"].(uint64)
						stackIds = append(stackIds, fmt.Sprintf("[%d, %d]", stackId1, stackId2))
					}
					stackIdsStr := strings.Join(stackIds, ", ")

					// Emit the deadlock packet for the new cycle
					packet, err := dsDeadlock.NewPacketSingle()
					if err != nil {
						api.Warnf("failed to create new packet: %s", err)
						continue
					}
					deadlockPidF.SetUint32(api.Data(packet), pid)
					deadlockNodesF.SetUint64(api.Data(packet), uint64(len(cycle)))
					deadlockStackIdsF.SetString(api.Data(packet), stackIdsStr)
					deadlockCommF.SetString(api.Data(packet), pidInfo[pid].comm)
					deadlockMntnsIdF.SetUint64(api.Data(packet), pidInfo[pid].mntnsId)

					dsDeadlock.EmitAndRelease(api.Packet(packet))
				}
			}
		}
		return nil
	}, 0)

	// Clean up dead processes using pid from the `process_exit` datasource
	dsProcessExit.Subscribe(func(source api.DataSource, data api.Data) {
		deadPid, err := deadPidF.Uint32(data)
		if err != nil {
			api.Warnf("failed to get pid: %s", err)
			return
		}
		delete(pidInfo, deadPid)
		delete(graphs, deadPid)
		delete(detectedCycles, deadPid)
	}, 0)

	return 0
}

// cycleToKeyString converts a cycle to a unique string representation.
func cycleToKeyString(cycle [][2]uint64) string {
	// Sort the cycle to ensure a consistent representation
	sort.Slice(cycle, func(i, j int) bool {
		if cycle[i][0] != cycle[j][0] {
			return cycle[i][0] < cycle[j][0]
		}
		return cycle[i][1] < cycle[j][1]
	})
	// Convert the cycle to a string of format: "1->2,2->3,3->1"
	var parts []string
	for _, edge := range cycle {
		parts = append(parts, fmt.Sprintf("%d->%d", edge[0], edge[1]))
	}
	return strings.Join(parts, ",")
}

// The main function is not used, but it's still required by the compiler
func main() {}
