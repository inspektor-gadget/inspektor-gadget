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

// Package digraph provides a directed graph implementation and methods for cycle detection.
package digraph

// StronglyConnectedComponents finds all strongly connected components in the graph.
func StronglyConnectedComponents(g *DiGraph) []map[uint64]struct{} {
	preorder := make(map[uint64]int)
	lowlink := make(map[uint64]int)
	sccFound := make(map[uint64]bool)
	sccQueue := []uint64{}
	var sccs []map[uint64]struct{}
	i := 0

	var strongConnect func(v uint64)
	strongConnect = func(v uint64) {
		i++
		preorder[v] = i
		lowlink[v] = i
		sccQueue = append(sccQueue, v)

		for _, w := range g.Neighbors(v) {
			if _, ok := preorder[w]; !ok {
				strongConnect(w)
				lowlink[v] = min(lowlink[v], lowlink[w])
			} else if !sccFound[w] {
				lowlink[v] = min(lowlink[v], preorder[w])
			}
		}
		if lowlink[v] == preorder[v] {
			scc := make(map[uint64]struct{})
			for {
				u := sccQueue[len(sccQueue)-1]
				sccQueue = sccQueue[:len(sccQueue)-1]
				scc[u] = struct{}{}
				sccFound[u] = true
				if u == v {
					break
				}
			}
			sccs = append(sccs, scc)
		}
	}
	for _, v := range g.Nodes() {
		if _, ok := preorder[v]; !ok {
			strongConnect(v)
		}
	}
	return sccs
}

// SimpleCycles finds all simple cycles in the graph.
func SimpleCycles(g *DiGraph) [][]uint64 {
	var cycles [][]uint64

	unblock := func(node uint64, blocked map[uint64]bool, B map[uint64]map[uint64]struct{}) {
		stack := []uint64{node}
		for len(stack) > 0 {
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if blocked[n] {
				blocked[n] = false
				for m := range B[n] {
					stack = append(stack, m)
				}
				delete(B, n)
			}
		}
	}
	subG := g.Subgraph(g.Nodes())
	sccs := StronglyConnectedComponents(subG)
	for len(sccs) > 0 {
		scc := sccs[len(sccs)-1]
		sccs = sccs[:len(sccs)-1]

		var startNode uint64
		for node := range scc {
			startNode = node
			break
		}
		path := []uint64{startNode}
		blocked := make(map[uint64]bool)
		closed := make(map[uint64]bool)
		blocked[startNode] = true
		B := make(map[uint64]map[uint64]struct{})
		stack := [][2]uint64{{startNode, 0}}

		for len(stack) > 0 {
			thisNode, prevNode := stack[len(stack)-1][0], stack[len(stack)-1][1]
			stack = stack[:len(stack)-1]
			if prevNode != 0 {
				path = append(path, thisNode)
			}
			done := true
			for _, nextNode := range subG.Neighbors(thisNode) {
				if nextNode == startNode {
					cycles = append(cycles, append(path, startNode))
					closed[startNode] = true
				} else if !blocked[nextNode] {
					stack = append(stack, [2]uint64{nextNode, thisNode})
					blocked[nextNode] = true
					done = false
				}
			}
			if done {
				if closed[thisNode] {
					unblock(thisNode, blocked, B)
				} else {
					for _, nextNode := range subG.Neighbors(thisNode) {
						if _, ok := B[nextNode]; !ok {
							B[nextNode] = make(map[uint64]struct{})
						}
						B[nextNode][thisNode] = struct{}{}
					}
				}
				path = path[:len(path)-1]
			}
		}
		subG.RemoveNode(startNode)
		H := subG.Subgraph(g.Nodes())
		newSCCs := StronglyConnectedComponents(H)
		sccs = append(sccs, newSCCs...)
	}
	return cycles
}

// FindCycles returns edges from all cycles in the graph.
func FindCycles(g *DiGraph) [][][2]uint64 {
	simpleCycles := SimpleCycles(g)
	var cycles [][][2]uint64

	for _, cycle := range simpleCycles {
		edges := make([][2]uint64, len(cycle)-1)
		for i := 0; i < len(cycle)-1; i++ {
			edges[i] = [2]uint64{cycle[i], cycle[i+1]}
		}
		cycles = append(cycles, edges)
	}
	return cycles
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
