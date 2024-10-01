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

// DiGraph represents a directed graph.
type DiGraph struct {
	adjacencyMap  map[uint64]map[uint64]struct{}
	attributesMap map[[2]uint64]map[string]interface{}
}

// NewDiGraph creates a new directed graph.
func NewDiGraph() *DiGraph {
	return &DiGraph{
		adjacencyMap:  make(map[uint64]map[uint64]struct{}),
		attributesMap: make(map[[2]uint64]map[string]interface{}),
	}
}

// Neighbors returns the neighbors of a node.
func (g *DiGraph) Neighbors(node uint64) []uint64 {
	neighbors := []uint64{}
	if adj, exists := g.adjacencyMap[node]; exists {
		for neighbor := range adj {
			neighbors = append(neighbors, neighbor)
		}
	}
	return neighbors
}

// Edges returns all edges in the graph.
func (g *DiGraph) Edges() [][2]uint64 {
	edges := [][2]uint64{}
	for node, neighbors := range g.adjacencyMap {
		for neighbor := range neighbors {
			edges = append(edges, [2]uint64{node, neighbor})
		}
	}
	return edges
}

// Nodes returns all nodes in the graph.
func (g *DiGraph) Nodes() []uint64 {
	nodes := []uint64{}
	for node := range g.adjacencyMap {
		nodes = append(nodes, node)
	}
	return nodes
}

// Attributes returns the attributes of an edge.
func (g *DiGraph) Attributes(node1, node2 uint64) map[string]interface{} {
	return g.attributesMap[[2]uint64{node1, node2}]
}

// AddEdge adds an edge to the graph with optional attributes.
func (g *DiGraph) AddEdge(node1, node2 uint64, attributes map[string]interface{}) {
	if _, exists := g.adjacencyMap[node1]; !exists {
		g.adjacencyMap[node1] = make(map[uint64]struct{})
	}
	if _, exists := g.adjacencyMap[node2]; !exists {
		g.adjacencyMap[node2] = make(map[uint64]struct{})
	}
	g.adjacencyMap[node1][node2] = struct{}{}
	g.attributesMap[[2]uint64{node1, node2}] = attributes
}

// RemoveNode removes a node and its edges from the graph.
func (g *DiGraph) RemoveNode(node uint64) {
	delete(g.adjacencyMap, node)
	for _, neighbors := range g.adjacencyMap {
		delete(neighbors, node)
	}
	for edge := range g.attributesMap {
		if edge[0] == node || edge[1] == node {
			delete(g.attributesMap, edge)
		}
	}
}

// Subgraph returns a subgraph containing only the specified nodes.
func (g *DiGraph) Subgraph(nodes []uint64) *DiGraph {
	subgraph := NewDiGraph()
	nodeSet := make(map[uint64]struct{})
	for _, node := range nodes {
		nodeSet[node] = struct{}{}
	}
	for node := range nodeSet {
		for _, neighbor := range g.Neighbors(node) {
			if _, exists := nodeSet[neighbor]; exists {
				subgraph.AddEdge(node, neighbor, g.Attributes(node, neighbor))
			}
		}
	}
	return subgraph
}
