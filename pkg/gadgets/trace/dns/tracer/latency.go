// Copyright 2023 The Inspektor Gadget authors
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
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

const dnsLatencyCacheSize int = 1024

// dnsQueryKey is a unique identifier for a DNS query.
// netns is the network namespace where the packet was observed.
// The ID comes from the DNS header.
type dnsQueryKey struct {
	netns uint64
	id    uint16
}

// dnsLatencyCalculator calculates the latency between a query and its response.
// It uses an LRU cache to bound memory usage.
// All operations are thread-safe.
type dnsLatencyCalculator struct {
	queryCache *lru.Cache[dnsQueryKey, uint64] // This is thread-safe.
}

func newDNSLatencyCalculator() (*dnsLatencyCalculator, error) {
	queryCache, err := lru.New[dnsQueryKey, uint64](dnsLatencyCacheSize)
	if err != nil {
		return nil, err
	}
	return &dnsLatencyCalculator{queryCache}, nil
}

func (c *dnsLatencyCalculator) storeDNSQueryTimestamp(netns uint64, id uint16, timestamp uint64) {
	// Store the timestamp of the query so we can calculate the latency once the response arrives.
	c.queryCache.Add(dnsQueryKey{netns, id}, timestamp)
}

// If there is no corresponding DNS query (either never received or evicted to make space), then this returns zero.
func (c *dnsLatencyCalculator) calculateDNSResponseLatency(netns uint64, id uint16, timestamp uint64) time.Duration {
	key := dnsQueryKey{netns, id}
	reqTS, ok := c.queryCache.Get(key)
	if !ok {
		// Either an invalid ID or we evicted the query from the map to free space.
		return 0
	}

	c.queryCache.Remove(key)

	if reqTS > timestamp {
		// Should never happen assuming timestamps are monotonic, but handle it just in case.
		return 0
	}

	return time.Duration(timestamp - reqTS)
}

func (c *dnsLatencyCalculator) numOutstandingQueries() int {
	return c.queryCache.Len()
}
