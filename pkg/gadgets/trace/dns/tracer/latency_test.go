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
	"testing"
	"time"
)

func mustCreateDNSLatencyCalculator(t *testing.T) *dnsLatencyCalculator {
	c, err := newDNSLatencyCalculator()
	if err != nil {
		t.Fatalf("Could not initialize DNS latency calculator: %s", err)
	}
	return c
}

func assertNumOutstandingQueries(t *testing.T, c *dnsLatencyCalculator, expected int) {
	n := c.numOutstandingQueries()
	if n != expected {
		t.Fatalf("Expected %d outstanding queries, but got %d", expected, n)
	}
}

func assertLatency(t *testing.T, actual time.Duration, expected time.Duration) {
	if actual != expected {
		t.Fatalf("Expected latency %d but got %d", expected, actual)
	}
}

func assertNoLatency(t *testing.T, actual time.Duration) {
	if actual != 0 {
		t.Fatalf("Expected no latency returned, but got %d", actual)
	}
}

func TestDnsLatencyCalculatorQueryResponse(t *testing.T) {
	netns := uint64(1)
	id := uint16(1)
	c := mustCreateDNSLatencyCalculator(t)
	c.storeDNSQueryTimestamp(netns, id, 100)
	assertNumOutstandingQueries(t, c, 1)

	latency := c.calculateDNSResponseLatency(netns, id, 500)
	assertLatency(t, latency, 400*time.Nanosecond)
	assertNumOutstandingQueries(t, c, 0)
}

func TestDnsLatencyCalculatorResponseWithoutMatchingQuery(t *testing.T) {
	netns := uint64(1)
	id := uint16(1)
	c := mustCreateDNSLatencyCalculator(t)

	// Response for an netns/id without a corresponding query.
	latency := c.calculateDNSResponseLatency(netns, id, 500)
	assertNoLatency(t, latency)
	assertNumOutstandingQueries(t, c, 0)
}

func TestDnsLatencyCalculatorResponseWithSameIdButDifferentNetNs(t *testing.T) {
	firstNetns, secondNetns := uint64(1), uint64(2)
	id := uint16(1)
	c := mustCreateDNSLatencyCalculator(t)

	// Two queries, same ID, different network namespaces.
	c.storeDNSQueryTimestamp(firstNetns, id, 100)
	c.storeDNSQueryTimestamp(secondNetns, id, 200)
	assertNumOutstandingQueries(t, c, 2)

	// Latency calculated correctly for both responses.
	firstLatency := c.calculateDNSResponseLatency(firstNetns, id, 500)
	assertLatency(t, firstLatency, 400*time.Nanosecond)
	secondLatency := c.calculateDNSResponseLatency(secondNetns, id, 700)
	assertLatency(t, secondLatency, 500*time.Nanosecond)
	assertNumOutstandingQueries(t, c, 0)
}

func TestDnsLatencyCalculatorManyOutstandingQueries(t *testing.T) {
	netns := uint64(1)
	c := mustCreateDNSLatencyCalculator(t)

	var lastID uint16
	for i := 0; i < dnsLatencyCacheSize*3; i++ {
		id := uint16(i)
		c.storeDNSQueryTimestamp(netns, id, 100)
		lastID = id
	}

	// Dropped some of the outstanding queries.
	assertNumOutstandingQueries(t, c, dnsLatencyCacheSize)

	// Response to most recent queries should report latency.
	latency := c.calculateDNSResponseLatency(netns, lastID, 300)
	assertLatency(t, latency, 200*time.Nanosecond)

	// Response to first (dropped) queries should NOT report latency.
	latency = c.calculateDNSResponseLatency(netns, 0, 400)
	assertNoLatency(t, latency)

	// Response to prior queries that wasn't yet dropped should report latency.
	latency = c.calculateDNSResponseLatency(netns, lastID-uint16(dnsLatencyCacheSize-1), 600)
	assertLatency(t, latency, 500*time.Nanosecond)
}

func TestDnsLatencyCalculatorResponseWithZeroTimestamp(t *testing.T) {
	netns := uint64(1)
	id := uint16(1)
	c := mustCreateDNSLatencyCalculator(t)

	c.storeDNSQueryTimestamp(netns, id, 100)
	assertNumOutstandingQueries(t, c, 1)

	// Response has timestamp zero (should never happen, but check it anyway to prevent overflow).
	latency := c.calculateDNSResponseLatency(netns, id, 0)
	assertNoLatency(t, latency)
	assertNumOutstandingQueries(t, c, 0)
}
