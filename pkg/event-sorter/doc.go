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

/*
Package eventsorter is a library that helps to sort streams of events
chronologically according to their timestamps.

This is motivated by events coming from a eBPF program via perf ring buffers.
Since perf ring buffer maps have one buffer per cpu, it might be that the
userland reader reads events out-of-order if they come from different per-cpu
buffers.

This package is generic and does not need to know the type of your events.
Instead of using references to an event, it just calls a callback. The caller
can use closures to handle the events.

This package re-order events based on a uint64 timestamp. It does not need to
know the clock used for the timestamp. It only compares timestamps between
themselves and not with other clocks such as time.Now(). In this way, users of
this library are free to use bpf_ktime_get_ns(), bpf_ktime_get_boot_ns() or
event a simple counter.

# How does it work?

	// Create the event sorter
	es = eventsorter.NewEventSorter()

	// Add events. The callbacks will be called asynchronously in the
	// right order after a short delay
	event := types.Event{
		Event: eventtypes.Event{
			Type:      eventtypes.NORMAL,
			Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
		},
		MountNsID: bpfEvent.MntnsId,
	}
	eventSorter.Append(uint64(event.Timestamp), func() {
		t.eventCallback(&event)
	})

	// Close the event sorter
	eventSorter.Close()
*/
package eventsorter
