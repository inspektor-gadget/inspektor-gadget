// Copyright 2022 The Inspektor Gadget authors
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
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/top/file/tracer"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/top/file/types"
)

const (
	// This is the time interval we collect information
	interval = 1
	// Maximum number of files to return
	maxRows = 5
)

func main() {
	// In some kernel versions it's needed to bump the rlimits to
	// use run BPF programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		return
	}

	// Define a callback that is called each interval seconds with
	// the information collected.
	callback := func(event *types.Event) {
		if event.Error != "" {
			fmt.Fprintf(os.Stderr, "There was an error: %s\n", event.Error)
			return
		}

		fmt.Printf("The %d files with more write operations in the last %d seconds were:\n",
			maxRows, interval)

		for i, stat := range event.Stats {
			fmt.Printf("[%d]: %s\n", i+1, stat.Filename)
		}

		fmt.Println("---")
	}

	// Create tracer configuration.
	tracerConfig := &tracer.Config{
		Interval: interval * time.Second,
		MaxRows:  maxRows,
		// Sort results by number of write operations
		SortBy: types.WRITES,
	}

	tracer, err := tracer.NewTracer(tracerConfig, nil, callback)
	if err != nil {
		fmt.Printf("error creating tracer: %s\n", err)
		return
	}
	defer tracer.Stop()

	// Graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit
}
