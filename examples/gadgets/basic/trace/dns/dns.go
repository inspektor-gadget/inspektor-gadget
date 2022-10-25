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

	"github.com/cilium/ebpf/rlimit"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

const key = "host"

func main() {
	// In some kernel versions it's needed to bump the rlimits to
	// use run BPF programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		return
	}

	// Define a callback to be called each time there is an event.
	eventCallback := func(event types.Event) {
		qr := event.Qr
		if qr == types.DNSPktTypeQuery {
			qr = "request"
		} else if qr == types.DNSPktTypeResponse {
			qr = "response"
		}
		fmt.Printf("A new %q dns %s about %s was observed\n",
			event.QType, qr, event.DNSName)
	}

	// Create tracer. In this case no parameters are passed.
	tracer, err := tracer.NewTracer()
	if err != nil {
		fmt.Printf("error creating tracer: %s\n", err)
		return
	}
	defer tracer.Close()

	// The tracer has to be attached. The DNS packets will be traced on
	// the network namespace of pid.
	pid := uint32(os.Getpid())
	if err := tracer.Attach(key, pid, eventCallback); err != nil {
		fmt.Printf("error attaching tracer: %s\n", err)
		return
	}
	defer tracer.Detach(key)

	// Graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit
}
