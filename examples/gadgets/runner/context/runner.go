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
	"context"
	"encoding/json"
	"fmt"

	"github.com/cilium/ebpf/rlimit"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runner"
)

func filterOnFile(r *runner.Runner, cancelFunc context.CancelFunc, file string) error {
	for !r.Done() {
		rawEvent, err := r.GetEvent()
		if err != nil {
			return fmt.Errorf("get event: %w", err)
		}

		type event struct {
			Filename string `json:"fname"`
		}
		var e event
		err = json.Unmarshal([]byte(rawEvent), &e)
		if err != nil {
			return fmt.Errorf("unmarshal event: %w", err)
		}

		if e.Filename == file {
			fmt.Println(rawEvent)
			cancelFunc()
			return nil
		}
	}
	return nil
}

func main() {
	// In some kernel versions it's needed to bump the rlimits to
	// use run BPF programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create a new runner with a timeout of 3 seconds
	r, err := runner.NewRunner("ghcr.io/inspektor-gadget/gadget/trace_open:latest",
		runner.WithPullPolicy(oci.PullImageAlways),
		runner.WithValidateMetadata(true),
		runner.WithContext(ctx),
	)
	if err != nil {
		fmt.Println("NewRunner:", err)
		return
	}
	// Make sure to close the runner instance to cleanup the resources
	defer r.Close()

	// Run the image based gadget asynchronously
	err = r.Run()
	if err != nil {
		fmt.Println("Run:", err)
		return
	}

	// Check for /etc/passwd opens asynchronously
	go filterOnFile(r, cancel, "/etc/passwd")

	// Wait for the gadget to finish
	err = r.Wait()
	if err != nil {
		fmt.Println("Wait:", err)
	}
}
