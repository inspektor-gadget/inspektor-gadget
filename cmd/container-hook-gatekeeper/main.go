// Copyright 2026 The Inspektor Gadget authors
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

// Command container-hook-gatekeeper answers the container hook's fanotify
// permission events with a deadline. It is started by pkg/container-hook, not
// by hand. Ship it as /usr/bin/ig-container-hook-gatekeeper (or point
// IG_CONTAINER_HOOK_GATEKEEPER_BIN at it); without it the container hook
// re-executes its own binary instead, which works but costs that binary's
// package initialization.
package main

import (
	"fmt"
	"os"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-hook/gatekeeper"
)

func main() {
	if os.Getenv(gatekeeper.Env) != "1" {
		fmt.Fprintln(os.Stderr, "container-hook-gatekeeper is started by the container hook; it is not meant to be run by hand")
		os.Exit(2)
	}
	os.Exit(gatekeeper.Run())
}
