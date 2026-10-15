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

package main

import (
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

//go:wasmexport gadgetPreStart
func gadgetPreStart() int32 {
	// The value is only present when the caller sets it; callers using the Go
	// API may omit it, so treat a missing value as the default (false).
	paths, err := api.GetParamValue("paths", 8)
	if err != nil {
		paths = "false"
	}

	// Every program of a gadget must attach, so without --paths don't attach
	// the kprobe at all: the gadget then also works on kernels built without
	// CONFIG_SECURITY_PATH.
	if paths != "true" {
		if err := api.SetConfig("programs.ig_rename_paths.attach_to", "gadget_program_disabled"); err != nil {
			api.Errorf("disabling ig_rename_paths: %s", err)
			return 1
		}
		return 0
	}

	if !api.KallsymsSymbolExists("security_path_rename") {
		api.Errorf("--paths requires a kernel built with CONFIG_SECURITY_PATH (security_path_rename not found)")
		return 1
	}

	return 0
}

func main() {}
