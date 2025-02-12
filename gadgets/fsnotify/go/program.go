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

package main

import (
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

//go:wasmexport gadgetPreStart
func gadgetPreStart() int32 {
	// Linux 5.16 renamed fsnotify_add_event to fsnotify_insert_event
	// https://github.com/torvalds/linux/commit/1ad03c3a326a86e259389592117252c851873395
	if api.KallsymsSymbolExists("fsnotify_insert_event") {
		return 0
	}

	if api.KallsymsSymbolExists("fsnotify_add_event") {
		api.SetConfig("programs.fsnotify_insert_event_e.attach_to", "fsnotify_add_event")
		return 0
	}

	api.Errorf("kernel symbol not found: fsnotify_add_event or fsnotify_insert_event")
	return 0
}

func main() {}
