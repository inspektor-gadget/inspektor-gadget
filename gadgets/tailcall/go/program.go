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
	api.SetConfig("programs.tail_f0.attach_to", "gadget_program_disabled")
	api.SetConfig("programs.tail_f1.attach_to", "gadget_program_disabled")

	api.SetConfig("programs.tail_kprobe_f0.attach_to", "gadget_program_disabled")
	api.SetConfig("programs.tail_kprobe_f1.attach_to", "gadget_program_disabled")

	// api.SetConfig("programs.replacement_func0.attach_to", "gadget_program_disabled")
	return 0
}

func main() {}
