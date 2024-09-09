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

// This program tries as hard as it can to break the host by calling functions
// with wrong arguments. It uses the low level functions directly as the goal is
// to test the host and not the wrapper API. Tests under dataarray and fields
// test also the higher level API.
package main

import (
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

//export gadgetInit
func gadgetInit() int {
	err := api.SetConfig("foo.bar.zas", "myvalue")
	if err != nil {
		api.Errorf("SetAnnotation failed: %v", err)
		return 1
	}

	// This should fail as the key is not a string
	err = api.SetConfig("foo.bar.zas", 42)
	if err == nil {
		api.Errorf("SetAnnotation should have failed")
		return 1
	}

	return 0
}

func main() {}
