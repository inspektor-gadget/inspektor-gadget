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

//export gadgetStart
func gadgetStart() int {
	val, err := api.GetParamValue("param-key")
	if err != nil {
		api.Errorf("failed to get param: %v", err)
		return 1
	}

	const expected = "param-value"
	if val != expected {
		api.Errorf("param value should be %q, got: %q", expected, val)
		return 1
	}

	_, err = api.GetParamValue("non-existing-param")
	if err == nil {
		api.Errorf("looking for non-existing-param succeded")
		return 1
	}

	return 0
}

func main() {}
