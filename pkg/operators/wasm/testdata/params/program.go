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

//go:wasmexport gadgetStart
func gadgetStart() int32 {
	val, err := api.GetParamValue("param-key", 32)
	if err != nil {
		api.Errorf("failed to get param: %v", err)
		return 1
	}

	const expected = "param-value"
	if val != expected {
		api.Errorf("param value should be %q, got: %q", expected, val)
		return 1
	}

	_, err = api.GetParamValue("non-existing-param", 32)
	if err == nil {
		api.Errorf("looking for non-existing-param succeeded")
		return 1
	}

	return 0
}

func main() {}
