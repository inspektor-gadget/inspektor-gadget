// Copyright 2025 The Inspektor Gadget authors
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

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	exists := api.KallsymsSymbolExists("abcde_this_symbol_does_not_exists")
	if exists {
		api.Errorf("KallsymsSymbolExists wrongly found symbol")
		return 1
	}

	exists = api.KallsymsSymbolExists("socket_file_ops")
	if !exists {
		api.Errorf("KallsymsSymbolExists did not find symbol")
		return 1
	}

	return 0
}

func main() {}
