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

// Invalid ptr: out of bound 17 MB (max memory of the module is 16MB)
const invalidPtr uint32 = uint32(17 * 1024 * 1024)

//go:wasmimport env fieldGetScalar
func fieldGetScalar(acc uint32, data uint32, kind uint32, errPtr uint32) uint64

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	fieldGetScalar(55, 55, uint32(api.Kind_Uint32), invalidPtr)
	panic("This should never be reached")
}

func main() {}
