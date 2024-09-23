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

package api

import (
	"fmt"
	"runtime"
)

//go:wasmimport env setConfig
func setConfig(key uint64, val uint64, kind uint32) uint32

func SetConfig(key string, val any) error {
	var result uint32

	keyPtr := uint64(stringToBufPtr(key))

	switch t := val.(type) {
	case string:
		valPtr := uint64(stringToBufPtr(t))
		result = setConfig(keyPtr, valPtr, uint32(Kind_String))
	default:
		return fmt.Errorf("unsupported type: %T", val)
	}

	runtime.KeepAlive(key)
	runtime.KeepAlive(val)
	if result != 0 {
		return fmt.Errorf("setting config")
	}

	return nil
}
