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
	// Imported for the gadgetAPIVersion export.
	_ "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

// gadgetInit wrongly doesn't return any value.
//
//go:wasmexport gadgetInit
func gadgetInit() {
}

func main() {}
