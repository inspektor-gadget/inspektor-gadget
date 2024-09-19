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

// This binary is compiled and included in the Gadget images to provide help in
// case it is run with Docker (or another container runtime) by mistake.

package main

import "os"

func main() {
	os.Stdout.WriteString(`
Hi! This OCI image is designed to be run with Inspektor Gadget.
Please check the documentation at https://inspektor-gadget.io/docs/
to get more details.

`)
}
