// Copyright 2019-2021 The Inspektor Gadget authors
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

package gadgettracermanager

// #include "common.h"
import "C"

const (
	NAME_MAX_LENGTH        = C.NAME_MAX_LENGTH
	NAME_MAX_CHARACTERS    = NAME_MAX_LENGTH - 1
	MAX_CONTAINER_PER_NODE = C.MAX_CONTAINER_PER_NODE
)

type container = C.struct_container

func copyToC(dest *[NAME_MAX_LENGTH]C.char, source string) {
	for i := 0; i < len(source) && i < NAME_MAX_CHARACTERS; i++ {
		dest[i] = C.char(source[i])
	}
}
