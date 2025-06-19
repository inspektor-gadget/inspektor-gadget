// Copyright 2023-2024 The Inspektor Gadget authors
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

// This file contains generic helpers that are not specific to an operating system nor architecture.

package gadgets

import (
	"bytes"
)

func FromCString(in []byte) string {
	idx := bytes.IndexByte(in, 0)
	switch {
	case idx == -1:
		return string(in)
	case idx < len(in):
		return string(in[:idx])
	default:
		return string(in)
	}
}

func FromCStringN(in []byte, length int) string {
	l := len(in)
	if length < l {
		l = length
	}

	buf := in[:l]
	idx := bytes.IndexByte(buf, 0)
	switch {
	case idx == -1:
		return string(in)
	case idx < l:
		return string(in[:idx])
	default:
		return string(in)
	}
}
