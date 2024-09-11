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

package uprobetracer

import "golang.org/x/arch/arm64/arm64asm"

const (
	armInstructionSize = 4
)

func findReturnOffsets(baseOffset uint64, data []byte) ([]uint64, error) {
	var returnOffsets []uint64
	index := 0
	for index < len(data) {
		instr, err := arm64asm.Decode(data[index:])
		if err == nil && instr.Op == arm64asm.RET {
			returnOffsets = append(returnOffsets, baseOffset+uint64(index))
		}
		index += armInstructionSize
	}
	return returnOffsets, nil
}
