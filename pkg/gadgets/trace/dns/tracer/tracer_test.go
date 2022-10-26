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

package tracer

import (
	"testing"
)

func TestParsing(t *testing.T) {
	word10 := []byte{9, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'}
	output10 := "abcdefghi."
	word250 := []byte{}
	output250 := ""
	for i := 0; i < 25; i++ {
		word250 = append(word250, word10...)
		output250 += output10
	}

	table := []struct {
		input  []byte
		output string
	}{
		{
			input: []byte{
				3, 'w', 'w', 'w',
				7, 'k', 'i', 'n', 'v', 'o', 'l', 'k',
				2, 'i', 'o',
				0,
				// trailing garbage is ignored
				0x42, 0x42,
			},
			output: "www.kinvolk.io.",
		},
		{
			input: []byte{
				3, 'w', 'w', 'w',
				255, // overflow
			},
			output: "www.",
		},
		{
			input: append(word250,
				[]byte{
					3, 'z', 'z', 'z',
					0,
				}...),
			output: output250 + "zzz.",
		},
	}

	for _, entry := range table {
		output := parseLabelSequence(entry.input)
		if output != entry.output {
			t.Fatalf("Failed to parse DNS string: got %q, expected %q", output, entry.output)
		}
	}
}
