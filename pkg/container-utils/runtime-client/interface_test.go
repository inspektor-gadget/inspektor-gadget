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

package runtimeclient

import "testing"

func TestNormalizeOCIRuntime(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"runc", "runc"},
		{"crun", "crun"},
		{"io.containerd.runc.v2", "runc"},
		{"io.containerd.crun.v2", "crun"},
		{"io.containerd.kata.v2", "kata"},
		{"io.containerd.runsc.v1", "runsc"},
		{"", ""},
		{"unknown", ""},
	}

	for _, tt := range tests {
		got := NormalizeOCIRuntime(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeOCIRuntime(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
