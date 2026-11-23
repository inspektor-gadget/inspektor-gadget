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

package gatekeeper

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMemoryLimited(t *testing.T) {
	root := t.TempDir()
	write := func(path, file, value string) {
		t.Helper()
		dir := filepath.Join(root, path)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, file), []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// user.slice/session.scope: no limits anywhere.
	write("user.slice", "memory.max", "max")
	write("user.slice", "memory.high", "max")
	write("user.slice/session.scope", "memory.max", "max")
	write("user.slice/session.scope", "memory.high", "max")
	// kubepods/pod: limit on the pod; container: memory.high only.
	write("kubepods/pod", "memory.max", "838860800")
	write("kubepods/pod/ctr", "memory.max", "max")
	write("other", "memory.high", "104857600")

	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/", false},
		{"/user.slice/session.scope", false},
		{"/kubepods/pod/ctr", true}, // inherited from the pod
		{"/kubepods/pod", true},
		{"/kubepods", false},
		{"/other", true}, // memory.high counts
		{"/missing/dir", false},
	} {
		if got := MemoryLimited(root, tc.path); got != tc.want {
			t.Errorf("MemoryLimited(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
