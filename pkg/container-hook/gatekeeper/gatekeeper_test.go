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

func TestConstrained(t *testing.T) {
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
	write("cpu", "cpu.max", "max 100000")
	write("cpu/quota", "cpu.max", "20000 100000")

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
		{"/cpu", false},  // cpu.max without a quota
		{"/cpu/quota", true},
		{"/missing/dir", false},
	} {
		if got := Constrained(root, tc.path); got != tc.want {
			t.Errorf("Constrained(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestOwnCgroupName(t *testing.T) {
	for name, want := range map[string]bool{
		"1234":           true,
		"1234-1":         true,
		"1234-99":        true,
		"system.slice":   false,
		"kubepods":       false,
		"1234-x":         false,
		"x-1":            false,
		"1234-1-2":       false,
		"":               false,
		"99999999999999": false,
	} {
		if got := ownCgroupName(name); got != want {
			t.Errorf("ownCgroupName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestCgroupRoot(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"a", "a/b"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"cgroup.controllers", "a/cgroup.controllers", "a/cgroup.type", "a/b/cgroup.controllers", "a/b/cgroup.type"} {
		if err := os.WriteFile(filepath.Join(root, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := cgroupRoot(filepath.Join(root, "a/b/new"))
	if err != nil || got != root {
		t.Fatalf("cgroupRoot = %q, %v; want %q", got, err, root)
	}
	if _, err := cgroupRoot(t.TempDir()); err == nil {
		t.Fatal("want an error outside a cgroup hierarchy")
	}
}
