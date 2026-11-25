//go:build linux

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

package host

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetSocketPathOnHost(t *testing.T) {
	originalRoot := HostRoot
	HostRoot = "/"
	t.Cleanup(func() { HostRoot = originalRoot })

	for _, path := range []string{"/run/runtime.sock", "run/runtime.sock", "/alias/../runtime.sock"} {
		t.Run(path, func(t *testing.T) {
			got, err := GetSocketPath(path)
			require.NoError(t, err)
			want := path
			if !filepath.IsAbs(want) {
				want = "/" + want
			}
			require.Equal(t, want, got)
		})
	}
}

func TestGetSocketPathInMountedHostRoot(t *testing.T) {
	originalRoot := HostRoot
	HostRoot = t.TempDir()
	t.Cleanup(func() { HostRoot = originalRoot })

	// An absolute symlink must be interpreted inside the mounted host root,
	// not in the container's own root filesystem.
	require.NoError(t, os.Symlink("/run/runtime.sock", filepath.Join(HostRoot, "absolute")))
	got, err := GetSocketPath("/absolute")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(HostRoot, "run/runtime.sock"), got)

	// Relative traversal must not escape the mounted host root either.
	require.NoError(t, os.Symlink("../../outside.sock", filepath.Join(HostRoot, "relative")))
	got, err = GetSocketPath("/relative")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(HostRoot, "outside.sock"), got)

	require.NoError(t, os.Symlink("loop", filepath.Join(HostRoot, "loop")))
	_, err = GetSocketPath("/loop")
	require.Error(t, err)
}
