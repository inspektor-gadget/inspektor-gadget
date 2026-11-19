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

package utils

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/docker"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

func TestCommonFlagsPreserveSocketAlias(t *testing.T) {
	originalRoot := host.HostRoot
	host.HostRoot = "/"
	t.Cleanup(func() { host.HostRoot = originalRoot })

	directory := t.TempDir()
	longDirectory := filepath.Join(directory, strings.Repeat("d", 128))
	require.NoError(t, os.Mkdir(longDirectory, 0o700))
	longSocket := filepath.Join(longDirectory, "runtime.sock")

	// Bind through a directory descriptor so even a long TMPDIR works.
	// The socket's absolute pathname is deliberately longer than sun_path.
	socketDirectory, err := os.Open(longDirectory)
	require.NoError(t, err)
	t.Cleanup(func() { socketDirectory.Close() })
	listener, err := net.Listen("unix", fmt.Sprintf("/proc/self/fd/%d/runtime.sock", socketDirectory.Fd()))
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	require.NoError(t, os.Symlink(longSocket, filepath.Join(directory, "alias.sock")))
	aliasDirectory, err := os.Open(directory)
	require.NoError(t, err)
	t.Cleanup(func() { aliasDirectory.Close() })
	alias := fmt.Sprintf("/proc/self/fd/%d/alias.sock", aliasDirectory.Fd())

	// Linux can connect through the short alias, but not the expanded path.
	connection, err := net.DialTimeout("unix", alias, time.Second)
	require.NoError(t, err)
	require.NoError(t, connection.Close())
	_, err = net.DialTimeout("unix", longSocket, time.Second)
	require.Error(t, err)

	for _, runtime := range []string{"docker", "containerd", "cri-o", "podman"} {
		t.Run(runtime, func(t *testing.T) {
			command := &cobra.Command{Run: func(*cobra.Command, []string) {}}
			flags := &CommonFlags{}
			AddCommonFlags(command, flags)
			socketFlag := runtime
			if runtime == "cri-o" {
				socketFlag = "crio"
			}
			command.SetArgs([]string{"--runtimes", runtime, "--" + socketFlag + "-socketpath", alias})
			require.NoError(t, command.Execute())
			require.Len(t, flags.RuntimeConfigs, 1)

			// Exercise the path delivered to the runtime client, not only
			// whether argument parsing accepts a symlink.
			if runtime == "docker" {
				client, err := docker.NewDockerClient(flags.RuntimeConfigs[0].SocketPath, "internal")
				require.NoError(t, err)
				require.NoError(t, client.Close())
			}
			connection, err := net.DialTimeout("unix", flags.RuntimeConfigs[0].SocketPath, time.Second)
			require.NoError(t, err)
			require.NoError(t, connection.Close())
		})
	}
}
