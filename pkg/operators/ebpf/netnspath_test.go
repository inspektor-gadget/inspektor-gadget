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

package ebpfoperator

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/tchandler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// newNetnsPathInstance builds the minimum of an ebpfInstance that
// resolveNetnsPath() looks at.
func newNetnsPathInstance(path string, withNetworkTracer, withTCHandler bool) *ebpfInstance {
	i := &ebpfInstance{
		paramValues:    map[string]string{ParamNetnsPath: path},
		networkTracers: map[string]*networktracer.Tracer[api.GadgetData]{},
		tcHandlers:     map[string]*tchandler.Handler{},
	}
	if withNetworkTracer {
		i.networkTracers["ig_trace_net"] = nil
	}
	if withTCHandler {
		i.tcHandlers["ig_trace_tc"] = nil
	}
	return i
}

func TestResolveNetnsPath(t *testing.T) {
	ownNetns := fmt.Sprintf("/proc/%d/ns/net", os.Getpid())

	tests := []struct {
		name              string
		path              string
		withNetworkTracer bool
		withTCHandler     bool
		errContains       string
	}{
		{
			name:              "unset",
			path:              "",
			withNetworkTracer: true,
		},
		{
			// The magic link at /proc/<pid>/ns/net can only be resolved by the
			// kernel, so path resolution must leave the last component alone.
			name:              "own network namespace",
			path:              ownNetns,
			withNetworkTracer: true,
		},
		{
			name:              "unset on a gadget with tc programs",
			path:              "",
			withNetworkTracer: true,
			withTCHandler:     true,
		},
		{
			name:              "tc programs",
			path:              ownNetns,
			withNetworkTracer: true,
			withTCHandler:     true,
			errContains:       "not yet supported for TC programs",
		},
		{
			// A gadget with only TC programs is rejected the same way: the
			// parameter is registered for it so that the error is explicit.
			name:          "tc programs only",
			path:          ownNetns,
			withTCHandler: true,
			errContains:   "not yet supported for TC programs",
		},
		{
			name:        "no network programs",
			path:        ownNetns,
			errContains: "only supported by gadgets with network programs",
		},
		{
			name:              "relative path",
			path:              "run/netns/foo",
			withNetworkTracer: true,
			errContains:       "must be an absolute path",
		},
		{
			name:              "nonexistent path",
			path:              "/run/netns/does-not-exist-4f2c1b",
			withNetworkTracer: true,
			errContains:       "no such file or directory",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			i := newNetnsPathInstance(test.path, test.withNetworkTracer, test.withTCHandler)

			err := i.resolveNetnsPath()
			if test.errContains != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.errContains)
				require.Empty(t, i.netnsPath, "nothing must be attached to after a failure")
				return
			}

			require.NoError(t, err)
			if test.path == "" {
				require.Empty(t, i.netnsPath)
			} else {
				// The host root is "/" in tests, so the path is kept as is.
				require.Equal(t, test.path, i.netnsPath)
			}
		})
	}
}

// TestResolveNetnsPathConfinesToHostRoot checks that a symlink in the host
// filesystem cannot make the gadget attach to a namespace outside of it. Only
// paths under /proc are resolved component-wise, because their last component
// is a magic link the kernel alone can follow.
func TestResolveNetnsPathConfinesToHostRoot(t *testing.T) {
	hostRoot := t.TempDir()

	saved := host.HostRoot
	host.HostRoot = hostRoot
	t.Cleanup(func() { host.HostRoot = saved })

	// <hostRoot>/run/netns/escape -> /proc/self/ns/net, which is a real network
	// namespace on the host but must be read as <hostRoot>/proc/self/ns/net,
	// which does not exist.
	require.NoError(t, os.MkdirAll(filepath.Join(hostRoot, "run", "netns"), 0o755))
	require.NoError(t, os.Symlink("/proc/self/ns/net", filepath.Join(hostRoot, "run", "netns", "escape")))

	i := newNetnsPathInstance("/run/netns/escape", true, false)

	err := i.resolveNetnsPath()
	require.Error(t, err, "a symlink pointing out of the host root must not resolve")
	require.Empty(t, i.netnsPath, "nothing must be attached to after a failure")
}
