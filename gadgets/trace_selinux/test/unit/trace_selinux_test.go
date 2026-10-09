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

package tests

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

const (
	selinuxfs = "/sys/fs/selinux"

	// Contexts from testdata/policy.conf.
	testContext   = "system_u:system_r:test_t"
	secretContext = "system_u:object_r:secret_t"
)

type traceSelinuxEvent struct {
	Proc          utils.Process `json:"proc"`
	Scontext      string        `json:"scontext"`
	Tcontext      string        `json:"tcontext"`
	Tclass        string        `json:"tclass"`
	DeniedPerms   string        `json:"denied_perms"`
	DeniedUnknown uint32        `json:"denied_unknown"`
}

func TestTraceSelinux(t *testing.T) {
	// Check that the gadget loads and runs without errors on every kernel.
	// TestTraceSelinuxDenial checks the produced data where it can.

	// The avc:selinux_audited tracepoint was added in v5.10-rc1.
	gadgettesting.MinimumKernelVersion(t, "5.10")

	gadgettesting.DummyGadgetTest(t, "trace_selinux")
}

// TestTraceSelinuxDenial loads a minimal SELinux policy that denies reading
// files labelled secret_t, reads such a file and checks the reported denial.
// Loading a policy cannot be undone, so it only runs in a disposable VM that
// has no policy yet.
func TestTraceSelinuxDenial(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	gadgettesting.MinimumKernelVersion(t, "5.10")
	gadgettesting.RequireDisposableVM(t)

	loadTestPolicy(t)

	runner := utils.NewRunnerWithTest(t, nil)

	// tmpfs is the only labelable filesystem in the test policy. Mount it in
	// the mount namespace of the runner, so that it goes away with it.
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	utils.RunWithRunner(t, runner, func() error {
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			return err
		}
		if err := unix.Mount("tmpfs", dir, "tmpfs", 0, ""); err != nil {
			return err
		}
		if err := os.WriteFile(secret, []byte("secret\n"), 0o600); err != nil {
			return err
		}
		return unix.Setxattr(secret, "security.selinux", []byte(secretContext), 0)
	})

	onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
		utils.RunWithRunner(t, runner, func() error {
			// The kernel is expected to be permissive, but tolerate an
			// enforcing one: the denial is audited either way.
			_, err := os.ReadFile(secret)
			if err != nil && !errors.Is(err, os.ErrPermission) {
				return err
			}
			return nil
		})
		return nil
	}
	opts := gadgetrunner.GadgetRunnerOpts[traceSelinuxEvent]{
		Image:          "trace_selinux",
		Timeout:        5 * time.Second,
		ParamValues:    api.ParamValues{},
		OnGadgetRun:    onGadgetRun,
		MntnsFilterMap: utils.CreateMntNsFilterMap(t, runner.Info.MountNsID),
	}
	gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

	gadgetRunner.RunGadget()

	// The AVC caches a permissive denial as granted, so only the first
	// check is audited.
	require.Len(t, gadgetRunner.CapturedEvents, 1, "One event is expected")
	event := gadgetRunner.CapturedEvents[0]
	require.Equal(t, uint32(runner.Info.Pid), event.Proc.Pid)
	require.Equal(t, uint32(runner.Info.Tid), event.Proc.Tid)
	require.Equal(t, runner.Info.Comm, event.Proc.Comm)
	require.Equal(t, runner.Info.MountNsID, event.Proc.MntNsID)
	require.Equal(t, testContext, event.Scontext)
	require.Equal(t, secretContext, event.Tcontext)
	require.Equal(t, "file", event.Tclass)
	require.Equal(t, "read", event.DeniedPerms)
	require.Zero(t, event.DeniedUnknown)
}

// loadTestPolicy loads testdata/policy.bin into the kernel.
func loadTestPolicy(t *testing.T) {
	t.Helper()

	if _, err := os.Stat(selinuxfs); err != nil {
		t.Skipf("Skipping test because SELinux is not enabled: %s", err)
	}

	var st unix.Statfs_t
	require.NoError(t, unix.Statfs(selinuxfs, &st))
	if st.Type != unix.SELINUX_MAGIC {
		require.NoError(t, unix.Mount("selinuxfs", selinuxfs, "selinuxfs", 0, ""), "mounting selinuxfs")
	}

	// The class directory is only populated once a policy is loaded.
	classes, err := os.ReadDir(filepath.Join(selinuxfs, "class"))
	require.NoError(t, err)
	if len(classes) > 0 {
		t.Skip("Skipping test because an SELinux policy is already loaded")
	}

	// Generated from testdata/policy.conf, see testdata/Makefile.
	data, err := os.ReadFile("testdata/policy.bin")
	require.NoError(t, err)
	f, err := os.OpenFile(filepath.Join(selinuxfs, "load"), os.O_WRONLY, 0)
	require.NoError(t, err)
	defer f.Close()
	_, err = f.Write(data)
	require.NoError(t, err, "loading the test policy")

	enforce, err := os.ReadFile(filepath.Join(selinuxfs, "enforce"))
	require.NoError(t, err)
	t.Logf("Loaded the test policy, enforce=%s", strings.TrimSpace(string(enforce)))
}
