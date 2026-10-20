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

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

// GADGET_PATH_MAX (512) including the trailing NUL.
const maxNameLen = 511

type ExpectedTraceRenameEvent struct {
	Proc    utils.Process `json:"proc"`
	OldName string        `json:"oldname"`
	NewName string        `json:"newname"`
	OldPath string        `json:"oldpath"`
	NewPath string        `json:"newpath"`
	Flags   string        `json:"flags"`
}

type generated struct {
	oldName string
	newName string
	oldPath string
	newPath string
	flags   string
}

type testDef struct {
	runnerConfig *utils.RunnerConfig
	paths        bool
	// pathsValue overrides the value passed for the paths param when set.
	pathsValue     string
	mntnsFilterMap func(info *utils.RunnerInfo) *ebpf.Map
	generateEvent  func(t *testing.T) (generated, error)
	// generateEventCtx is used instead of generateEvent when the generator
	// needs the gadget context, e.g. to access the gadget's maps.
	generateEventCtx func(t *testing.T, gadgetCtx operators.GadgetContext) (generated, error)
	validateEvent    func(t *testing.T, info *utils.RunnerInfo, gen generated, events []ExpectedTraceRenameEvent)
}

func expectOne(t *testing.T, info *utils.RunnerInfo, gen generated, events []ExpectedTraceRenameEvent) {
	utils.ExpectOneEvent(func(info *utils.RunnerInfo, _ int) *ExpectedTraceRenameEvent {
		proc := info.Proc
		utils.NormalizeParentTid(&proc)
		return &ExpectedTraceRenameEvent{
			Proc:    proc,
			OldName: gen.oldName,
			NewName: gen.newName,
			OldPath: gen.oldPath,
			NewPath: gen.newPath,
			Flags:   gen.flags,
		}
	})(t, info, 0, events)
}

func expectNone(t *testing.T, info *utils.RunnerInfo, _ generated, events []ExpectedTraceRenameEvent) {
	utils.ExpectNoEvent(t, info, 0, events)
}

func matchingFilter(t *testing.T) func(info *utils.RunnerInfo) *ebpf.Map {
	return func(info *utils.RunnerInfo) *ebpf.Map {
		return utils.CreateMntNsFilterMap(t, info.MountNsID)
	}
}

func TestTraceRenameGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	testCases := map[string]testDef{
		"captures_all_events_with_no_filters_configured": {
			runnerConfig:  &utils.RunnerConfig{},
			generateEvent: generateRename,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, gen generated, events []ExpectedTraceRenameEvent) {
				utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, _ int) *ExpectedTraceRenameEvent {
					proc := info.Proc
					utils.NormalizeParentTid(&proc)
					return &ExpectedTraceRenameEvent{
						Proc:    proc,
						OldName: gen.oldName,
						NewName: gen.newName,
					}
				})(t, info, 0, events)
			},
		},
		"captures_no_events_with_no_matching_filter": {
			runnerConfig: &utils.RunnerConfig{},
			mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
				return utils.CreateMntNsFilterMap(t, 0)
			},
			generateEvent: generateRename,
			validateEvent: expectNone,
		},
		"captures_events_with_matching_filter": {
			runnerConfig:   &utils.RunnerConfig{},
			mntnsFilterMap: matchingFilter(t),
			generateEvent:  generateRename,
			validateEvent:  expectOne,
		},
		"no_event_on_failed_rename": {
			runnerConfig:   &utils.RunnerConfig{},
			mntnsFilterMap: matchingFilter(t),
			generateEvent:  generateFailedRename,
			validateEvent:  expectNone,
		},
		"renameat2_noreplace_flag": {
			runnerConfig:   &utils.RunnerConfig{},
			mntnsFilterMap: matchingFilter(t),
			generateEvent:  generateRenameat2(unix.RENAME_NOREPLACE, "RENAME_NOREPLACE", false),
			validateEvent:  expectOne,
		},
		"renameat2_exchange_flag": {
			runnerConfig:   &utils.RunnerConfig{},
			mntnsFilterMap: matchingFilter(t),
			generateEvent:  generateRenameat2(unix.RENAME_EXCHANGE, "RENAME_EXCHANGE", true),
			validateEvent:  expectOne,
		},
		"noop_rename_emits_event": {
			runnerConfig:   &utils.RunnerConfig{},
			mntnsFilterMap: matchingFilter(t),
			generateEvent:  generateNoopRename,
			validateEvent:  expectOne,
		},
		"long_name_is_truncated_not_dropped": {
			runnerConfig:   &utils.RunnerConfig{},
			mntnsFilterMap: matchingFilter(t),
			generateEvent:  generateLongNameRename,
			validateEvent:  expectOne,
		},
		"paths_resolves_absolute_paths_from_dirfd": {
			runnerConfig:   &utils.RunnerConfig{},
			paths:          true,
			mntnsFilterMap: matchingFilter(t),
			generateEvent:  generateRenameatRelative,
			validateEvent:  expectOne,
		},
		"paths_param_is_case_insensitive": {
			runnerConfig:   &utils.RunnerConfig{},
			pathsValue:     "True",
			mntnsFilterMap: matchingFilter(t),
			generateEvent:  generateRenameatRelative,
			validateEvent:  expectOne,
		},
		"paths_no_event_when_rename_fails_after_lsm_hook": {
			runnerConfig:   &utils.RunnerConfig{},
			paths:          true,
			mntnsFilterMap: matchingFilter(t),
			generateEvent:  generateRenameOntoNonEmptyDir,
			validateEvent:  expectNone,
		},
		"no_event_for_filtered_task_with_stale_entry": {
			runnerConfig: &utils.RunnerConfig{},
			mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
				return utils.CreateMntNsFilterMap(t, 0)
			},
			generateEventCtx: generateRenameWithStaleEntry,
			validateEvent:    expectNone,
		},
		"event_has_UID_and_GID_of_user_generating_event": {
			runnerConfig: &utils.RunnerConfig{
				Uid: int(1435),
				Gid: int(6789),
			},
			mntnsFilterMap: matchingFilter(t),
			generateEvent:  generateRename,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, _ generated, events []ExpectedTraceRenameEvent) {
				require.Len(t, events, 1, "expected one event")
				require.Equal(t, uint32(info.Uid), events[0].Proc.Creds.Uid)
				require.Equal(t, uint32(info.Gid), events[0].Proc.Creds.Gid)
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var gen generated
			runner := utils.NewRunnerWithTest(t, testCase.runnerConfig)
			var mntnsFilterMap *ebpf.Map
			if testCase.mntnsFilterMap != nil {
				mntnsFilterMap = testCase.mntnsFilterMap(runner.Info)
			}
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utils.RunWithRunner(t, runner, func() error {
					var err error
					if testCase.generateEventCtx != nil {
						gen, err = testCase.generateEventCtx(t, gadgetCtx)
					} else {
						gen, err = testCase.generateEvent(t)
					}
					return err
				})
				return nil
			}
			normalizeEvent := func(event *ExpectedTraceRenameEvent) {
				utils.NormalizeParentTid(&event.Proc)
			}
			paramValues := api.ParamValues{}
			if testCase.paths {
				paramValues["operator.oci.wasm.paths"] = "true"
			}
			if testCase.pathsValue != "" {
				paramValues["operator.oci.wasm.paths"] = testCase.pathsValue
			}
			opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceRenameEvent]{
				Image:          "trace_rename",
				Timeout:        5 * time.Second,
				MntnsFilterMap: mntnsFilterMap,
				ParamValues:    paramValues,
				OnGadgetRun:    onGadgetRun,
				NormalizeEvent: normalizeEvent,
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()

			testCase.validateEvent(t, runner.Info, gen, gadgetRunner.CapturedEvents)
		})
	}
}

func createFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	return f.Close()
}

// generateRename renames an existing file using absolute paths.
func generateRename(t *testing.T) (generated, error) {
	base := t.TempDir()
	oldName := filepath.Join(base, "trace_rename_old")
	newName := filepath.Join(base, "trace_rename_new")
	if err := createFile(oldName); err != nil {
		return generated{}, err
	}
	if err := unix.Rename(oldName, newName); err != nil {
		return generated{}, err
	}
	return generated{oldName: oldName, newName: newName}, nil
}

// generateFailedRename renames a file that doesn't exist; the syscall fails
// with ENOENT and the gadget must not emit anything.
func generateFailedRename(t *testing.T) (generated, error) {
	base := t.TempDir()
	err := unix.Rename(filepath.Join(base, "missing"), filepath.Join(base, "x"))
	if !errors.Is(err, unix.ENOENT) {
		return generated{}, errors.New("expected ENOENT from rename of a missing file")
	}
	return generated{}, nil
}

// generateRenameat2 calls renameat2 with the given flags. RENAME_EXCHANGE
// requires both files to exist, so createNew creates the target too.
func generateRenameat2(flags uint, flagsStr string, createNew bool) func(t *testing.T) (generated, error) {
	return func(t *testing.T) (generated, error) {
		base := t.TempDir()
		oldName := filepath.Join(base, "trace_rename_old")
		newName := filepath.Join(base, "trace_rename_new")
		if err := createFile(oldName); err != nil {
			return generated{}, err
		}
		if createNew {
			if err := createFile(newName); err != nil {
				return generated{}, err
			}
		}
		if err := unix.Renameat2(unix.AT_FDCWD, oldName, unix.AT_FDCWD, newName, flags); err != nil {
			return generated{}, err
		}
		return generated{oldName: oldName, newName: newName, flags: flagsStr}, nil
	}
}

// generateNoopRename renames a file onto itself: the kernel returns 0 without
// doing anything, so this is a successful rename and must produce an event.
func generateNoopRename(t *testing.T) (generated, error) {
	base := t.TempDir()
	name := filepath.Join(base, "trace_rename_same")
	if err := createFile(name); err != nil {
		return generated{}, err
	}
	if err := unix.Rename(name, name); err != nil {
		return generated{}, err
	}
	return generated{oldName: name, newName: name}, nil
}

// generateLongNameRename uses absolute paths longer than GADGET_PATH_MAX: the
// event must still be emitted, with names truncated to maxNameLen bytes.
func generateLongNameRename(t *testing.T) (generated, error) {
	base := t.TempDir()
	dir := filepath.Join(base, strings.Repeat("d", 200), strings.Repeat("e", 200), strings.Repeat("f", 200))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return generated{}, err
	}
	oldName := filepath.Join(dir, "trace_rename_old")
	newName := filepath.Join(dir, "trace_rename_new")
	if err := createFile(oldName); err != nil {
		return generated{}, err
	}
	if err := unix.Rename(oldName, newName); err != nil {
		return generated{}, err
	}
	return generated{oldName: oldName[:maxNameLen], newName: newName[:maxNameLen]}, nil
}

// generateRenameatRelative renames "a" to "b" relative to a directory fd, so
// oldname/newname are relative while oldpath/newpath must be absolute.
func generateRenameatRelative(t *testing.T) (generated, error) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		return generated{}, err
	}
	if err := createFile(filepath.Join(base, "a")); err != nil {
		return generated{}, err
	}
	dirfd, err := unix.Open(base, unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		return generated{}, err
	}
	defer unix.Close(dirfd)
	if err := unix.Renameat(dirfd, "a", dirfd, "b"); err != nil {
		return generated{}, err
	}
	return generated{
		oldName: "a",
		newName: "b",
		oldPath: filepath.Join(base, "a"),
		newPath: filepath.Join(base, "b"),
	}, nil
}

// generateRenameOntoNonEmptyDir renames a directory onto a non-empty one. The
// LSM hook runs (and fills the paths) but the filesystem then refuses the
// rename, so no event may be emitted.
func generateRenameOntoNonEmptyDir(t *testing.T) (generated, error) {
	base := t.TempDir()
	src := filepath.Join(base, "src")
	dst := filepath.Join(base, "dst")
	if err := os.Mkdir(src, 0o755); err != nil {
		return generated{}, err
	}
	if err := os.Mkdir(dst, 0o755); err != nil {
		return generated{}, err
	}
	if err := createFile(filepath.Join(dst, "f")); err != nil {
		return generated{}, err
	}
	err := unix.Rename(src, dst)
	if !errors.Is(err, unix.ENOTEMPTY) && !errors.Is(err, unix.EEXIST) {
		return generated{}, errors.New("expected ENOTEMPTY or EEXIST renaming onto a non-empty directory")
	}
	return generated{}, nil
}

// generateRenameWithStaleEntry simulates a `start` entry leaked by a rename
// that never reached the exit tracepoint, for a tid now reused by a task the
// filter discards. That task's successful rename must not produce an event.
func generateRenameWithStaleEntry(t *testing.T, gadgetCtx operators.GadgetContext) (generated, error) {
	v, ok := gadgetCtx.GetVar(operators.MapPrefix + "start")
	if !ok {
		return generated{}, errors.New("start map not found")
	}
	start, ok := v.(*ebpf.Map)
	if !ok {
		return generated{}, errors.New("start is not an *ebpf.Map")
	}

	// The runner executes this on a locked OS thread, so the tid is stable.
	tid := uint32(unix.Gettid())
	if err := start.Update(tid, make([]byte, start.ValueSize()), ebpf.UpdateAny); err != nil {
		return generated{}, err
	}

	return generateRename(t)
}
