package tests

import (
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedTraceCapEvent struct {
	Proc utils.Process `json:"proc"`

	Cap     int32  `json:"cap"`
	Syscall string `json:"syscall"`
	Audit   int32  `json:"audit"`
	Verdict int32  `json:"verdict"`
}

type testDef struct {
	runnerConfig   *utilstest.RunnerConfig
	mntnsFilterMap func(info *utilstest.RunnerInfo) *ebpf.Map
	generateEvent  func() (int, error)
	validateEvent  func(t *testing.T, info *utilstest.RunnerInfo, capValue int, events []ExpectedTraceCapEvent)
}

func TestTraceCapabilitiesGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	testCases := map[string]testDef{
		"captures_all_events_with_no_filters_configured": {
			runnerConfig:  &utilstest.RunnerConfig{},
			generateEvent: generateCapabilityEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, capValue int, events []ExpectedTraceCapEvent) {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, capValue int) *ExpectedTraceCapEvent {
					return &ExpectedTraceCapEvent{
						Proc:    info.Proc,
						Cap:     int32(capValue),
						Syscall: "capset",
						Audit:   1,
						Verdict: 0,
					}
				})(t, info, capValue, events)
			},
		},
		"captures_no_events_with_no_matching_filter": {
			runnerConfig: &utilstest.RunnerConfig{},
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, 0)
			},
			generateEvent: generateCapabilityEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, capValue int, events []ExpectedTraceCapEvent) {
				utilstest.ExpectNoEvent(t, info, capValue, events)
			},
		},
		"captures_events_with_matching_filter": {
			runnerConfig: &utilstest.RunnerConfig{},
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: generateCapabilityEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, capValue int, events []ExpectedTraceCapEvent) {
				utilstest.ExpectOneEvent(func(info *utilstest.RunnerInfo, capValue int) *ExpectedTraceCapEvent {
					return &ExpectedTraceCapEvent{
						Proc:    info.Proc,
						Cap:     int32(capValue),
						Syscall: "capset",
						Audit:   1,
						Verdict: 0,
					}
				})(t, info, capValue, events)
			},
		},
		"test_different_capabilities": {
			runnerConfig: &utilstest.RunnerConfig{},
			generateEvent: func() (int, error) {
				header := unix.CapUserHeader{
					Version: unix.LINUX_CAPABILITY_VERSION_3,
					Pid:     0,
				}
				data := unix.CapUserData{
					Effective: 1 << uint(unix.CAP_NET_ADMIN),
				}
				err := unix.Capset(&header, &data)
				return unix.CAP_NET_ADMIN, err
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, capValue int, events []ExpectedTraceCapEvent) {
				require.NotEmpty(t, events, "Expected at least one event")
				found := false
				for _, event := range events {
					if event.Cap == int32(capValue) {
						found = true
						break
					}
				}
				require.True(t, found, "Expected to find capability %d", capValue)
			},
		},
		"test_audit_mode": {
			runnerConfig: &utilstest.RunnerConfig{},
			generateEvent: func() (int, error) {
				capValue := unix.CAP_SETUID
				header := unix.CapUserHeader{
					Version: unix.LINUX_CAPABILITY_VERSION_3,
					Pid:     0,
				}
				data := unix.CapUserData{
					Effective: 1 << uint(capValue),
				}
				err := unix.Capset(&header, &data)
				return capValue, err
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, capValue int, events []ExpectedTraceCapEvent) {
				utilstest.ExpectOneEvent(func(info *utilstest.RunnerInfo, capValue int) *ExpectedTraceCapEvent {
					return &ExpectedTraceCapEvent{
						Proc:    info.Proc,
						Cap:     int32(capValue),
						Syscall: "capset",
						Audit:   1,
						Verdict: 0,
					}
				})(t, info, capValue, events)
			},
		},
		"event_has_UID_and_GID_of_user_generating_event": {
			runnerConfig: &utilstest.RunnerConfig{
				Uid: int(1435),
				Gid: int(6789),
			},
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: generateCapabilityEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, capValue int, events []ExpectedTraceCapEvent) {
				require.Len(t, events, 1, "expected one event")
				require.Equal(t, uint32(info.Uid), events[0].Proc.Creds.Uid)
				require.Equal(t, uint32(info.Gid), events[0].Proc.Creds.Gid)
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var capValue int
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			var mntnsFilterMap *ebpf.Map
			if testCase.mntnsFilterMap != nil {
				mntnsFilterMap = testCase.mntnsFilterMap(runner.Info)
			}
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, func() error {
					var err error
					capValue, err = testCase.generateEvent()
					if err != nil {
						return err
					}
					return nil
				})
				return nil
			}
			opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceCapEvent]{
				Image:          "trace_capabilities",
				Timeout:        5 * time.Second,
				MntnsFilterMap: mntnsFilterMap,
				OnGadgetRun:    onGadgetRun,
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()

			testCase.validateEvent(t, runner.Info, capValue, gadgetRunner.CapturedEvents)
		})
	}
}

// generateCapabilityEvent simulates a capability check event
func generateCapabilityEvent() (int, error) {
	capValue := unix.CAP_NET_ADMIN
	header := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     0,
	}
	data := unix.CapUserData{
		Effective: 1 << uint(capValue),
	}
	err := unix.Capset(&header, &data)
	return capValue, err
}
