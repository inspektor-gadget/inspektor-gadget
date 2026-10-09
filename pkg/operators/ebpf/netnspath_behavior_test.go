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
	"bytes"
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	orasoci "oras.land/oras-go/v2/content/oci"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/networktracer"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

// TestNetnsPathMixedSocketFilterTracepoint needs BPF, raw sockets, setns and
// tracepoint attachment privileges, plus kernel BTF for the network dispatcher.
func TestNetnsPathMixedSocketFilterTracepoint(t *testing.T) {
	utilstest.RequireRoot(t)

	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"socket": {
			Name: "socket", Type: ebpf.SocketFilter, SectionName: "socket", License: "GPL",
			Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		},
		"trace": {
			Name: "trace", Type: ebpf.TracePoint, SectionName: "tracepoint/raw_syscalls/sys_enter", AttachTo: "raw_syscalls/sys_enter", License: "GPL",
			Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		},
	}}
	collection, err := ebpf.NewCollection(spec)
	require.NoError(t, err)
	t.Cleanup(collection.Close)
	tracer, err := networktracer.NewTracer[api.GadgetData]()
	require.NoError(t, err)
	t.Cleanup(tracer.Close)

	var output bytes.Buffer
	lg := logrus.New()
	lg.SetOutput(&output)
	lg.SetLevel(logger.DebugLevel)
	// Keep the target namespace alive on a disposable OS thread. A distinct
	// target catches accidentally attaching the socket in the caller's netns.
	target := make(chan string, 1)
	failed := make(chan error, 1)
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		runtime.LockOSThread()
		// Never unlock: this thread must die rather than rejoin the runtime
		// pool in a different network namespace.
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			failed <- err
			return
		}
		target <- fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), unix.Gettid())
		<-done
	}()
	var path string
	select {
	case path = <-target:
	case err := <-failed:
		t.Fatalf("creating target network namespace: %v", err)
	}
	var original, selected unix.Stat_t
	require.NoError(t, unix.Stat("/proc/self/ns/net", &original))
	require.NoError(t, unix.Stat(path, &selected))
	require.NotEqual(t, original.Ino, selected.Ino)
	i := newNetnsPathInstance(path, true, false)
	i.logger = lg
	i.config = viper.New()
	i.collectionSpec = spec
	i.collection = collection
	i.networkTracers = map[string]*networktracer.Tracer[api.GadgetData]{"socket": tracer}
	require.NoError(t, i.PreStart(nil))

	l, err := i.attachProgram(nil, spec.Programs["socket"], collection.Programs["socket"])
	require.NoError(t, err)
	require.Nil(t, l, "socket filters attach via the network tracer, not a link")
	l, err = i.attachProgram(nil, spec.Programs["trace"], collection.Programs["trace"])
	require.NoError(t, err)
	require.NotNil(t, l, "unaffected tracepoints must attach normally")
	t.Cleanup(func() { require.NoError(t, l.Close()) })
	require.Equal(t, 1, strings.Count(output.String(), "Ignoring"))
	require.Contains(t, output.String(), ParamNetnsPath)

	// Detach fails if attachProgram never installed an attachment for this
	// exact path. This verifies a real namespace target without private hooks.
	require.NoError(t, tracer.DetachNetnsPath(i.netnsPath))
	require.ErrorContains(t, tracer.DetachNetnsPath(i.netnsPath), "is not attached")
}

func TestNetnsPathRegistrationForTracepoints(t *testing.T) {
	ctx := context.Background()
	// Use the committed OCI example rather than injecting a handler map: this
	// exercises image metadata, ebpfInstance.init and CLI parameter registration.
	store, err := orasoci.NewFromTar(ctx, "../../../docs/api/_golang/from_file/trace_open.tar")
	require.NoError(t, err)
	gadgetCtx := gadgetcontext.New(ctx, "ghcr.io/inspektor-gadget/gadget/trace_open:latest",
		gadgetcontext.WithDataOperators(ocihandler.OciHandler),
		gadgetcontext.WithOrasReadonlyTarget(store))
	t.Cleanup(gadgetCtx.Cancel)
	require.NoError(t, gadgetCtx.LoadGadgetInfo(&api.GadgetInfo{}, api.ParamValues{
		"operator.oci.verify-image":    "false",
		"operator.oci.ebpf.netns-path": "invalid-relative-path",
	}, false, nil))

	inst, ok := gadgetCtx.GetVar("ebpfInstance")
	require.True(t, ok)
	i := inst.(*ebpfInstance)
	t.Cleanup(func() { require.NoError(t, i.Close(gadgetCtx)) })
	require.NotEmpty(t, i.collectionSpec.Programs)
	for _, p := range i.collectionSpec.Programs {
		require.Equal(t, ebpf.TracePoint, p.Type, "fixture must contain only tracepoints")
	}
	var exposed bool
	for _, p := range gadgetCtx.Params() {
		if p.Prefix+p.Key == "operator.oci.ebpf.netns-path" {
			exposed = true
		}
		require.NotEqual(t, "operator.oci.ebpf.iface", p.Prefix+p.Key)
	}
	require.True(t, exposed, "tracepoint-only gadgets must expose netns-path to the CLI")
	require.NoError(t, i.PreStart(gadgetCtx), "an invalid path must be ignored for the real tracepoint-only gadget")
	require.Empty(t, i.netnsPath)
}

func TestPreStartNetnsPath(t *testing.T) {
	ownNetns := fmt.Sprintf("/proc/%d/ns/net", os.Getpid())
	for _, tc := range []struct {
		name string
		path string
		tc   bool
		want string
		err  string
	}{
		{name: "socket filter", path: ownNetns, want: ownNetns},
		{name: "default applied before validation", want: ownNetns},
		{name: "TC rejected before callbacks", path: ownNetns, tc: true, err: "not yet supported for TC programs"},
		{name: "invalid socket target", path: "relative", err: "must be an absolute path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := newNetnsPathInstance(tc.path, true, tc.tc)
			i.collectionSpec = &ebpf.CollectionSpec{}
			i.params = map[string]*param{ParamNetnsPath: {Param: &api.Param{Key: ParamNetnsPath, DefaultValue: ownNetns}}}
			if tc.path == "" {
				delete(i.paramValues, ParamNetnsPath)
			}
			err := i.PreStart(nil)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				require.Empty(t, i.netnsPath)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want, i.netnsPath, "effective mode must be ready before manager callbacks")
			}
		})
	}
}

func TestNetnsPathIgnoredDebugLog(t *testing.T) {
	var output bytes.Buffer
	lg := logrus.New()
	lg.SetOutput(&output)
	lg.SetLevel(logrus.DebugLevel)
	i := newNetnsPathInstance("relative/invalid", false, false)
	i.logger = lg
	require.NoError(t, i.validateNetnsPath())
	require.Empty(t, i.netnsPath)
	require.Contains(t, output.String(), "level=debug")
	require.Contains(t, output.String(), "Ignoring")
	require.Contains(t, output.String(), ParamNetnsPath)
	require.Equal(t, 1, strings.Count(output.String(), "Ignoring"))
}

func TestNetnsPathMixedAttachmentLogsAndErrors(t *testing.T) {
	// Malformed attachment specs reach real attachProgram error paths without
	// requiring kernel privileges. Ignoring netns-path must not swallow errors.
	for _, tc := range []struct {
		name string
		prog *ebpf.ProgramSpec
		err  string
	}{
		{"kprobe", &ebpf.ProgramSpec{Name: "probe", Type: ebpf.Kprobe, SectionName: "unsupported"}, "unsupported section name"},
		{"iterator", &ebpf.ProgramSpec{Name: "iter", Type: ebpf.Tracing, SectionName: "iter/unknown", AttachTo: "unknown"}, "unsupported iter type"},
		{"unknown program", &ebpf.ProgramSpec{Name: "unknown", Type: ebpf.UnspecifiedProgram}, "unsupported program"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			lg := logrus.New()
			lg.SetOutput(&output)
			lg.SetLevel(logrus.DebugLevel)
			i := newNetnsPathInstance("/proc/self/ns/net", true, false)
			i.logger = lg
			i.config = viper.New()
			require.NoError(t, i.validateNetnsPath())
			l, err := i.attachProgram(nil, tc.prog, nil)
			require.Nil(t, l)
			require.ErrorContains(t, err, tc.err)
			require.Contains(t, output.String(), "level=debug")
			require.Contains(t, output.String(), ParamNetnsPath)
			require.Contains(t, output.String(), tc.prog.Name)
			require.Equal(t, 1, strings.Count(output.String(), "Ignoring"), "one ignored-flag message per unaffected attachment")
		})
	}
}
