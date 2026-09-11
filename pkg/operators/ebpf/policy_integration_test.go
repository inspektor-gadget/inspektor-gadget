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
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func setPolicyAdminConfig(t *testing.T, v *viper.Viper) {
	t.Helper()
	previous := config.Config
	config.Config = v
	t.Cleanup(func() { config.Config = previous })
}

func policyFixtureInstance(t *testing.T, metadata string, remote bool) (*ebpfInstance, *gadgetcontext.GadgetContext) {
	t.Helper()
	ctx := gadgetcontext.New(t.Context(), "policy-test", gadgetcontext.WithAsRemoteCall(remote))
	require.NoError(t, ctx.SetMetadata([]byte(metadata)))
	metadataConfig, ok := ctx.GetVar("config")
	require.True(t, ok)
	program, err := os.ReadFile("testdata/policy.bpf.o")
	require.NoError(t, err)
	instance := &ebpfInstance{
		bpfOperator: &ebpfOperator{btfCache: btf.NewCache(), gadgetObjs: make(map[operators.GadgetContext]gadgetObjects)},
		program:     program,
		config:      metadataConfig.(*viper.Viper),
		logger:      ctx.Logger(),
		gadgetCtx:   ctx,
		params:      make(map[string]*param),
		done:        make(chan struct{}),
	}
	t.Cleanup(func() {
		require.NoError(t, instance.Stop(ctx))
		require.NoError(t, instance.Close(ctx))
	})
	return instance, ctx
}

func TestPolicyCompiledFunctions(t *testing.T) {
	for _, fixture := range []string{"policy", "policy-callback"} {
		t.Run(fixture, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpec("testdata/" + fixture + ".bpf.o")
			require.NoError(t, err)
			p, err := NewPolicy(&Config{Policy: PolicyConfigSpec{Helpers: HelpersConfig{Drop: []string{"bpf_get_current_pid_tgid"}}}})
			require.NoError(t, err)
			require.ErrorContains(t, verifyCollectionSpec(spec, p), "bpf_get_current_pid_tgid")
			// The denied helper lives in a linked function body, reached by a
			// pseudo-call or a function pointer rather than a direct entry call.
			linkedFunction := false
			for _, ins := range spec.Programs["observe"].Instructions {
				if ins.IsFunctionCall() || ins.Src == asm.PseudoFunc {
					linkedFunction = true
				}
			}
			require.True(t, linkedFunction)
		})
	}
}

func TestPolicyCompiledKfunc(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec("testdata/policy-kfunc.bpf.o")
	require.NoError(t, err)
	p, err := NewPolicy(&Config{Policy: PolicyConfigSpec{Helpers: HelpersConfig{Add: []string{"readonly"}}}})
	require.NoError(t, err)
	require.ErrorContains(t, verifyCollectionSpec(spec, p), "kfunc")
	unrestricted, err := NewPolicy(nil)
	require.NoError(t, err)
	require.NoError(t, verifyCollectionSpec(spec, unrestricted))
}

func TestPolicyAdministratorOverridesImageMetadata(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "remote-context"}[remote], func(t *testing.T) {
			admin := viper.New()
			admin.Set("operator.ebpf.policy.helpers.drop", []string{"bpf_get_current_pid_tgid"})
			setPolicyAdminConfig(t, admin)
			instance, ctx := policyFixtureInstance(t, "operator:\n  ebpf:\n    policy:\n      helpers:\n        add: [all]\n", remote)
			require.ErrorContains(t, instance.init(ctx), "bpf_get_current_pid_tgid")
			require.Nil(t, instance.collection)
		})
	}
}

func TestPolicyFinalCheckpointUsesSnapshot(t *testing.T) {
	admin := viper.New()
	admin.Set("operator.ebpf.policy.helpers.drop", []string{"bpf_send_signal"})
	setPolicyAdminConfig(t, admin)
	instance, ctx := policyFixtureInstance(t, "{}", false)
	require.NoError(t, instance.init(ctx))

	// A late mutation affects this initialized instance's actual load path.
	prog := instance.collectionSpec.Programs["observe"]
	prog.Instructions = append(asm.Instructions{asm.FnSendSignal.Call()}, prog.Instructions...)
	// Neither changed administrator state nor image metadata can weaken the
	// immutable policy captured during this instance's initialization.
	admin.Set("operator.ebpf.policy.helpers.drop", []string{})
	instance.config.Set("operator.ebpf.policy.helpers.add", []string{"all"})
	require.ErrorContains(t, instance.Start(ctx), "verifying BPF policy before loading")
	require.Nil(t, instance.collection)
}

func TestPolicyKtimeTransformationPreservesPermission(t *testing.T) {
	p, err := NewPolicy(&Config{Policy: PolicyConfigSpec{Helpers: HelpersConfig{Add: []string{"bpf_ktime_get_boot_ns"}}}})
	require.NoError(t, err)
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"clock": {Type: ebpf.Kprobe, Instructions: asm.Instructions{asm.FnKtimeGetBootNs.Call(), asm.Return()}},
	}}
	require.NoError(t, verifyCollectionSpec(spec, p))
	gadgets.FixBpfKtimeGetBootNs(spec.Programs)
	require.NoError(t, verifyCollectionSpec(spec, p))
}

func TestPolicyLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load and attach the tracepoint fixture")
	}
	for _, mode := range []string{"default", "readonly"} {
		t.Run(mode, func(t *testing.T) {
			admin := viper.New()
			if mode == "readonly" {
				admin.Set("operator.ebpf.policy.helpers.add", []string{"readonly"})
				admin.Set("operator.ebpf.policy.programTypes.add", []string{"readonly"})
			}
			setPolicyAdminConfig(t, admin)
			instance, ctx := policyFixtureInstance(t, "{}", false)
			require.NoError(t, instance.init(ctx))
			require.NoError(t, instance.Start(ctx))
			require.NotNil(t, instance.collection)
			require.NotEmpty(t, instance.links)
		})
	}
}

func TestPolicyDocumentationExamples(t *testing.T) {
	doc, err := os.ReadFile("../../../docs/reference/limiting-permissions.mdx")
	require.NoError(t, err)
	count := 0
	for _, section := range strings.Split(string(doc), "```yaml\n")[1:] {
		body, _, ok := strings.Cut(section, "```")
		require.True(t, ok)
		v := viper.New()
		v.SetConfigType("yaml")
		require.NoError(t, v.ReadConfig(strings.NewReader(body)))
		cfg, err := NewConfigFromViper(v)
		require.NoError(t, err, body)
		_, err = NewPolicy(cfg)
		require.NoError(t, err, body)
		count++
	}
	require.GreaterOrEqual(t, count, 3)
}
