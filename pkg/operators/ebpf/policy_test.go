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
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestPolicyRegression(t *testing.T) {
	for _, tt := range []struct {
		name    string
		cfg     Config
		typ     ebpf.ProgramType
		helper  asm.BuiltinFunc
		allowed bool
	}{
		{"default future", Config{}, ebpf.ProgramType(10000), asm.BuiltinFunc(10000), true},
		{"drop only", Config{Policy: PolicyConfigSpec{Helpers: HelpersConfig{Drop: []string{"bpf_override_return"}}}}, ebpf.Kprobe, asm.FnGetCurrentPidTgid, true},
		{"reset then add", Config{Policy: PolicyConfigSpec{ProgramTypes: ProgramTypesConfig{Add: []string{"kprobe"}, Drop: []string{"all"}}}}, ebpf.Kprobe, asm.FnGetCurrentPidTgid, true},
		{"readonly writable tracepoint", Config{Policy: PolicyConfigSpec{Helpers: HelpersConfig{Add: []string{"all"}}, ProgramTypes: ProgramTypesConfig{Add: []string{"readonly"}}}}, ebpf.RawTracepointWritable, asm.FnGetCurrentPidTgid, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewPolicy(&tt.cfg)
			if err != nil {
				t.Fatal(err)
			}
			err = verifyCollectionSpec(&ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{"test": {Type: tt.typ, Instructions: asm.Instructions{tt.helper.Call()}}}}, p)
			if (err == nil) != tt.allowed {
				t.Fatalf("allowed=%v, err=%v", tt.allowed, err)
			}
		})
	}
}

func policyTestSpec(typ ebpf.ProgramType, instructions ...asm.Instruction) *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{"test": {Type: typ, Instructions: instructions}}}
}

func TestPolicyTruthTable(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		add, drop            []string
		known, other, future bool
		invalid              bool
	}{
		{name: "empty", known: true, other: true, future: true},
		{name: "named add", add: []string{" BPF_PROG_TYPE_KPROBE ", "kprobe"}, known: true},
		{name: "all", add: []string{" ALL "}, known: true, other: true, future: true},
		{name: "drop", drop: []string{"xdp"}, known: true, future: true},
		{name: "overlap", add: []string{"kprobe"}, drop: []string{"kprobe"}},
		{name: "deny all", drop: []string{"all"}},
		{name: "reset add", add: []string{"kprobe"}, drop: []string{"all"}, known: true},
		{name: "reset readonly", add: []string{"readonly"}, drop: []string{"all"}, known: true},
		{name: "all minus named", add: []string{"all"}, drop: []string{"xdp"}, known: true, future: true},
		{name: "contradiction", add: []string{"all"}, drop: []string{"all"}, invalid: true},
		{name: "mixed keyword", add: []string{"readonly", "kprobe"}, invalid: true},
		{name: "drop readonly", drop: []string{"readonly"}, invalid: true},
		{name: "unknown", add: []string{"not-a-type"}, invalid: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewPolicy(&Config{Policy: PolicyConfigSpec{ProgramTypes: ProgramTypesConfig{Add: tt.add, Drop: tt.drop}}})
			if tt.invalid {
				if err == nil || !strings.Contains(err.Error(), ConfigKey+".policy.programTypes") {
					t.Fatalf("expected path error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range []struct {
				typ     ebpf.ProgramType
				allowed bool
			}{{ebpf.Kprobe, tt.known}, {ebpf.XDP, tt.other}, {ebpf.ProgramType(10000), tt.future}} {
				err := verifyCollectionSpec(policyTestSpec(item.typ, asm.FnSendSignal.Call()), p)
				if (err == nil) != item.allowed {
					t.Errorf("type %v allowed=%v: %v", item.typ, item.allowed, err)
				}
			}
		})
	}
}

func TestPolicyHelperSemantics(t *testing.T) {
	for _, tt := range []struct {
		name      string
		add, drop []string
		allowed   bool
	}{
		{name: "default", allowed: true},
		{name: "all", add: []string{"all"}, allowed: true},
		{name: "deny unrelated", drop: []string{"bpf_override_return"}, allowed: true},
		{name: "finite", add: []string{"bpf_ktime_get_ns"}},
		{name: "deny all", drop: []string{"all"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewPolicy(&Config{Policy: PolicyConfigSpec{Helpers: HelpersConfig{Add: tt.add, Drop: tt.drop}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []asm.BuiltinFunc{10000, ^asm.BuiltinFunc(0), 0xbad2310} {
				err := verifyCollectionSpec(policyTestSpec(ebpf.Kprobe, id.Call()), p)
				if (err == nil) != tt.allowed {
					t.Fatalf("helper %v allowed=%v: %v", id, tt.allowed, err)
				}
			}
		})
	}
	p, err := NewPolicy(&Config{Policy: PolicyConfigSpec{Helpers: HelpersConfig{Add: []string{" BPF_KTIME_GET_NS ", "bpf_ktime_get_ns"}, Drop: []string{"all"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCollectionSpec(policyTestSpec(ebpf.XDP, asm.FnKtimeGetNs.Call()), p); err != nil {
		t.Fatal(err)
	}
	p, err = NewPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCollectionSpec(nil, p); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyReadonly(t *testing.T) {
	p, err := NewPolicy(&Config{Policy: PolicyConfigSpec{Helpers: HelpersConfig{Add: []string{"readonly"}}, ProgramTypes: ProgramTypesConfig{Add: []string{"readonly"}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []ebpf.ProgramType{ebpf.Kprobe, ebpf.TracePoint, ebpf.RawTracepoint, ebpf.PerfEvent} {
		if err := verifyCollectionSpec(policyTestSpec(typ, asm.FnPerfEventOutput.Call(), asm.FnMapUpdateElem.Call(), asm.FnProbeReadKernel.Call()), p); err != nil {
			t.Error(err)
		}
	}
	for _, typ := range []ebpf.ProgramType{ebpf.RawTracepointWritable, ebpf.Tracing, ebpf.LSM, ebpf.Syscall, ebpf.SocketFilter, ebpf.XDP} {
		if err := verifyCollectionSpec(policyTestSpec(typ), p); err == nil {
			t.Errorf("admitted %v", typ)
		}
	}
	for _, h := range []asm.BuiltinFunc{asm.FnOverrideReturn, asm.FnSendSignal, asm.FnSendSignalThread, asm.FnProbeWriteUser, asm.FnSysBpf, asm.FnSetRetval, asm.FnSkbStoreBytes, asm.FnRedirect, asm.FnSetsockopt, asm.FnGetHashRecalc, asm.FnBtfFindByNameKind, asm.FnTimerInit, asm.FnTimerSetCallback, asm.FnTimerStart, asm.FnTimerCancel, asm.FnDynptrWrite} {
		if err := verifyCollectionSpec(policyTestSpec(ebpf.Kprobe, h.Call()), p); err == nil {
			t.Errorf("admitted %v", h)
		}
	}
}

func TestPolicyLoaderFallback(t *testing.T) {
	for source, destination := range map[asm.BuiltinFunc]asm.BuiltinFunc{asm.FnProbeReadKernel: asm.FnProbeRead, asm.FnProbeReadUser: asm.FnProbeRead, asm.FnProbeReadKernelStr: asm.FnProbeReadStr, asm.FnProbeReadUserStr: asm.FnProbeReadStr} {
		for _, allowDestination := range []bool{false, true} {
			add := []string{helperFuncToName(source)}
			if allowDestination {
				add = append(add, helperFuncToName(destination))
			}
			p, err := NewPolicy(&Config{Policy: PolicyConfigSpec{Helpers: HelpersConfig{Add: add}}})
			if err != nil {
				t.Fatal(err)
			}
			err = verifyCollectionSpec(policyTestSpec(ebpf.Kprobe, source.Call()), p)
			if allowDestination {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "loader fallback") {
				t.Fatalf("missing fallback error: %v", err)
			}
		}
	}
}

func TestPolicyCallClassification(t *testing.T) {
	kfunc := asm.Instruction{OpCode: asm.Call.Op(asm.ImmSource), Src: asm.PseudoKfuncCall, Constant: 123}
	for _, tt := range []struct {
		add, drop []string
		denyKfunc bool
	}{{add: []string{"readonly"}, denyKfunc: true}, {add: []string{"all"}}, {add: []string{"bpf_ktime_get_ns"}}, {drop: []string{"all"}}} {
		p, err := NewPolicy(&Config{Policy: PolicyConfigSpec{Helpers: HelpersConfig{Add: tt.add, Drop: tt.drop}}})
		if err != nil {
			t.Fatal(err)
		}
		// A pseudo call and ordinary immediate are not builtin calls.
		if err := verifyCollectionSpec(policyTestSpec(ebpf.Kprobe, asm.Call.Label("subprog"), asm.Mov.Imm(asm.R0, int32(asm.FnOverrideReturn))), p); err != nil {
			t.Fatal(err)
		}
		err = verifyCollectionSpec(policyTestSpec(ebpf.Kprobe, kfunc), p)
		if (err != nil) != tt.denyKfunc {
			t.Fatalf("kfunc denied=%v: %v", tt.denyKfunc, err)
		}
	}
}

func TestPolicyDiagnosticsAndSnapshot(t *testing.T) {
	cfg := &Config{Policy: PolicyConfigSpec{Helpers: HelpersConfig{Add: []string{"bpf_ktime_get_ns"}}, ProgramTypes: ProgramTypesConfig{Add: []string{"kprobe"}}}}
	p, err := NewPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Policy.Helpers.Add[0] = "all"
	cfg.Policy.ProgramTypes.Add[0] = "all"
	spec := policyTestSpec(ebpf.XDP, asm.FnSendSignal.Call(), asm.FnSendSignal.Call(), asm.FnOverrideReturn.Call())
	spec.Programs["alpha"] = &ebpf.ProgramSpec{Type: ebpf.LSM, Instructions: asm.Instructions{asm.FnProbeWriteUser.Call()}}
	first := verifyCollectionSpec(spec, p)
	if first == nil {
		t.Fatal("snapshot changed")
	}
	for range 20 {
		if err := verifyCollectionSpec(spec, p); err.Error() != first.Error() {
			t.Fatalf("unstable diagnostics: %v", err)
		}
	}
	if strings.Count(first.Error(), "bpf_send_signal") != 1 {
		t.Fatal(first)
	}
}

func BenchmarkPolicyVerification(b *testing.B) {
	for _, mode := range []string{"all", "readonly"} {
		b.Run(mode, func(b *testing.B) {
			p, err := NewPolicy(&Config{Policy: PolicyConfigSpec{Helpers: HelpersConfig{Add: []string{mode}}, ProgramTypes: ProgramTypesConfig{Add: []string{mode}}}})
			if err != nil {
				b.Fatal(err)
			}
			spec := policyTestSpec(ebpf.Kprobe)
			for range 1000 {
				spec.Programs["test"].Instructions = append(spec.Programs["test"].Instructions, asm.FnGetCurrentPidTgid.Call())
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := verifyCollectionSpec(spec, p); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
