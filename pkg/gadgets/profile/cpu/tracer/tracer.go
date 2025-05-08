// Copyright 2019-2023 The Inspektor Gadget authors
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

//go:build !withoutebpf

package tracer

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"unsafe"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -type key_t -cc clang -cflags ${CFLAGS} profile ./bpf/profile.bpf.c -- -I./bpf/

type Config struct {
	MountnsMap      *ebpf.Map
	UserStackOnly   bool
	KernelStackOnly bool
}

type Tracer struct {
	enricher gadgets.DataEnricherByMntNs
	objs     profileObjects
	perfFds  []int
	config   *Config
}

const (
	perfMaxStackDepth = 127
	perfSampleFreq    = 49
	// In C, struct perf_event_attr has a freq field which is a bit in a
	// 64-length bitfield.
	// In Golang, there is a Bits field which 64 bits long.
	// From C, we can deduce freq (which permits using frequency not period)
	// is the 10th bit.
	frequencyBit = 1 << 10
)

func NewTracer(enricher gadgets.DataEnricherByMntNs, config *Config) (*Tracer, error) {
	t := &Tracer{
		enricher: enricher,
		config:   config,
	}

	if err := t.install(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
}

type keyCount struct {
	key   profileKeyT
	value uint64
}

func (t *Tracer) readCountsMap() ([]keyCount, error) {
	var prev *profileKeyT = nil
	counts := t.objs.Counts
	keysCounts := []keyCount{}
	key := profileKeyT{}

	if t.objs.Counts == nil {
		return nil, fmt.Errorf("counts map was not created at moment of stop")
	}

	i := 0
	for {
		if err := counts.NextKey(unsafe.Pointer(prev), unsafe.Pointer(&key)); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return nil, fmt.Errorf("getting next key: %w", err)
		}

		var value uint64
		err := counts.Lookup(key, unsafe.Pointer(&value))
		if err != nil {
			return nil, err
		}

		kv := keyCount{
			key:   key,
			value: value,
		}

		if i < len(keysCounts)-1 {
			keysCounts[i] = kv
		} else {
			keysCounts = append(keysCounts, kv)
		}

		if value == 0 {
			continue
		}

		prev = &key
		i++
	}

	return keysCounts, nil
}

func getReport(t *Tracer, kAllSyms *kallsyms.KAllSyms, stack *ebpf.Map, keyCount keyCount) (types.Report, error) {
	kernelInstructionPointers := [perfMaxStackDepth]uint64{}
	userInstructionPointers := [perfMaxStackDepth]uint64{}
	v := keyCount.value
	k := keyCount.key

	// 	if (!env.kernel_stacks_only && k->user_stack_id >= 0) {
	if k.UserStackId >= 0 {
		err := stack.Lookup(k.UserStackId, unsafe.Pointer(&userInstructionPointers))
		if err != nil {
			return types.Report{}, err
		}
	}

	// 	if (!env.user_stacks_only && k->kern_stack_id >= 0) {
	if k.KernStackId >= 0 {
		err := stack.Lookup(k.KernStackId, unsafe.Pointer(&kernelInstructionPointers))
		if err != nil {
			return types.Report{}, err
		}
	}

	userSymbols := []string{}
	for _, ip := range userInstructionPointers {
		if ip == 0 {
			break
		}

		// We will not support getting userland symbols.
		userSymbols = append(userSymbols, "[unknown]")
	}

	kernelSymbols := []string{}
	for _, ip := range kernelInstructionPointers {
		if ip == 0 {
			break
		}

		kernelSymbols = append(kernelSymbols, kAllSyms.LookupByInstructionPointer(ip))
	}

	report := types.Report{
		Comm:        gadgets.FromCString(k.Name[:]),
		Pid:         k.Pid,
		UserStack:   userSymbols,
		KernelStack: kernelSymbols,
		Count:       v,
	}

	if t.enricher != nil {
		t.enricher.EnrichByMntNs(&report.CommonData, k.MntnsId)
	}

	return report, nil
}

func (t *Tracer) Stop() (string, error) {
	defer t.close()

	result, err := t.collectResult()
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func (t *Tracer) close() {
	t.objs.Close()

	for _, fd := range t.perfFds {
		// Disable perf event.
		err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0)
		if err != nil {
			log.Errorf("Failed to disable perf fd: %v", err)
		}

		err = unix.Close(fd)
		if err != nil {
			log.Errorf("Failed to close perf fd: %v", err)
		}
	}
}

func (t *Tracer) collectResult() ([]byte, error) {
	keysCounts, err := t.readCountsMap()
	if err != nil {
		return nil, err
	}

	sort.Slice(keysCounts, func(i, j int) bool {
		if keysCounts[i].value > keysCounts[j].value {
			return false
		}
		return keysCounts[i].value != keysCounts[j].value
	})

	kAllSyms, err := kallsyms.NewKAllSyms()
	if err != nil {
		return nil, err
	}

	reports := make([]types.Report, len(keysCounts))
	for i, keyVal := range keysCounts {
		report, err := getReport(t, kAllSyms, t.objs.Stackmap, keyVal)
		if err != nil {
			return nil, err
		}

		reports[i] = report
	}

	return json.Marshal(reports)
}

func (t *Tracer) install() error {
	spec, err := loadProfile()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	consts := map[string]interface{}{
		"kernel_stacks_only": t.config.KernelStackOnly,
		"user_stacks_only":   t.config.UserStackOnly,
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, consts, &t.objs); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	for cpu := 0; cpu < runtime.NumCPU(); cpu++ {
		// Highly inspired from:
		// https://gist.github.com/florianl/5d9cc9dbb3822e03f6f65a073ffbedbb#file-main-go-L101
		// https://github.com/iovisor/bcc/pull/3782/commits/8ee4449fa091c70f3c60cbe95929481c0d6711d1#diff-61b9f61545aedae166fcc06305a62f12699219aed0eb1e1fb4abe74fa31cb3d7R196
		// https://github.com/libbpf/libbpf/blob/645500dd7d2d6b5bb76e4c0375d597d4f0c4814e/src/libbpf.c#L10546
		fd, err := unix.PerfEventOpen(
			&unix.PerfEventAttr{
				Type:        unix.PERF_TYPE_SOFTWARE,
				Config:      unix.PERF_COUNT_SW_CPU_CLOCK,
				Sample_type: unix.PERF_SAMPLE_RAW,
				Sample:      perfSampleFreq,
				Bits:        frequencyBit,
			},
			-1,
			cpu,
			-1,
			unix.PERF_FLAG_FD_CLOEXEC,
		)
		if err != nil {
			return fmt.Errorf("creating the perf fd: %w", err)
		}

		t.perfFds = append(t.perfFds, fd)

		// Attach program to perf event.
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, t.objs.IgProfCpu.FD()); err != nil {
			return fmt.Errorf("attaching eBPF program to perf fd: %w", err)
		}

		// Start perf event.
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			return fmt.Errorf("enabling perf fd: %w", err)
		}
	}

	return nil
}

// ---

// TracerWrap is required to implement interfaces
type TracerWrap struct {
	Tracer
	enricherFunc  func(ev any) error
	eventCallback func(ev *types.Report)
}

func (t *TracerWrap) Run(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	t.config.UserStackOnly = params.Get(ParamUserStack).AsBool()
	t.config.KernelStackOnly = params.Get(ParamKernelStack).AsBool()

	defer t.close()
	if err := t.install(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	res, err := t.collectResult()
	if err != nil {
		return fmt.Errorf("collecting result: %w", err)
	}

	var reports []*types.Report
	if err = json.Unmarshal(res, &reports); err != nil {
		return fmt.Errorf("unmarshaling report: %w", err)
	}
	for _, report := range reports {
		t.eventCallback(report)
	}

	return nil
}

func (t *TracerWrap) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *types.Report))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

func (t *TracerWrap) SetEventEnricher(enricher func(ev any) error) {
	t.enricherFunc = enricher
	t.enricher = t
}

func (t *TracerWrap) EnrichByMntNs(event *eventtypes.CommonData, mountnsid uint64) {
	// TODO: This is ugly as it temporarily wraps and unwraps the event; should be changed in the original gadget code
	//  after full migration to NewInstance()
	wrap := &types.Report{CommonData: *event, MntnsID: mountnsid}
	t.enricherFunc(wrap)
	*event = wrap.CommonData
}

func (t *TracerWrap) SetMountNsMap(mountNsMap *ebpf.Map) {
	t.config.MountnsMap = mountNsMap
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &TracerWrap{
		Tracer: Tracer{
			config: &Config{},
		},
	}
	return tracer, nil
}
