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
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -type key_t -cc clang profile ./bpf/profile.bpf.c -- -I./bpf/ -I../../../../${TARGET}

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

	if err := t.start(); err != nil {
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
	counts := t.objs.profileMaps.Counts
	keysCounts := []keyCount{}
	key := profileKeyT{}

	if t.objs.profileMaps.Counts == nil {
		return nil, fmt.Errorf("counts map was not created at moment of stop")
	}

	i := 0
	for {
		if err := counts.NextKey(unsafe.Pointer(prev), unsafe.Pointer(&key)); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return nil, fmt.Errorf("error getting next key: %w", err)
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

type kernelSymbol struct {
	addr uint64
	name string
}

// readKernelSymbols reads /proc/kallsyms and a slice of kernelSymbols.
func readKernelSymbols() ([]kernelSymbol, error) {
	symbols := []kernelSymbol{}

	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		addr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil {
			return nil, err
		}

		// The kernel function is the third field in /proc/kallsyms line:
		// 0000000000000000 t acpi_video_unregister_backlight      [video]
		// First is the symbol address and second is described in man nm.
		symbols = append(symbols, kernelSymbol{
			addr: addr,
			name: fields[2],
		})
	}

	err = scanner.Err()
	if err != nil {
		return nil, err
	}

	return symbols, nil
}

// findKernelSymbol tries to find the kernel symbol corresponding to the given
// instruction pointer.
// For example, if instruction pointer is 0x1004 and there is a symbol which
// address is 0x1000, this function will return the name of this symbol.
// If no symbol is found, it returns "[unknown]".
func findKernelSymbol(kAllSyms []kernelSymbol, ip uint64) string {
	// Go translation of iovisor/bcc ksyms__map_addr():
	// https://github.com/iovisor/bcc/blob/c65446b765c9f7df7e357ee9343192de8419234a/libbpf-tools/trace_helpers.c#L149
	end := len(kAllSyms) - 1
	var addr uint64
	start := 0

	for start < end {
		mid := start + (end-start+1)/2

		addr = kAllSyms[mid].addr

		if addr <= ip {
			start = mid
		} else {
			end = mid - 1
		}
	}

	if start == end && kAllSyms[start].addr <= addr {
		return kAllSyms[start].name
	}

	return "[unknown]"
}

func getReport(t *Tracer, kAllSyms []kernelSymbol, stack *ebpf.Map, keyCount keyCount) (types.Report, error) {
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

		kernelSymbols = append(kernelSymbols, findKernelSymbol(kAllSyms, ip))
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
	reports := []types.Report{}

	defer func() {
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
	}()

	keysCounts, err := t.readCountsMap()
	if err != nil {
		return "", err
	}

	sort.Slice(keysCounts, func(i, j int) bool {
		if keysCounts[i].value > keysCounts[j].value {
			return false
		}
		return keysCounts[i].value != keysCounts[j].value
	})

	kAllSyms, err := readKernelSymbols()
	if err != nil {
		return "", err
	}

	for _, keyVal := range keysCounts {
		report, err := getReport(t, kAllSyms, t.objs.profileMaps.Stackmap, keyVal)
		if err != nil {
			return "", err
		}

		reports = append(reports, report)
	}

	output, err := json.Marshal(reports)

	return string(output), err
}

func (t *Tracer) start() error {
	spec, err := loadProfile()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if t.config.MountnsMap != nil {
		filterByMntNs = true
		mapReplacements["mount_ns_filter"] = t.config.MountnsMap
	}

	consts := map[string]interface{}{
		"kernel_stacks_only": t.config.KernelStackOnly,
		"user_stacks_only":   t.config.UserStackOnly,
		"filter_by_mnt_ns":   filterByMntNs,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("error RewriteConstants: %w", err)
	}

	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}

	if err := spec.LoadAndAssign(&t.objs, &opts); err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
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
			return fmt.Errorf("failed to create the perf fd: %w", err)
		}

		t.perfFds = append(t.perfFds, fd)

		// Attach program to perf event.
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, t.objs.IgProfCpu.FD()); err != nil {
			return fmt.Errorf("failed to attach eBPF program to perf fd: %w", err)
		}

		// Start perf event.
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			return fmt.Errorf("failed to enable perf fd: %w", err)
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

func (t *TracerWrap) Start() error {
	if err := t.start(); err != nil {
		t.Stop()
		return err
	}
	return nil
}

func (t *TracerWrap) Stop() {
	// TODO: Error handling on stop?
	res, _ := t.Tracer.Stop()
	var reports []*types.Report
	json.Unmarshal([]byte(res), &reports)
	for _, report := range reports {
		t.eventCallback(report)
	}
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
	t.Tracer.enricher = t
}

func (t *TracerWrap) EnrichByMntNs(event *eventtypes.CommonData, mountnsid uint64) {
	// TODO: This is ugly as it temporarily wraps and unwraps the event; should be changed in the original gadget code
	//  after full migration to NewInstance()
	wrap := &types.Report{CommonData: *event, MntnsID: mountnsid}
	t.enricherFunc(wrap)
	*event = wrap.CommonData
}

func (t *TracerWrap) SetMountNsMap(mountNsMap *ebpf.Map) {
	t.Tracer.config.MountnsMap = mountNsMap
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &TracerWrap{
		Tracer: Tracer{
			config: &Config{},
		},
	}
	return tracer, nil
}

func (t *Tracer) Init(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	t.config.UserStackOnly = params.Get(ParamUserStack).AsBool()
	t.config.KernelStackOnly = params.Get(ParamKernelStack).AsBool()
	return nil
}
