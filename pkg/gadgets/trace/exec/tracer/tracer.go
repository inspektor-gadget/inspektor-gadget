// Copyright 2019-2024 The Inspektor Gadget authors
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
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfhelpers"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	ebpfutils "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} -type event execsnoop ./bpf/execsnoop.bpf.c -- -DWITH_LONG_PATHS  -I./bpf/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} -type event execsnoopWithLongPaths ./bpf/execsnoop.bpf.c -- -DWITH_LONG_PATHS -I./bpf/

// needs to be kept in sync with execsnoopEvent from execsnoop_bpfel.go without the Args field
type execsnoopEventAbbrev struct {
	MntnsId     uint64
	Timestamp   uint64
	Pid         uint32
	Tid         uint32
	Ptid        uint32
	Ppid        uint32
	Uid         uint32
	Gid         uint32
	Loginuid    uint32
	Sessionid   uint32
	Retval      int32
	ArgsCount   int32
	UpperLayer  bool
	PupperLayer bool
	_           [2]byte
	ArgsSize    uint32
	Comm        [16]uint8
	Pcomm       [16]uint8
}

type Config struct {
	MountnsMap   *ebpf.Map
	GetPaths     bool
	IgnoreErrors bool
	FieldsSize   uint32
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)

	objs          execsnoopObjects
	enterLink     link.Link
	enterAtLink   link.Link
	schedExecLink link.Link
	exitLink      link.Link
	exitAtLink    link.Link
	securityLink  link.Link
	reader        *perf.Reader

	cwdOffset           uint32
	exepathOffset       uint32
	fileOffset          uint32
	parentExePathOffset uint32
}

func NewTracer(config *Config, enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*types.Event),
) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		enricher:      enricher,
		eventCallback: eventCallback,
	}

	if err := t.install(); err != nil {
		t.close()
		return nil, err
	}

	go t.run()

	return t, nil
}

// Stop stops the tracer
// TODO: Remove after refactoring
func (t *Tracer) Stop() {
	t.close()
}

func (t *Tracer) close() {
	t.enterLink = gadgets.CloseLink(t.enterLink)
	t.enterAtLink = gadgets.CloseLink(t.enterAtLink)
	t.schedExecLink = gadgets.CloseLink(t.schedExecLink)
	t.exitLink = gadgets.CloseLink(t.exitLink)
	t.exitAtLink = gadgets.CloseLink(t.exitAtLink)
	t.securityLink = gadgets.CloseLink(t.securityLink)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) generateTypes(spec *ebpf.CollectionSpec) ([]btf.Type, *btf.Struct, error) {
	size := t.config.FieldsSize
	const structName = "event"

	uint32T := btfhelpers.BtfInt(4, btf.Unsigned)
	charT := btfhelpers.BtfInt(1, btf.Char)

	types := []btf.Type{uint32T, charT}

	// Look for the sockets_val btf structure to fill fixed members
	srcBtfStruct := &btf.Struct{}
	if err := spec.Types.TypeByName(structName, &srcBtfStruct); err != nil {
		return nil, nil, fmt.Errorf("getting BTF struct %q: %w", structName, err)
	}

	members := []btf.Member{}
	currentOffset := uint32(0)
	for _, member := range srcBtfStruct.Members {
		// stop when we find the first optional field, cwd.
		if member.Name == "cwd" {
			currentOffset = member.Offset.Bytes()
			break
		}
		members = append(members, member)
	}

	addMember := func(name string, size uint32, typ btf.Type) {
		member := btf.Member{
			Name:   name,
			Type:   typ,
			Offset: btf.Bits(currentOffset * 8),
		}
		members = append(members, member)
		types = append(types, typ)
		currentOffset += size
	}

	cwdTyp := btfhelpers.BtfArray(uint32T, charT, size)
	t.cwdOffset = currentOffset
	addMember("cwd", size, cwdTyp)

	exepathTyp := btfhelpers.BtfArray(uint32T, charT, size)
	t.exepathOffset = currentOffset
	addMember("exepath", size, exepathTyp)

	fileTyp := btfhelpers.BtfArray(uint32T, charT, size)
	t.fileOffset = currentOffset
	addMember("file", size, fileTyp)

	parentExePath := btfhelpers.BtfArray(uint32T, charT, size)
	t.parentExePathOffset = currentOffset
	addMember("parent_exepath", size, parentExePath)

	//args := btfhelpers.BtfArray(uint32T, charT, 20*256)
	//addMember("args", 20*256, args)

	for _, member := range srcBtfStruct.Members {
		if member.Name == "args" {
			member.Offset = btf.Bits(currentOffset * 8)
			members = append(members, member)
			// TODO: how to get this from btf?
			currentOffset += 20 * 256
			break
		}
	}

	btfStruct := &btf.Struct{
		Name:    structName,
		Size:    currentOffset,
		Members: members,
	}
	types = append(types, btfStruct)

	return types, btfStruct, nil
}

func (t *Tracer) install() error {
	var spec *ebpf.CollectionSpec
	var err error

	if t.config.GetPaths {
		spec, err = loadExecsnoopWithLongPaths()
	} else {
		spec, err = loadExecsnoop()
	}
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	/* change spec here */
	types, btfStruct, err := t.generateTypes(spec)
	if err != nil {
		return fmt.Errorf("generating BTF types: %w", err)
	}

	kernelSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("loading kernel BTF spec: %w", err)
	}

	mergedBtf, err := btfhelpers.AppendTypesToSpec(kernelSpec, types)
	if err != nil {
		return fmt.Errorf("merging BTF specs: %w", err)
	}

	execsMap := spec.Maps["execs"]

	execsMap.ValueSize = btfStruct.Size
	execsMap.Value = btfStruct

	/*****/

	consts := map[string]interface{}{
		"ignore_failed": t.config.IgnoreErrors,
	}

	gadgets.FixBpfKtimeGetBootNs(spec.Programs)
	filterByMntNs := true
	consts[gadgets.FilterByMntNsName] = filterByMntNs

	if err := ebpfutils.SpecSetVars(spec, consts); err != nil {
		return err
	}

	opts := ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			gadgets.MntNsFilterMapName: t.config.MountnsMap,
		},
		Programs: ebpf.ProgramOptions{
			KernelTypes: mergedBtf,
		},
	}

	if err := spec.LoadAndAssign(&t.objs, &opts); err != nil {
		return fmt.Errorf("loading maps and programs: %w", err)
	}

	t.enterLink, err = link.Tracepoint("syscalls", "sys_enter_execve", t.objs.IgExecveE, nil)
	if err != nil {
		return fmt.Errorf("attaching enter tracepoint: %w", err)
	}
	t.enterAtLink, err = link.Tracepoint("syscalls", "sys_enter_execveat", t.objs.IgExecveatE, nil)
	if err != nil {
		return fmt.Errorf("attaching enter tracepoint: %w", err)
	}

	t.schedExecLink, err = link.Tracepoint("sched", "sched_process_exec", t.objs.IgSchedExec, nil)
	if err != nil {
		return fmt.Errorf("attaching sched_process_exec tracepoint: %w", err)
	}

	t.exitLink, err = link.Tracepoint("syscalls", "sys_exit_execve", t.objs.IgExecveX, nil)
	if err != nil {
		return fmt.Errorf("attaching exit tracepoint: %w", err)
	}
	t.exitAtLink, err = link.Tracepoint("syscalls", "sys_exit_execveat", t.objs.IgExecveatX, nil)
	if err != nil {
		return fmt.Errorf("attaching exit tracepoint: %w", err)
	}

	t.securityLink, err = link.Kprobe("security_bprm_check", t.objs.SecurityBprmCheck, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe security_bprm_check: %w", err)
	}

	reader, err := perf.NewReader(t.objs.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("creating perf ring buffer: %w", err)
	}
	t.reader = reader

	if err := gadgets.FreezeMaps(t.objs.Events); err != nil {
		return err
	}

	return nil
}

func (t *Tracer) run() {
	for {
		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				// nothing to do, we're done
				return
			}

			msg := fmt.Sprintf("reading perf ring buffer: %s", err)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		// this works regardless the kind of event because cwd is defined at the end of the
		// structure. (Just before args that are handled in a different way below)
		bpfEvent := (*execsnoopEventAbbrev)(unsafe.Pointer(&record.RawSample[0]))

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			},
			Pid:           bpfEvent.Pid,
			Tid:           bpfEvent.Tid,
			Ppid:          bpfEvent.Ppid,
			Ptid:          bpfEvent.Ptid,
			Uid:           bpfEvent.Uid,
			Gid:           bpfEvent.Gid,
			LoginUid:      bpfEvent.Loginuid,
			SessionId:     bpfEvent.Sessionid,
			UpperLayer:    bpfEvent.UpperLayer,
			PupperLayer:   bpfEvent.PupperLayer,
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
			Retval:        int(bpfEvent.Retval),
			Comm:          gadgets.FromCString(bpfEvent.Comm[:]),
			Pcomm:         gadgets.FromCString(bpfEvent.Pcomm[:]),
		}

		//argsCount := 0
		//buf := []byte{}
		//args := record.RawSample[unsafe.Offsetof(execsnoopEvent{}.Args):]

		if t.config.GetPaths {
			l := uint32(len(record.RawSample))
			cwdFinal := t.cwdOffset + t.config.FieldsSize
			if l < cwdFinal {
				cwdFinal = l
			}
			exePathFinal := t.exepathOffset + t.config.FieldsSize
			if l < exePathFinal {
				exePathFinal = l
			}
			fileFinal := t.fileOffset + t.config.FieldsSize
			if l < fileFinal {
				fileFinal = l
			}
			parentExePathFinal := t.parentExePathOffset + t.config.FieldsSize
			if l < parentExePathFinal {
				parentExePathFinal = l
			}

			event.Cwd = gadgets.FromCString(record.RawSample[t.cwdOffset:cwdFinal])
			event.ExePath = gadgets.FromCString(record.RawSample[t.exepathOffset:exePathFinal])
			event.File = gadgets.FromCString(record.RawSample[t.fileOffset:fileFinal])
			event.ParentExePath = gadgets.FromCString(record.RawSample[t.parentExePathOffset:parentExePathFinal])
		}

		//for i := 0; i < int(bpfEvent.ArgsSize) && argsCount < int(bpfEvent.ArgsCount); i++ {
		//	c := args[i]
		//	if c == 0 {
		//		event.Args = append(event.Args, string(buf))
		//		argsCount = 0
		//		buf = []byte{}
		//	} else {
		//		buf = append(buf, c)
		//	}
		//}

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		}

		t.eventCallback(&event)
	}
}

// --- Registry changes

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	t.config.GetPaths = gadgetCtx.GadgetParams().Get(ParamPaths).AsBool()
	t.config.IgnoreErrors = gadgetCtx.GadgetParams().Get(ParamIgnoreErrors).AsBool()
	t.config.FieldsSize = gadgetCtx.GadgetParams().Get(ParamFieldsSize).AsUint32()

	defer t.close()
	if err := t.install(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

	go t.run()
	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	return nil
}

func (t *Tracer) SetMountNsMap(mountnsMap *ebpf.Map) {
	t.config.MountnsMap = mountnsMap
}

func (t *Tracer) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *types.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config: &Config{},
	}
	return tracer, nil
}
