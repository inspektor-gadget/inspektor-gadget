// Copyright 2024-2025 The Inspektor Gadget authors
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
	"net"
	"runtime"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/cgroups"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/uprobetracer"
)

const (
	kprobePrefix    = "kprobe/"
	kretprobePrefix = "kretprobe/"
	iterPrefix      = "iter/"
	fentryPrefix    = "fentry/"
	fexitPrefix     = "fexit/"
	perfEventPrefix = "perf_event/"
	tpBtfPrefix     = "tp_btf/"
	uprobePrefix    = "uprobe/"
	uretprobePrefix = "uretprobe/"
	usdtPrefix      = "usdt/"
)

const (
	disabledProgram = "gadget_program_disabled"

	// defaultSockhashMapName is the sockhash map an sk_skb program is attached
	// to when the gadget does not override it via
	// "programs.<name>.attach_to". It matches the map defined by the shared
	// <gadget/tcp_stream.h> header.
	defaultSockhashMapName = "gadget_sockhash"
)

// sockmapAttachment records an sk_skb program attached to a sockmap/sockhash
// map. sk_skb attachments are done via BPF_PROG_ATTACH and, unlike most other
// program types, are not backed by a bpf_link. We therefore keep track of the
// information needed to detach them explicitly on Stop() (mirroring how perf
// event fds are tracked).
type sockmapAttachment struct {
	prog       *ebpf.Program
	sockmap    *ebpf.Map
	attachType ebpf.AttachType
}

func (i *ebpfInstance) attachProgram(gadgetCtx operators.GadgetContext, p *ebpf.ProgramSpec, prog *ebpf.Program) (link.Link, error) {
	attachTo := p.AttachTo

	if attachToCfg := i.config.GetString("programs." + p.Name + ".attach_to"); attachToCfg != "" {
		i.logger.Debugf("Overriding attachTo with %q for program %q", attachToCfg, p.Name)
		attachTo = attachToCfg
	}

	if attachTo == disabledProgram {
		i.logger.Debugf("Skipping program %q as it is disabled", p.Name)
		return nil, nil
	}

	switch p.Type {
	case ebpf.Kprobe:
		switch {
		case strings.HasPrefix(p.SectionName, kprobePrefix):
			i.logger.Debugf("Attaching kprobe %q to %q", p.Name, attachTo)
			return link.Kprobe(attachTo, prog, nil)
		case strings.HasPrefix(p.SectionName, kretprobePrefix):
			i.logger.Debugf("Attaching kretprobe %q to %q", p.Name, attachTo)
			return link.Kretprobe(attachTo, prog, nil)
		case strings.HasPrefix(p.SectionName, uprobePrefix) ||
			strings.HasPrefix(p.SectionName, uretprobePrefix) ||
			strings.HasPrefix(p.SectionName, usdtPrefix):
			uprobeTracer := i.uprobeTracers[p.Name]
			switch strings.Split(p.SectionName, "/")[0] {
			case "uprobe":
				return nil, uprobeTracer.AttachProg(p.Name, uprobetracer.ProgUprobe, attachTo, prog)
			case "uretprobe":
				return nil, uprobeTracer.AttachProg(p.Name, uprobetracer.ProgUretprobe, attachTo, prog)
			case "usdt":
				return nil, uprobeTracer.AttachProg(p.Name, uprobetracer.ProgUSDT, attachTo, prog)
			}
		}
		return nil, fmt.Errorf("unsupported section name %q for program %q", p.SectionName, p.Name)
	case ebpf.TracePoint:
		i.logger.Debugf("Attaching tracepoint %q to %q", p.Name, attachTo)
		parts := strings.Split(attachTo, "/")
		return link.Tracepoint(parts[0], parts[1], prog, nil)
	case ebpf.SocketFilter:
		i.logger.Debugf("Attaching socket filter %q to %q", p.Name, attachTo)
		networkTracer := i.networkTracers[p.Name]
		return nil, networkTracer.AttachProg(prog)
	case ebpf.Tracing:
		switch {
		case strings.HasPrefix(p.SectionName, iterPrefix):
			i.logger.Debugf("Attaching iter %q to %q", p.Name, attachTo)
			switch attachTo {
			case "task", "task_file", "tcp", "udp", "ksym":
				return link.AttachIter(link.IterOptions{
					Program: prog,
				})
			}
			return nil, fmt.Errorf("unsupported iter type %q", attachTo)
		case strings.HasPrefix(p.SectionName, fentryPrefix):
			i.logger.Debugf("Attaching fentry %q to %q", p.Name, attachTo)
			return link.AttachTracing(link.TracingOptions{
				Program:    prog,
				AttachType: ebpf.AttachTraceFEntry,
			})
		case strings.HasPrefix(p.SectionName, fexitPrefix):
			i.logger.Debugf("Attaching fexit %q to %q", p.Name, attachTo)
			return link.AttachTracing(link.TracingOptions{
				Program:    prog,
				AttachType: ebpf.AttachTraceFExit,
			})
		case strings.HasPrefix(p.SectionName, tpBtfPrefix):
			i.logger.Debugf("Attaching tp_btf %q to %q", p.Name, p.AttachTo)
			return link.AttachTracing(link.TracingOptions{
				Program:    prog,
				AttachType: ebpf.AttachTraceRawTp,
			})
		}
		return nil, fmt.Errorf("unsupported section name %q for program %q as type ebpf.Tracing", p.SectionName, p.Name)
	case ebpf.RawTracepoint:
		i.logger.Debugf("Attaching raw tracepoint %q to %q", p.Name, attachTo)
		return link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    attachTo,
			Program: prog,
		})
	case ebpf.SchedCLS:
		handler := i.tcHandlers[p.Name]

		ifaceName := i.paramValues[ParamIface]
		if ifaceName != "" {
			iface, err := net.InterfaceByName(ifaceName)
			if err != nil {
				return nil, fmt.Errorf("getting interface %q: %w", ifaceName, err)
			}

			if err := handler.AttachIface(iface); err != nil {
				return nil, fmt.Errorf("attaching iface %q: %w", ifaceName, err)
			}
		}

		i.logger.Debugf("Attaching sched_cls %q", p.Name)
		return nil, handler.AttachProg(prog)
	case ebpf.LSM:
		i.logger.Debugf("Attaching LSM %q to %q", p.Name, attachTo)
		return link.AttachLSM(link.LSMOptions{
			Program: prog,
		})
	case ebpf.SockOps:
		// sock_ops programs are attached to a cgroup v2. By default we attach
		// to the cgroup v2 root so the program observes every socket on the
		// host; this can be overridden per-program via
		// "programs.<name>.cgroup". sock_ops is typically used to populate a
		// sockhash map (see <gadget/tcp_stream.h>) that sk_skb programs then
		// process.
		cgroupPath, err := i.sockOpsCgroupPath(p.Name)
		if err != nil {
			return nil, fmt.Errorf("resolving cgroup for sockops program %q: %w", p.Name, err)
		}
		i.logger.Debugf("Attaching sockops %q to cgroup %q", p.Name, cgroupPath)
		return link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  ebpf.AttachCGroupSockOps,
			Program: prog,
		})
	case ebpf.SkSKB, ebpf.SkMsg:
		// sk_skb (STREAM_PARSER / STREAM_VERDICT) and sk_msg (MSG_VERDICT)
		// programs are attached to a sockmap/sockhash map, not to a kernel
		// hook. sk_skb runs on the receive path of the sockets in the map,
		// sk_msg on their send path. The target map is named by
		// "programs.<name>.attach_to" and defaults to the sockhash defined by
		// <gadget/tcp_stream.h>. The attachment is done via BPF_PROG_ATTACH,
		// which is not backed by a bpf_link, so we record it for explicit
		// detachment on Stop().
		mapName := attachTo
		if mapName == "" {
			mapName = defaultSockhashMapName
		}
		sockmap, ok := i.collection.Maps[mapName]
		if !ok {
			return nil, fmt.Errorf("sockhash map %q not found for %s program %q", mapName, p.Type, p.Name)
		}
		i.logger.Debugf("Attaching %s %q to sockhash map %q", p.Type, p.Name, mapName)
		if err := link.RawAttachProgram(link.RawAttachProgramOptions{
			Target:  sockmap.FD(),
			Program: prog,
			Attach:  p.AttachType,
		}); err != nil {
			return nil, fmt.Errorf("attaching %s program %q to sockhash %q: %w", p.Type, p.Name, mapName, err)
		}
		i.sockmapAttachments = append(i.sockmapAttachments, sockmapAttachment{
			prog:       prog,
			sockmap:    sockmap,
			attachType: p.AttachType,
		})
		return nil, nil
	case ebpf.PerfEvent:
		perfType := uint32(unix.PERF_TYPE_SOFTWARE)
		perfConfig := uint64(unix.PERF_COUNT_SW_CPU_CLOCK)
		perfSampleType := uint64(unix.PERF_SAMPLE_RAW)
		frequency := uint64(0)
		name, ok := strings.CutPrefix(p.SectionName, perfEventPrefix)
		if !ok {
			return nil, fmt.Errorf("perf_event programs require a name")
		}

		switch tmp := i.config.GetString("programs." + name + ".perf.type"); tmp {
		case "":
			return nil, fmt.Errorf("perf.type not specified for program %q", name)
		case "software":
			perfType = unix.PERF_TYPE_SOFTWARE
		default:
			return nil, fmt.Errorf("unsupported perf.type %q", tmp)
		}
		switch tmp := i.config.GetString("programs." + name + ".perf.config"); tmp {
		case "":
			return nil, fmt.Errorf("perf.config not specified for program %q", name)
		case "count_sw_cpu_clock":
			perfConfig = unix.PERF_COUNT_SW_CPU_CLOCK
		default:
			return nil, fmt.Errorf("unsupported perf.config %q", tmp)
		}
		switch tmp := i.config.GetString("programs." + name + ".perf.sampleType"); tmp {
		case "":
			return nil, fmt.Errorf("perf.sampleType not specified for program %q", name)
		case "sample_raw":
			perfSampleType = unix.PERF_SAMPLE_RAW
		default:
			return nil, fmt.Errorf("unsupported perf.sampleType %q", tmp)
		}
		if tmpFrequency := i.config.GetString("programs." + name + ".sampler.frequency"); tmpFrequency != "" {
			var err error
			frequency, err = strconv.ParseUint(tmpFrequency, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parsing frequency %q for program %q: %w", tmpFrequency, name, err)
			}
		} else {
			return nil, fmt.Errorf("sampler.frequency not specified for program %q", name)
		}
		if frequency == 0 {
			return nil, fmt.Errorf("sampler.frequency is zero for program %q", name)
		}
		for cpu := 0; cpu < runtime.NumCPU(); cpu++ {
			fd, err := unix.PerfEventOpen(
				&unix.PerfEventAttr{
					Type:        perfType,
					Config:      perfConfig,
					Sample_type: perfSampleType,
					Sample:      frequency,
					Bits:        unix.PerfBitFreq,
				},
				-1,
				cpu,
				-1,
				unix.PERF_FLAG_FD_CLOEXEC,
			)
			if err != nil {
				return nil, fmt.Errorf("opening perf event: %w", err)
			}
			i.perfFds = append(i.perfFds, fd)

			// Attach program to perf event.
			if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, prog.FD()); err != nil {
				return nil, fmt.Errorf("attaching eBPF program to perf fd: %w", err)
			}

			// Start perf event.
			if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
				return nil, fmt.Errorf("enabling perf fd: %w", err)
			}
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported program %q of type %q", p.Name, p.Type)
	}
}

// sockOpsCgroupPath returns the cgroup v2 path a sock_ops program should be
// attached to. It defaults to the cgroup v2 root (so the program sees every
// socket on the host) and can be overridden per-program via the
// "programs.<name>.cgroup" configuration key.
func (i *ebpfInstance) sockOpsCgroupPath(progName string) (string, error) {
	if path := i.config.GetString("programs." + progName + ".cgroup"); path != "" {
		return path, nil
	}

	path, err := cgroups.CgroupPathV2AddMountpoint("/")
	if err != nil {
		return "", fmt.Errorf("resolving cgroup v2 root mountpoint: %w", err)
	}
	return path, nil
}
