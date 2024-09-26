// Copyright 2024 The Inspektor Gadget authors
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
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/uprobetracer"
)

const (
	kprobePrefix    = "kprobe/"
	kretprobePrefix = "kretprobe/"
	iterPrefix      = "iter/"
	fentryPrefix    = "fentry/"
	fexitPrefix     = "fexit/"
	tpBtfPrefix     = "tp_btf/"
	uprobePrefix    = "uprobe/"
	uretprobePrefix = "uretprobe/"
	usdtPrefix      = "usdt/"
)

const (
	disabledProgram = "gadget_program_disabled"
)

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
	default:
		return nil, fmt.Errorf("unsupported program %q of type %q", p.Name, p.Type)
	}
}
