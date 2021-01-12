// +build linux
// +build cgo

package seccomp

import (
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"time"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/seccomp/types"
	"github.com/opencontainers/runtime-spec/specs-go"
	libseccomp "github.com/seccomp/libseccomp-golang"
)

type SeccompAdvisor struct {
	nodeName    string
	bpfModule   *bpf.Module
	syscallsMap *bpf.BPFMap

	started bool
	ticker  *time.Ticker
	done    chan bool

	// containers by mntns
	containers        map[uint64]*types.Container
	stoppedContainers []*types.Container
}

/* Keep in sync with constants in pkg/gadgets/seccomp/tracepoint-bpf-asset.c
 */
const (
	SyscallsCount              = 500
	SyscallsMapValueFooterSize = 1
	SyscallsMapValueSize       = SyscallsCount + SyscallsMapValueFooterSize
)

func NewAdvisor(nodeName string) (*SeccompAdvisor, error) {
	return &SeccompAdvisor{
		nodeName:   nodeName,
		containers: make(map[uint64]*types.Container),
		done:       make(chan bool),
	}, nil
}

func (sa *SeccompAdvisor) Start() error {
	buf, err := Asset("tracepoint-bpf-asset.o")
	if err != nil {
		return fmt.Errorf("couldn't find asset: %s", err)
	}

	bpfModule, err := bpf.NewModuleFromBuffer(buf, "tracepoint-bpf-asset.o")
	if err != nil {
		return err
	}

	err = bpfModule.BPFLoadObject()
	if err != nil {
		return err
	}

	syscallsMap, _ := bpfModule.GetMap("syscalls_per_mntns")
	blank := make([]byte, SyscallsMapValueSize)
	err = syscallsMap.Update(uint64(0), blank)
	if err != nil {
		return err
	}

	prog, err := bpfModule.GetProgram("tracepoint__raw_syscalls__sys_enter")
	if err != nil {
		return err
	}
	_, err = prog.AttachRawTracepoint("sys_enter")
	if err != nil {
		return err
	}

	sa.bpfModule = bpfModule
	sa.syscallsMap = syscallsMap

	sa.started = true

	sa.ticker = time.NewTicker(1 * time.Second)
	go func() {
		for {
			select {
			case <-sa.done:
				return
			case <-sa.ticker.C:
				sa.update()
			}
		}
	}()

	return nil
}

func (sa *SeccompAdvisor) Stop() {
	if !sa.started {
		return
	}

	sa.ticker.Stop()
	sa.done <- true

	sa.stoppedContainers = nil
	sa.bpfModule.Close()
	sa.syscallsMap = nil
	sa.bpfModule = nil
	sa.started = false
}

func (sa *SeccompAdvisor) update() {
	if !sa.started {
		return
	}
	for _, c := range sa.containers {
		v, err := sa.syscallsMap.Lookup(c.Mntns, SyscallsMapValueSize)
		if err == nil {
			c.SeccompPolicy = syscallArrToLinuxSeccomp(v)
		}
	}
}

func (sa *SeccompAdvisor) AddContainer(mntns uint64, namespace, podname, containerName string) {
	sa.containers[mntns] = &types.Container{
		Mntns:         mntns,
		Namespace:     namespace,
		Podname:       podname,
		ContainerName: containerName,
	}
}

func (sa *SeccompAdvisor) RemoveContainer(mntns uint64, namespace, podname, containerName string) {
	if sa.started {
		c := sa.containers[mntns]
		v, err := sa.syscallsMap.Lookup(c.Mntns, SyscallsMapValueSize)
		if err == nil {
			c.SeccompPolicy = syscallArrToLinuxSeccomp(v)
		}
		err = sa.syscallsMap.Delete(c.Mntns)

		sa.stoppedContainers = append(sa.stoppedContainers, c)
	}
	delete(sa.containers, mntns)
}

/* Function arches() under the Apache License, Version 2.0 by the containerd authors:
 * https://github.com/containerd/containerd/blob/66fec3bbbf91520a1433faa16e99e5a314a61902/contrib/seccomp/seccomp_default.go#L29
 */
func arches() []specs.Arch {
	switch runtime.GOARCH {
	case "amd64":
		return []specs.Arch{specs.ArchX86_64, specs.ArchX86, specs.ArchX32}
	case "arm64":
		return []specs.Arch{specs.ArchARM, specs.ArchAARCH64}
	case "mips64":
		return []specs.Arch{specs.ArchMIPS, specs.ArchMIPS64, specs.ArchMIPS64N32}
	case "mips64n32":
		return []specs.Arch{specs.ArchMIPS, specs.ArchMIPS64, specs.ArchMIPS64N32}
	case "mipsel64":
		return []specs.Arch{specs.ArchMIPSEL, specs.ArchMIPSEL64, specs.ArchMIPSEL64N32}
	case "mipsel64n32":
		return []specs.Arch{specs.ArchMIPSEL, specs.ArchMIPSEL64, specs.ArchMIPSEL64N32}
	case "s390x":
		return []specs.Arch{specs.ArchS390, specs.ArchS390X}
	default:
		return []specs.Arch{}
	}
}

func syscallArrToLinuxSeccomp(v []byte) *specs.LinuxSeccomp {
	names := []string{}
	for i, val := range v[:SyscallsCount] {
		if val == 0 {
			continue
		}
		call1 := libseccomp.ScmpSyscall(i)
		name, err := call1.GetName()
		if err != nil {
			name = fmt.Sprintf("syscall%d", i)
		}
		names = append(names, name)
	}
	sort.Strings(names)

	syscalls := []specs.LinuxSyscall{
		{
			Names:  names,
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{},
		},
	}

	s := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: arches(),
		Syscalls:      syscalls,
	}
	return s
}

func (sa *SeccompAdvisor) Query() (out string) {
	resp := &types.SeccompAdvisorQueryResponse{
		Node: sa.nodeName,
	}
	for _, c := range sa.containers {
		resp.Containers = append(resp.Containers, *c)
	}
	for _, c := range sa.stoppedContainers {
		resp.Containers = append(resp.Containers, *c)
	}
	b, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": "%s"}`, err)
	}
	return string(b)
}

func (sa *SeccompAdvisor) Dump() (out string) {
	if !sa.started {
		return
	}
	out += "Seccomp advisor: running containers:\n"
	for _, c := range sa.containers {
		out += fmt.Sprintf("%s\n", c.Dump())
	}
	out += "Seccomp advisor: stopped containers:\n"
	for _, c := range sa.stoppedContainers {
		out += fmt.Sprintf("%s\n", c.Dump())
	}
	return
}
