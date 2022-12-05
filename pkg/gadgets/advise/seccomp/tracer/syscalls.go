//go:build !docs
// +build !docs

// Copyright 2019-2021 The Inspektor Gadget authors
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

package tracer

import (
	"runtime"

	"github.com/opencontainers/runtime-spec/specs-go"
)

/* Function arches() under the Apache License, Version 2.0 by the containerd authors:
 * https://github.com/containerd/containerd/blob/66fec3bbbf91520a1433faa16e99e5a314a61902/contrib/seccomp/seccomp_default.go#L29
 */
func Arches() []specs.Arch {
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

func SyscallNamesToLinuxSeccomp(syscallNames []string) *specs.LinuxSeccomp {
	syscalls := []specs.LinuxSyscall{
		{
			Names:  syscallNames,
			Action: specs.ActAllow,
			Args:   []specs.LinuxSeccompArg{},
		},
	}

	s := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: Arches(),
		Syscalls:      syscalls,
	}
	return s
}
