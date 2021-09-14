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

package seccomp

import (
	"fmt"
	"runtime"
	"sort"

	commonseccomp "github.com/containers/common/pkg/seccomp"
	"github.com/opencontainers/runtime-spec/specs-go"
	libseccomp "github.com/seccomp/libseccomp-golang"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	seccompprofilev1alpha1 "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"
)

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

func syscallArrToNameList(v []byte) []string {
	names := []string{}
	for i, val := range v {
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
	return names
}

func syscallArrToLinuxSeccomp(v []byte) *specs.LinuxSeccomp {
	syscalls := []specs.LinuxSyscall{
		{
			Names:  syscallArrToNameList(v),
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

func syscallArrToSeccompPolicy(namespace, name string, v []byte) *seccompprofilev1alpha1.SeccompProfile {
	syscalls := []*seccompprofilev1alpha1.Syscall{
		{
			Names:  syscallArrToNameList(v),
			Action: commonseccomp.ActAllow,
			Args:   []*seccompprofilev1alpha1.Arg{},
		},
	}

	ret := seccompprofilev1alpha1.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: seccompprofilev1alpha1.SeccompProfileSpec{
			BaseProfileName: "",
			DefaultAction:   commonseccomp.ActErrno,
			Architectures:   nil,
			Syscalls:        syscalls,
		},
	}
	for _, a := range arches() {
		arch := seccompprofilev1alpha1.Arch(a)
		ret.Spec.Architectures = append(ret.Spec.Architectures, &arch)
	}

	return &ret
}
