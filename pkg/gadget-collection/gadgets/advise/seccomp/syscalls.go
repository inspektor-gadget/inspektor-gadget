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

package seccomp

import (
	commonseccomp "github.com/containers/common/pkg/seccomp"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/advise/seccomp/tracer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
)

func syscallNamesToSeccompPolicy(profileName *SeccompProfileNsName, syscallNames []string) *seccompprofile.SeccompProfile {
	syscalls := []*seccompprofile.Syscall{
		{
			Names:  syscallNames,
			Action: commonseccomp.ActAllow,
			Args:   []*seccompprofile.Arg{},
		},
	}

	ret := seccompprofile.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   profileName.namespace,
			Annotations: map[string]string{},
			Labels:      map[string]string{},
		},
		Spec: seccompprofile.SeccompProfileSpec{
			BaseProfileName: "",
			DefaultAction:   commonseccomp.ActErrno,
			Architectures:   nil,
			Syscalls:        syscalls,
		},
	}

	if profileName.generateName {
		ret.ObjectMeta.GenerateName = profileName.name + "-"
	} else {
		ret.ObjectMeta.Name = profileName.name
	}

	for _, a := range tracer.Arches() {
		arch := seccompprofile.Arch(a)
		ret.Spec.Architectures = append(ret.Spec.Architectures, arch)
	}

	return &ret
}
