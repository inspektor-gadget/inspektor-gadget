// Copyright 2012-2017 Docker, Inc.
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

// This file is derived from github.com/moby/moby/pkg/parsers/kernel
// (https://github.com/moby/moby/blob/v28.1.1/pkg/parsers/kernel/kernel.go)
// and has been modified for use in Inspektor Gadget.

// Package kernel provides helper functions to get, parse and compare kernel
// versions.
package kernel

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// VersionInfo holds information about the kernel.
type VersionInfo struct {
	Kernel int    // Version of the kernel (e.g. 4.1.2-generic -> 4)
	Major  int    // Major part of the kernel version (e.g. 4.1.2-generic -> 1)
	Minor  int    // Minor part of the kernel version (e.g. 4.1.2-generic -> 2)
	Flavor string // Flavor of the kernel version (e.g. 4.1.2-generic -> generic)
}

func (k *VersionInfo) String() string {
	return fmt.Sprintf("%d.%d.%d%s", k.Kernel, k.Major, k.Minor, k.Flavor)
}

// CompareKernelVersion compares two kernel.VersionInfo structs.
// Returns -1 if a < b, 0 if a == b, 1 if a > b
func CompareKernelVersion(a, b VersionInfo) int {
	if a.Kernel < b.Kernel {
		return -1
	} else if a.Kernel > b.Kernel {
		return 1
	}
	if a.Major < b.Major {
		return -1
	} else if a.Major > b.Major {
		return 1
	}
	if a.Minor < b.Minor {
		return -1
	} else if a.Minor > b.Minor {
		return 1
	}
	return 0
}

// ParseRelease parses a string and creates a VersionInfo based on it.
func ParseRelease(release string) (*VersionInfo, error) {
	var (
		kernelVer, major, minor, parsed int
		flavor, partial                 string
	)

	parsed, _ = fmt.Sscanf(release, "%d.%d%s", &kernelVer, &major, &partial)
	if parsed < 2 {
		return nil, errors.New("Can't parse kernel version " + release)
	}

	parsed, _ = fmt.Sscanf(partial, ".%d%s", &minor, &flavor)
	if parsed < 1 {
		flavor = partial
	}

	return &VersionInfo{
		Kernel: kernelVer,
		Major:  major,
		Minor:  minor,
		Flavor: flavor,
	}, nil
}

// GetKernelVersion gets the current kernel version.
func GetKernelVersion() (*VersionInfo, error) {
	uts := &unix.Utsname{}
	if err := unix.Uname(uts); err != nil {
		return nil, err
	}
	return ParseRelease(unix.ByteSliceToString(uts.Release[:]))
}
