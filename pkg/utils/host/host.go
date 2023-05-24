// Copyright 2023 The Inspektor Gadget authors
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

// Package host provides ways to access the host filesystem.
//
// Inspektor Gadget can run either in the host or in a container. When running
// in a container, the host filesystem must be available in a specific
// directory.
package host

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	HostRoot   string
	HostProcFs string
)

func init() {
	HostRoot = os.Getenv("HOST_ROOT")
	if HostRoot == "" {
		HostRoot = "/"
	}
	HostProcFs = filepath.Join(HostRoot, "/proc")
}

func GetProcComm(pid int) string {
	pidStr := fmt.Sprint(pid)
	commBytes, _ := os.ReadFile(filepath.Join(HostProcFs, pidStr, "comm"))
	return strings.TrimRight(string(commBytes), "\n")
}

func GetProcCmdline(pid int) []string {
	pidStr := fmt.Sprint(pid)
	cmdlineBytes, _ := os.ReadFile(filepath.Join(HostProcFs, pidStr, "cmdline"))
	return strings.Split(string(cmdlineBytes), "\x00")
}
