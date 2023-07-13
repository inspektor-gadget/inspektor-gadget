//go:build linux
// +build linux

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

	"github.com/spf13/cobra"
)

var (
	HostRoot   string
	HostProcFs string
)

func init() {
	// Initialize HostRoot and HostProcFs
	HostRoot = os.Getenv("HOST_ROOT")
	if HostRoot == "" {
		HostRoot = "/"
	}
	HostProcFs = filepath.Join(HostRoot, "/proc")
}

type Config struct {
	// AutoMountFilesystems will automatically mount bpffs, debugfs and
	// tracefs if they are not already mounted.
	//
	// This is useful for some environments where those filesystems are not
	// mounted by default on the host, such as:
	// - minikube with the Docker driver
	// - Docker Desktop with WSL2
	// - Talos Linux
	AutoMountFilesystems bool
}

var (
	autoSdUnitRestartFlag    bool
	autoMountFilesystemsFlag bool
	autoWSLWorkaroundFlag    bool

	initDone bool
)

func Init(config Config) error {
	var err error

	// Init() is called both from the local runtime and the local manager operator.
	// Different gadgets (trace-exec and top-ebpf) have different code paths, and we need both to make both work.
	// TODO: understand why we need to call Init() twice and fix it.
	if initDone {
		return nil
	}

	// Apply systemd workaround first because it might start a new process and
	// exit before the other workarounds.
	if autoSdUnitRestartFlag {
		exit, err := autoSdUnitRestart()
		if exit {
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
		if err != nil {
			return err
		}
	} else {
		if err := suggestSdUnitRestart(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}

	// The mount workaround could either be applied unconditionally (in the
	// gadget DaemonSet) or with the flag (in ig).
	if config.AutoMountFilesystems || autoMountFilesystemsFlag {
		_, err = autoMountFilesystems(false)
		if err != nil {
			return err
		}
	} else {
		mountsSuggested, err := autoMountFilesystems(true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if len(mountsSuggested) != 0 {
			fmt.Fprintf(os.Stderr, "error: filesystems %s not mounted (did you try --auto-mount-filesystems?)\n", strings.Join(mountsSuggested, ", "))
			os.Exit(1)
		}
	}

	// The WSL workaround is applied with the flag (in ig).
	if autoWSLWorkaroundFlag {
		err = autoWSLWorkaround()
		if err != nil {
			return err
		}
	} else {
		err = suggestWSLWorkaround()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}

	initDone = true
	return nil
}

// AddFlags adds CLI flags for various workarounds
func AddFlags(command *cobra.Command) {
	command.PersistentFlags().BoolVarP(
		&autoSdUnitRestartFlag,
		"auto-sd-unit-restart",
		"",
		false,
		"Automatically run in a privileged systemd unit if lacking enough capabilities",
	)
	command.PersistentFlags().BoolVarP(
		&autoMountFilesystemsFlag,
		"auto-mount-filesystems",
		"",
		false,
		"Automatically mount bpffs, debugfs and tracefs if they are not already mounted",
	)
	command.PersistentFlags().BoolVarP(
		&autoWSLWorkaroundFlag,
		"auto-wsl-workaround",
		"",
		false,
		"Automatically find the host procfs when running in WSL2",
	)
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
