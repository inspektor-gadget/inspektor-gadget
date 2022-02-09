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

package main

import (
	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/bcck8s"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
)

var (
	profileKernel bool
	profileUser   bool
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Profile CPU usage by sampling stack traces",
	RunE:   func() func(*cobra.Command, []string) error {
		specificFlag := "-f -d "

		if profileUser {
			specificFlag += "-U "
		} else if profileKernel {
			specificFlag += "-K "
		}

		return bcck8s.BccCmd("profile", "/usr/share/bcc/tools/profile", &params, specificFlag)
	}(),
}

func init() {
	commands := []*cobra.Command{
		profileCmd,
	}

	// Add flags for all BCC gadgets
	for _, command := range commands {
		rootCmd.AddCommand(command)
		utils.AddCommonFlags(command, &params)
	}

	// Add flags specific to some BCC gadgets
	profileCmd.PersistentFlags().BoolVarP(
		&profileUser,
		"user",
		"U",
		false,
		"Show stacks from user space only (no kernel space stacks)",
	)
	profileCmd.PersistentFlags().BoolVarP(
		&profileKernel,
		"kernel",
		"K",
		false,
		"Show stacks from kernel space only (no user space stacks)",
	)
}
