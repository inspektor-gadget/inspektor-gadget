// Copyright 2022 The Inspektor Gadget authors
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

package profile

import (
	"github.com/spf13/cobra"
)

type CPUFlags struct {
	ProfileKernelOnly bool
	ProfileUserOnly   bool
}

func NewCPUCmd(runCmd func(*cobra.Command, []string) error, flags *CPUFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "cpu",
		Short:        "Analyze CPU performance by sampling stack traces",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE:         runCmd,
	}

	cmd.PersistentFlags().BoolVarP(
		&flags.ProfileUserOnly,
		"user-stack",
		"U",
		false,
		"Show stacks from user space only (no kernel space stacks)",
	)
	cmd.PersistentFlags().BoolVarP(
		&flags.ProfileKernelOnly,
		"kernel-stack",
		"K",
		false,
		"Show stacks from kernel space only (no user space stacks)",
	)

	return cmd
}
