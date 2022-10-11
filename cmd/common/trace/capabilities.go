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

package trace

import (
	"github.com/spf13/cobra"
)

type CapabilitiesFlags struct {
	AuditOnly bool
	Unique    bool
}

func NewCapabilitiesCmd(runCmd func(*cobra.Command, []string) error, flags *CapabilitiesFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "capabilities",
		Short: "Trace security capability checks",
		RunE:  runCmd,
	}

	cmd.PersistentFlags().BoolVarP(
		&flags.AuditOnly,
		"audit-only",
		"",
		true,
		"Only show audit checks",
	)

	cmd.PersistentFlags().BoolVarP(
		&flags.Unique,
		"unique",
		"",
		false,
		"Only show a capability once on the same container",
	)

	return cmd
}
