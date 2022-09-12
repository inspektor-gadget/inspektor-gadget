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

type SignalFlags struct {
	Pid    uint64
	Sig    string
	Failed bool
}

func NewSignalCmd(runCmd func(*cobra.Command, []string) error, flags *SignalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signal",
		Short: "Trace signals received by processes",
		RunE:  runCmd,
	}

	cmd.PersistentFlags().Uint64VarP(
		&flags.Pid,
		"pid",
		"",
		0,
		"Show only signal sent by this particular PID",
	)
	cmd.PersistentFlags().StringVarP(
		&flags.Sig,
		"signal",
		"",
		"",
		`Trace only this signal (it can be an int like 9 or string beginning with "SIG" like "SIGKILL")`,
	)
	cmd.PersistentFlags().BoolVarP(
		&flags.Failed,
		"failed-only",
		"f",
		false,
		`Show only events where the syscall sending a signal failed`,
	)

	return cmd
}
