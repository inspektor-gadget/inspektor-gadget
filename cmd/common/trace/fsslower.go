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
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/fsslower/types"
)

type FsSlowerFlags struct {
	MinLatency uint
	Filesystem string
}

func NewFsSlowerCmd(runCmd func(*cobra.Command, []string) error, flags *FsSlowerFlags) *cobra.Command {
	validFsSlowerFilesystems := []string{"btrfs", "ext4", "nfs", "xfs"}

	cmd := &cobra.Command{
		Use:   "fsslower",
		Short: "Trace open, read, write and fsync operations slower than a threshold",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if flags.Filesystem == "" {
				return commonutils.WrapInErrMissingArgs("--filesystem / -f")
			}

			found := false
			for _, val := range validFsSlowerFilesystems {
				if flags.Filesystem == val {
					found = true
					break
				}
			}

			if !found {
				return commonutils.WrapInErrInvalidArg("--filesystem / -f",
					fmt.Errorf("%q is not a valid filesystem", flags.Filesystem))
			}

			return nil
		},
		RunE: runCmd,
	}

	cmd.Flags().UintVarP(
		&flags.MinLatency, "min", "m", types.MinLatencyDefault,
		"Min latency to trace, in ms",
	)
	cmd.Flags().StringVarP(
		&flags.Filesystem, "filesystem", "f", "",
		fmt.Sprintf("Which filesystem to trace: [%s]", strings.Join(validFsSlowerFilesystems, ", ")),
	)

	return cmd
}
