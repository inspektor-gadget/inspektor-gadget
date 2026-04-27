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

package common

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/auth"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

func NewLoginCmd() *cobra.Command {
	opts := &auth.LoginOptions{}
	cmd := &cobra.Command{
		Use:          "login [command options] REGISTRY",
		Short:        "Login to a container registry",
		Long:         "Login to a container registry on a specified server.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Stdout = os.Stdout
			opts.Stdin = os.Stdin
			return auth.Login(cmd.Context(), opts, args)
		},
	}
	loginFlagSet := auth.GetLoginFlags(opts)
	loginFlagSet.Lookup("authfile").Value.Set(oci.DefaultAuthFile)
	cmd.Flags().AddFlagSet(loginFlagSet)
	return cmd
}
