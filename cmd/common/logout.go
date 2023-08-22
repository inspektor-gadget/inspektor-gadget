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

	"github.com/containers/common/pkg/auth"
	"github.com/containers/image/v5/types"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci_helper"
)

type logoutOptions struct {
	logoutOpts auth.LogoutOptions
}

func NewLogoutCmd() *cobra.Command {
	o := logoutOptions{}
	cmd := &cobra.Command{
		Use:          "logout [command options] REGISTRY",
		Short:        "Logout of a container registry",
		Long:         "Logout of a container registry on a specified server.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.logoutOpts.Stdout = os.Stdout
			return auth.Logout(&types.SystemContext{}, &o.logoutOpts, args)
		},
	}
	logoutFlagSet := auth.GetLogoutFlags(&o.logoutOpts)
	logoutFlagSet.Lookup("authfile").Value.Set(oci_helper.DefaultAuthFile)
	cmd.Flags().AddFlagSet(logoutFlagSet)
	return cmd
}
