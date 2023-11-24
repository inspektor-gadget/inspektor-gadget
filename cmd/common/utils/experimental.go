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

package utils

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/experimental"
)

const (
	errMsgExperimental = "this command can only be used when experimental features are enabled"
)

func replaceFunc(f func(cmd *cobra.Command, args []string)) func(cmd *cobra.Command, args []string) {
	if f == nil || experimental.Enabled() {
		return f
	}

	return func(cmd *cobra.Command, args []string) {
		fmt.Println(errMsgExperimental)
	}
}

func replaceFuncE(f func(cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error {
	if f == nil || experimental.Enabled() {
		return f
	}

	return func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf(errMsgExperimental)
	}
}

func MarkExperimental(cmd *cobra.Command) *cobra.Command {
	cmd.Short += " (experimental)"

	if !experimental.Enabled() {
		// Allow printing help when -h is passed.
		cmd.DisableFlagParsing = false
		// Ignore unknown flags so that we can print help when -h is passed.
		cmd.FParseErrWhitelist.UnknownFlags = true
	}

	cmd.Run = replaceFunc(cmd.Run)
	cmd.PreRun = replaceFunc(cmd.PreRun)
	cmd.PostRun = replaceFunc(cmd.PostRun)
	cmd.RunE = replaceFuncE(cmd.RunE)
	cmd.PreRunE = replaceFuncE(cmd.PreRunE)
	cmd.PostRunE = replaceFuncE(cmd.PostRunE)

	return cmd
}
