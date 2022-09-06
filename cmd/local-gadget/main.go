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
	"os"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/local-gadget/containers"
	"github.com/kinvolk/inspektor-gadget/cmd/local-gadget/interactive"
	"github.com/kinvolk/inspektor-gadget/cmd/local-gadget/trace"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "local-gadget",
		Short: "Collection of gadgets for containers",
	}

	rootCmd.AddCommand(
		interactive.NewInteractiveCmd(),
		containers.NewListContainersCmd(),
		trace.NewTraceCmd(),
		newVersionCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
