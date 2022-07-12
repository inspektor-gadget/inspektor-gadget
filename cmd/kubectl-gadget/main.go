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

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/advise"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/audit"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/profile"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/snapshot"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/top"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/trace"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
)

// common params for all gadgets
var params utils.CommonFlags

var rootCmd = &cobra.Command{
	Use:   "kubectl-gadget",
	Short: "Collection of gadgets for Kubernetes developers",
}

func init() {
	utils.FlagInit(rootCmd)

	rootCmd.AddCommand(advise.AdviseCmd)
	rootCmd.AddCommand(audit.AuditCmd)
	rootCmd.AddCommand(profile.NewProfileCmd())
	rootCmd.AddCommand(snapshot.NewSnapshotCmd())
	rootCmd.AddCommand(top.TopCmd)
	rootCmd.AddCommand(trace.NewTraceCmd())
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
