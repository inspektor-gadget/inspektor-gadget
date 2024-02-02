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
	"context"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/internal/deployinfo"
	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:          "version",
	Short:        "Show version",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Client version: v%s\n", version.Version())

		client, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
		if err != nil {
			return commonutils.WrapInErrSetupK8sClient(err)
		}

		gadgetNamespace := runtimeGlobalParams.Get(grpcruntime.ParamGadgetNamespace).AsString()

		opts := metav1.ListOptions{LabelSelector: "k8s-app=gadget"}
		pods, err := client.CoreV1().Pods(gadgetNamespace).List(context.TODO(), opts)
		if err != nil {
			return commonutils.WrapInErrListPods(err)
		}

		if len(pods.Items) == 0 {
			fmt.Println("Server version:", "not installed")
			return nil
		}

		grpcRuntime.InitDeployInfo()
		info, err := deployinfo.Load()
		if err != nil {
			return fmt.Errorf("loading deploy info: %w", err)
		}

		fmt.Printf("Server version: v%s\n", info.ServerVersion)

		return nil
	},
}
