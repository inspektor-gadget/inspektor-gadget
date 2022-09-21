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
	"strings"

	"github.com/blang/semver"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
)

// This variable is used by the "version" command and is set during build.
var version = "undefined"

func init() {
	rootCmd.AddCommand(versionCmd)

	utils.KubectlGadgetVersion, _ = semver.New(version[1:])
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Client version:", version)

		client, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
		if err != nil {
			return commonutils.WrapInErrSetupK8sClient(err)
		}

		opts := metav1.ListOptions{LabelSelector: "k8s-app=gadget"}
		pods, err := client.CoreV1().Pods("gadget").List(context.TODO(), opts)
		if err != nil {
			return commonutils.WrapInErrListNodes(err)
		}

		serverVersions := make(map[string]struct{})
		for _, pod := range pods.Items {
			image := pod.Spec.Containers[0].Image

			// Get the image tag
			parts := strings.Split(image, ":")
			if len(parts) < 2 {
				continue
			}

			versionStr := parts[len(parts)-1]
			if _, ok := serverVersions[versionStr]; !ok {
				serverVersions[versionStr] = struct{}{}
			}
		}

		if len(serverVersions) == 0 {
			fmt.Println("Server version:", "not installed")
		} else {
			if len(serverVersions) > 1 {
				fmt.Println("Warning: Multiple deployed versions detected")
			}
			for version := range serverVersions {
				fmt.Println("Server version:", version)
			}
		}

		return nil
	},
}
