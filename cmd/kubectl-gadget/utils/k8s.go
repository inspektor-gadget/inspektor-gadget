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
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
)

func GetRunningGadgetNamespaces() ([]string, error) {
	client, err := k8sutil.NewClientsetFromConfigFlags(KubernetesConfigFlags)
	if err != nil {
		return []string{}, fmt.Errorf("creating k8s client: %w", err)
	}

	opts := metav1.ListOptions{
		FieldSelector: "metadata.name=gadget",
		LabelSelector: "k8s-app=gadget",
	}
	daemonSet, err := client.AppsV1().DaemonSets("").List(context.TODO(), opts)
	if err != nil {
		return []string{}, err
	}
	gadgetNamespaces := make([]string, len(daemonSet.Items))
	for i, ds := range daemonSet.Items {
		gadgetNamespaces[i] = ds.Namespace
	}

	return gadgetNamespaces, nil
}
