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

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	k8smeta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
)

type K8sCommand struct {
	name    string
	runFunc func(*testing.T)
}

func (c *K8sCommand) Run(t *testing.T) {
	t.Logf("Run K8sCommand:\n%s\n", c.name)
	c.runFunc(t)
}
func (c *K8sCommand) Start(*testing.T) {}
func (c *K8sCommand) Stop(*testing.T)  {}

func (c *K8sCommand) RunWithoutTest() error   { return nil }
func (c *K8sCommand) StartWithoutTest() error { return nil }
func (c *K8sCommand) WaitWithoutTest() error  { return nil }
func (c *K8sCommand) KillWithoutTest() error  { return nil }

func (c *K8sCommand) IsCleanup() bool      { return false }
func (c *K8sCommand) IsStartAndStop() bool { return false }
func (c *K8sCommand) IsStarted() bool      { return false }

// PodCommand returns a Command that starts a pid with a specified image, command and args
func PodCommand(podname, image, namespace string, command, commandArgs []string) *K8sCommand {
	return &K8sCommand{
		name: fmt.Sprintf("Creating pod %s", podname),
		runFunc: func(t *testing.T) {
			k8sClient, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
			if err != nil {
				t.Fatalf("Creating pod (%s): %s", podname, commonutils.WrapInErrSetupK8sClient(err).Error())
				return
			}

			containerConfig := v1.Container{
				Name:    podname,
				Image:   image,
				Command: command,
				Args:    commandArgs,
			}

			gracedPeriod := int64(0)
			podSpec := v1.PodSpec{
				RestartPolicy:                 v1.RestartPolicyNever,
				TerminationGracePeriodSeconds: &gracedPeriod,
				Containers:                    []v1.Container{containerConfig},
			}

			objectMeta := k8smeta.ObjectMeta{
				Name:      podname,
				Namespace: namespace,
				Labels: map[string]string{
					"run": podname,
				},
			}

			podConfig := v1.Pod{
				ObjectMeta: objectMeta,
				Spec:       podSpec,
			}

			podClient := k8sClient.CoreV1().Pods(namespace)
			// First returned variable is the pod. Maybe we could use it later?
			_, err = podClient.Create(context.TODO(), &podConfig, k8smeta.CreateOptions{})

			if err != nil {
				t.Fatalf("Creating pod (%s): %s\n", podname, err.Error())
				return
			}
		},
	}
}

// BusyboxPodCommand returns a Command that creates a pod and runs "cmd" in it.
func BusyboxPodCommand(namespace, cmd string) *K8sCommand {
	return PodCommand("test-pod", "busybox", namespace, []string{"/bin/sh", "-c"}, []string{cmd})
}

// BusyboxPodRepeatCommand returns a CmdCommand that creates a pod and runs
// "cmd" each 0.1 seconds inside the pod.
func BusyboxPodRepeatCommand(namespace, cmd string) *K8sCommand {
	cmdStr := fmt.Sprintf("while true; do %s ; sleep 0.1; done", cmd)
	return BusyboxPodCommand(namespace, cmdStr)
}

// CreateTestNamespaceCommand returns a K8sCommand which creates a namespace whom
// name is given as parameter.
func CreateTestNamespaceCommand(namespace string) *K8sCommand {
	return &K8sCommand{
		name: fmt.Sprintf("Creating namespace %s", namespace),
		runFunc: func(t *testing.T) {
			k8sClient, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
			if err != nil {
				t.Fatalf("creating namespace %s: %s", namespace, commonutils.WrapInErrSetupK8sClient(err).Error())
				return
			}
			objectMeta := k8smeta.ObjectMeta{
				Name: namespace,
				Labels: map[string]string{
					namespaceLabelKey: namespaceLabelValue,
				},
			}

			nsConfig := v1.Namespace{
				ObjectMeta: objectMeta,
			}

			ns, err := k8sClient.CoreV1().Namespaces().Create(context.TODO(), &nsConfig, k8smeta.CreateOptions{})
			if err != nil {
				t.Fatalf("creating namespace %s: %s", namespace, err.Error())
				return
			}

			timeout := 15
			for i := 0; i < timeout; i++ {
				if ns.Status.Phase == v1.NamespaceActive {
					break
				}
				time.Sleep(1 * time.Second)
			}
			if ns.Status.Phase != v1.NamespaceActive {
				t.Fatalf("namespace %s was not active after %d seconds", namespace, timeout)
			}
		},
	}
}

// WaitUntilPodReadyCommand returns a CmdCommand which waits until pod with the specified name in
// the given as parameter namespace is ready.
func WaitUntilPodReadyCommand(namespace string, podname string) *K8sCommand {
	return &K8sCommand{
		name: fmt.Sprintf("Waiting for pod %s", podname),
		runFunc: func(t *testing.T) {
			k8sClient, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
			if err != nil {
				t.Fatal(commonutils.WrapInErrSetupK8sClient(err).Error())
				return
			}

			podClient := k8sClient.CoreV1().Pods(namespace)

			opts := k8smeta.ListOptions{
				FieldSelector: fmt.Sprintf("metadata.name=%s", podname),
			}
			watcher, err := podClient.Watch(context.TODO(), opts)
			if err != nil {
				t.Fatalf("Adding watch for pod (%s): %s\n", podname, err.Error())
				return
			}
			defer watcher.Stop()

			isReady := func(conditions []v1.PodCondition) bool {
				for _, condition := range conditions {
					if condition.Type == v1.PodReady {
						return condition.Status == v1.ConditionTrue
					}
				}
				return false
			}

			podList, err := podClient.List(context.TODO(), opts)
			if err != nil {
				t.Fatal(commonutils.WrapInErrListPods(err).Error())
				return
			} else if len(podList.Items) > 1 {
				t.Fatalf("Found %d pods with name %s instead of 1", len(podList.Items), podname)
				return
			} else if len(podList.Items) == 1 {
				// Check after .Watch(...) so we do not miss an event
				if isReady(podList.Items[0].Status.Conditions) {
					return
				}
			}

			for event := range watcher.ResultChan() {
				switch event.Type {
				case watch.Added:
				case watch.Modified:
					pod := event.Object.(*v1.Pod)

					if isReady(pod.Status.Conditions) {
						return
					}
				case watch.Error:
				default:
					t.Fatalf("Unknown event while waiting for pod %s", podname)
					return
				}
			}
			t.Fatalf("Timeout waiting for pod %s", podname)
		},
	}
}

// WaitUntilTestPodReadyCommand returns a CmdCommand which waits until test-pod in
// the given as parameter namespace is ready.
func WaitUntilTestPodReadyCommand(namespace string) *K8sCommand {
	return WaitUntilPodReadyCommand(namespace, "test-pod")
}
