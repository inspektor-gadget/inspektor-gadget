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

package utils

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

func ExecPodSimple(client *kubernetes.Clientset, node string, podCmd string) string {
	stdout, stderr, err := ExecPodCapture(client, node, podCmd)
	if err != nil {
		return fmt.Sprintf("%s", err) + stdout + stderr
	} else {
		return stdout + stderr
	}
}

func ExecPodCapture(client *kubernetes.Clientset, node string, podCmd string) (string, string, error) {
	var stdout, stderr bytes.Buffer
	err := ExecPod(client, node, podCmd, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

func ExecPod(client *kubernetes.Clientset, node string, podCmd string, cmdStdout io.Writer, cmdStderr io.Writer) error {
	listOptions := metav1.ListOptions{
		LabelSelector: "k8s-app=gadget",
		FieldSelector: "spec.nodeName=" + node + ",status.phase=Running",
	}
	pods, err := client.CoreV1().Pods("gadget").List(context.TODO(), listOptions)
	if err != nil {
		return err
	}
	if len(pods.Items) == 0 {
		return errors.New("Gadget Daemon not found")
	}
	if len(pods.Items) != 1 {
		return errors.New("Multiple Gadget Daemons found")
	}
	podName := pods.Items[0].Name

	restConfig, err := kubeRestConfig()
	if err != nil {
		return err
	}

	restClient, err := restclient.RESTClientFor(restConfig)
	if err != nil {
		return err
	}

	req := restClient.Post().
		Resource("pods").
		Name(podName).
		Namespace("gadget").
		SubResource("exec").
		Param("container", "gadget").
		VersionedParams(&corev1.PodExecOptions{
			Container: "gadget",
			Command:   []string{"/bin/sh", "-c", podCmd},
			Stdin:     false,
			Stdout:    true,
			Stderr:    true,
			TTY:       true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
	if err != nil {
		return err
	}

	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: cmdStdout,
		Stderr: cmdStderr,
		Tty:    true,
	})
	return err
}
