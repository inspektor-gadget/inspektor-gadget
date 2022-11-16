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
	"net/http"
	"net/url"
	"os"
	"path"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/transport/spdy"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	pb "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/api"
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
		return commonutils.WrapInErrListPods(err)
	}
	if len(pods.Items) == 0 {
		return commonutils.ErrGadgetPodNotFound
	}
	if len(pods.Items) != 1 {
		return commonutils.ErrMultipleGadgetPodFound
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

// ReceiveStream uses a tunnel (port forwarding) through the API server to fetch a trace stream
func ReceiveStream(
	client *kubernetes.Clientset,
	node string,
	traceID string,
	callback func(line string, node string),
	transform func(line string) string,
	writer io.Writer,
) error {
	listOptions := metav1.ListOptions{
		LabelSelector: "k8s-app=gadget",
		FieldSelector: "spec.nodeName=" + node + ",status.phase=Running",
	}
	pods, err := client.CoreV1().Pods("gadget").List(context.TODO(), listOptions)
	if err != nil {
		return commonutils.WrapInErrListPods(err)
	}
	if len(pods.Items) == 0 {
		return commonutils.ErrGadgetPodNotFound
	}
	if len(pods.Items) != 1 {
		return commonutils.ErrMultipleGadgetPodFound
	}
	podName := pods.Items[0].Name

	restConfig, err := kubeRestConfig()
	if err != nil {
		return err
	}

	transport, upgrader, err := spdy.RoundTripperFor(restConfig)
	if err != nil {
		return fmt.Errorf("creating roundtripper: %w", err)
	}

	targetURL, err := url.Parse(restConfig.Host)
	if err != nil {
		return fmt.Errorf("parsing restConfig.Host: %w", err)
	}

	targetURL.Path = path.Join(
		"api", "v1",
		"namespaces", "gadget",
		"pods", podName,
		"portforward",
	)

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, targetURL)
	readyChan := make(chan struct{})
	stopChan := make(chan struct{})

	fw, err := portforward.New(dialer, []string{fmt.Sprintf("%d:%d", 0, 7080)}, stopChan, readyChan, nil, os.Stderr)
	if err != nil {
		return fmt.Errorf("creating port forwarder: %w", err)
	}

	go fw.ForwardPorts()
	defer close(stopChan)

	// Wait for ready signal
	<-readyChan

	ports, err := fw.GetPorts()
	if err != nil {
		return err
	}

	if len(ports) != 1 {
		return errors.New("unexpected result from GetPorts()")
	}

	tlsConfig, err := getTLSConfig(node, client)
	if err != nil {
		return fmt.Errorf("generating certificate: %w", err)
	}
	cr := credentials.NewTLS(tlsConfig)

	conn, err := grpc.Dial(fmt.Sprintf("127.0.0.1:%d", ports[0].Local), grpc.WithTransportCredentials(cr))
	if err != nil {
		return fmt.Errorf("connecting to grpc: %w", err)
	}
	defer conn.Close()

	svc := pb.NewGadgetTracerManagerClient(conn)

	rsc, err := svc.ReceiveStream(context.Background(), &pb.TracerID{Id: traceID})
	if err != nil {
		return err
	}
	for {
		data, err := rsc.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("receiving gRPC data: %w", err)
		}
		if callback != nil {
			callback(data.Line, node)
		} else {
			if transform != nil {
				data.Line = transform(data.Line)
			}
			if data.Line != "" {
				fmt.Fprintf(writer, "%s\n", data.Line)
			}
		}
	}
}
