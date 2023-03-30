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

package grpcruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/factory"
	pb "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/api"
)

type k8sExecConn struct {
	io.Writer
	io.Reader
	exec       remotecommand.Executor
	podName    string
	cancelFunc func()
}

// NewK8SExecConn connects to a Pod using the Kubernetes API Server and launches a socat
func NewK8SExecConn(ctx context.Context, pod gadgetPod, timeout time.Duration) (net.Conn, error) {
	readerExt, writer := io.Pipe()
	reader, writerExt := io.Pipe()
	conn := &k8sExecConn{
		Writer: writer,
		Reader: reader,
	}

	config, err := utils.KubernetesConfigFlags.ToRESTConfig()
	if err != nil {
		return nil, fmt.Errorf("creating RESTConfig: %w", err)
	}

	// set GroupVersion and NegotiatedSerializer for RESTClient
	factory.SetKubernetesDefaults(config)

	conn.podName = pod.name

	config.Timeout = timeout

	restClient, err := restclient.RESTClientFor(config)
	if err != nil {
		return nil, err
	}

	req := restClient.Post().
		Resource("pods").
		Name(conn.podName).
		Namespace("gadget").
		SubResource("exec").
		Param("container", "gadget").
		VersionedParams(&v1.PodExecOptions{
			Container: "gadget",
			Command:   []string{"/usr/bin/socat", pb.GadgetServiceSocket, "-"},
			Stdin:     true,
			Stdout:    true,
			Stderr:    false,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		return nil, err
	}
	conn.exec = exec

	ctx, cancelFunc := context.WithCancel(context.Background())
	conn.cancelFunc = cancelFunc

	go func() {
		err := exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdin:             readerExt,
			Stdout:            writerExt,
			Stderr:            nil,
			Tty:               false,
			TerminalSizeQueue: nil,
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Warnf("connecting to gadget service on node %q: %v", pod.node, err)
		}
	}()
	return conn, nil
}

func (k *k8sExecConn) Close() error {
	k.cancelFunc()
	return nil
}

func (k *k8sExecConn) LocalAddr() net.Addr {
	return nil
}

func (k *k8sExecConn) RemoteAddr() net.Addr {
	return &k8sAddress{podName: k.podName}
}

func (k *k8sExecConn) SetDeadline(t time.Time) error {
	return nil
}

func (k *k8sExecConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (k *k8sExecConn) SetWriteDeadline(t time.Time) error {
	return nil
}
