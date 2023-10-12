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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/factory"
)

type k8sPortFwdDialer struct {
	io.Writer
	io.Reader
	conn    httpstream.Connection
	stream  httpstream.Stream
	podName string
}

// NewK8SPortFwdConn connects to a Pod using PortForwarding via the Kubernetes API Server
func NewK8SPortFwdConn(ctx context.Context, pod target, targetPort uint16, timeout time.Duration) (net.Conn, error) {
	conn := &k8sPortFwdDialer{}

	config, err := utils.KubernetesConfigFlags.ToRESTConfig()
	if err != nil {
		return nil, fmt.Errorf("creating RESTConfig: %w", err)
	}

	// set GroupVersion and NegotiatedSerializer for RESTClient
	factory.SetKubernetesDefaults(config)

	conn.podName = pod.addressOrPod

	config.Timeout = timeout

	transport, upgrader, err := spdy.RoundTripperFor(config)
	if err != nil {
		return nil, fmt.Errorf("creating roundtripper: %w", err)
	}

	targetURL, err := url.Parse(config.Host)
	if err != nil {
		return nil, fmt.Errorf("parsing restConfig.Host: %w", err)
	}

	targetURL.Path = fmt.Sprintf("api/v1/namespaces/gadget/pods/%s/portforward", conn.podName)

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, targetURL)

	newConn, _, err := dialer.Dial(portforward.PortForwardProtocolV1Name)
	if err != nil {
		return nil, err
	}

	// create error stream
	headers := http.Header{}
	headers.Set(v1.StreamType, v1.StreamTypeError)
	headers.Set(v1.PortHeader, fmt.Sprintf("%d", targetPort))
	headers.Set(v1.PortForwardRequestIDHeader, strconv.Itoa(1))
	errorStream, err := newConn.CreateStream(headers)
	if err != nil {
		newConn.Close()
		return nil, fmt.Errorf("creating error stream for port forward: %w", err)
	}
	// we're not writing to this stream, but it is required for other streams to be able to connect
	errorStream.Close()

	go func() {
		message, err := io.ReadAll(errorStream)
		switch {
		case err != nil:
			log.Errorf("k8sPortFwd connection: reading from error stream: %v", err)
		case len(message) > 0:
			log.Errorf("k8sPortFwd tcp connection: forwarding port: %v", string(message))
			log.Errorf("Please make sure the --connection-method value matches your installation.")
		}
	}()

	// create data stream
	headers.Set(v1.StreamType, v1.StreamTypeData)
	dataStream, err := newConn.CreateStream(headers)
	if err != nil {
		newConn.Close()
		return nil, fmt.Errorf("creating data stream for port forward: %w", err)
	}

	conn.conn = newConn
	conn.stream = dataStream
	return conn, nil
}

func (k *k8sPortFwdDialer) Close() error {
	k.stream.Close()
	return k.conn.Close()
}

func (k *k8sPortFwdDialer) Read(b []byte) (n int, err error) {
	return k.stream.Read(b)
}

func (k *k8sPortFwdDialer) Write(b []byte) (n int, err error) {
	return k.stream.Write(b)
}

func (k *k8sPortFwdDialer) LocalAddr() net.Addr {
	return nil
}

func (k *k8sPortFwdDialer) RemoteAddr() net.Addr {
	return &k8sAddress{podName: k.podName}
}

// satisfying the net.Conn interface

func (k *k8sPortFwdDialer) SetDeadline(_ time.Time) error {
	return nil
}

func (k *k8sPortFwdDialer) SetReadDeadline(_ time.Time) error {
	return nil
}

func (k *k8sPortFwdDialer) SetWriteDeadline(_ time.Time) error {
	return nil
}
