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
	"encoding/json"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/api"

	"github.com/containerd/nri/skel"
	types "github.com/containerd/nri/types/v1"

	"github.com/sirupsen/logrus"
)

// TODO: Understand why using github.com/containerd/pkg/cri/annonations
// creates a hell dependency problem with k8s.io packages.
const (
	// SandboxNamespace is the name of the namespace of the sandbox (pod)
	SandboxNamespace = "io.kubernetes.cri.sandbox-namespace"

	// SandboxName is the name of the sandbox (pod)
	SandboxName = "io.kubernetes.cri.sandbox-name"

	// ContainerName is the name of the container in the pod
	ContainerName = "io.kubernetes.cri.container-name"
)

var socketfile string

type igHookConf struct {
	Socketfile string
	Debug      bool
}

type igHook struct{}

func (i *igHook) Type() string {
	return "ighook"
}

func (i *igHook) Invoke(ctx context.Context, r *types.Request) (*types.Result, error) {
	// Ignore sandbox containers
	if !r.IsSandbox() && (r.State == types.Create || r.State == types.Delete) {
		conf := igHookConf{}
		err := json.Unmarshal(r.Conf, &conf)
		if err != nil {
			return nil, err
		}
		err = processContainer(r, &conf)
		if err != nil && conf.Debug {
			logrus.Debugf("failed to process container %s: %s", r.ID, err)
		}
	}

	result := r.NewResult("ighook")
	return result, nil
}

func main() {
	ctx := context.Background()
	if err := skel.Run(ctx, &igHook{}); err != nil {
		fmt.Fprintf(os.Stderr, "Error executing ighook: %v", err)
		// don't return an error as it's a debug tool and we don't want to
		// create extra trouble if there is a failure.
		os.Exit(0)
	}
}

func processContainer(r *types.Request, conf *igHookConf) error {
	// Validate state
	if r.ID == "" || (r.Pid == 0 && r.State == types.Create) {
		return fmt.Errorf("invalid OCI state: %v %v", r.ID, r.Pid)
	}

	// Connect to the Gadget Tracer Manager
	var client pb.GadgetTracerManagerClient
	var ctx context.Context
	var cancel context.CancelFunc
	conn, err := grpc.Dial("unix://"+conf.Socketfile, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	client = pb.NewGadgetTracerManagerClient(conn)
	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Handle the poststop hook first
	if r.State == types.Delete {
		_, err := client.RemoveContainer(ctx, &pb.ContainerDefinition{
			Id: r.ID,
		})
		return err
	}

	labels := []*pb.Label{}

	for key, value := range r.Labels {
		label := &pb.Label{
			Key:   key,
			Value: value,
		}
		labels = append(labels, label)
	}

	namespace, ok := r.Spec.Annotations[SandboxNamespace]
	if !ok {
		return nil
	}
	containerName, ok := r.Spec.Annotations[ContainerName]
	if !ok {
		return nil
	}
	podName, ok := r.Spec.Annotations[SandboxName]
	if !ok {
		return nil
	}

	_, err = client.AddContainer(ctx, &pb.ContainerDefinition{
		Id:        r.ID,
		Labels:    labels,
		Namespace: namespace,
		Podname:   podName,
		Name:      containerName,
		Pid:       uint32(r.Pid),
	})
	return err
}
