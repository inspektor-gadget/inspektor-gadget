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
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k8s.io/apimachinery/pkg/types"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
)

var (
	kubeconfig = flag.String("kubeconfig", "", "kubeconfig")
	node       = flag.String("node", "", "Node name")

	client *kubernetes.Clientset
	cc     *containercollection.ContainerCollection
)

func publishEvent(c *containercollection.Container, reason, message string) {
	eventTime := metav1.NewTime(time.Now())
	event := &api.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%v.%x", c.K8s.Pod, time.Now().UnixNano()),
			Namespace: c.K8s.Namespace,
		},
		Source: api.EventSource{
			Component: "KubeContainerCollection",
			Host:      *node,
		},
		Count:               1,
		ReportingController: "github.com/inspektor-gadget/inspektor-gadget",
		ReportingInstance:   os.Getenv("POD_NAME"), // pod name
		FirstTimestamp:      eventTime,
		LastTimestamp:       eventTime,
		InvolvedObject: api.ObjectReference{
			Kind:      "Pod",
			Namespace: c.K8s.Namespace,
			Name:      c.K8s.Pod,
			UID:       types.UID(c.K8s.PodUID),
		},
		Type:    api.EventTypeNormal,
		Reason:  reason,
		Message: message,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.CoreV1().Events(c.K8s.Namespace).Create(ctx, event, metav1.CreateOptions{}); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create event: %s\n", err)
	}
}

func callback(notif containercollection.PubSubEvent) {
	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		fmt.Printf("Container added: %v pid %d\n", notif.Container.Runtime.ContainerID, notif.Container.Pid)
		if notif.Container.OciConfig != nil {
			config, err := json.Marshal(notif.Container.OciConfig)
			if err != nil {
				publishEvent(notif.Container, "CannotMarshalContainerConfig", err.Error())
			} else {
				publishEvent(notif.Container, "NewContainerConfig", string(config))
			}
		} else {
			publishEvent(notif.Container, "ContainerConfigNotFound", "")
		}
	case containercollection.EventTypeRemoveContainer:
		fmt.Printf("Container removed: %v pid %d\n", notif.Container.Runtime.ContainerID, notif.Container.Pid)
	default:
		return
	}
}

func main() {
	flag.Parse()

	if *kubeconfig == "" && os.Getenv("KUBECONFIG") != "" {
		*kubeconfig = os.Getenv("KUBECONFIG")
	}

	if *node == "" && os.Getenv("NODE_NAME") != "" {
		*node = os.Getenv("NODE_NAME")
	}

	config, err := k8sutil.NewKubeConfig(*kubeconfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get kubeconfig: %s\n", err)
		os.Exit(1)
	}

	client, err = kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get Kubernetes client set: %s\n", err)
		os.Exit(1)
	}

	containerEventFuncs := []containercollection.FuncNotify{callback}
	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithPubSub(containerEventFuncs...),
		containercollection.WithCgroupEnrichment(),
		containercollection.WithKubernetesEnrichment(*node, config),
		containercollection.WithRuncFanotify(),
	}

	cc = &containercollection.ContainerCollection{}
	err = cc.Initialize(opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize container collection: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Ready\n")

	cc.ContainerRange(func(c *containercollection.Container) {
		fmt.Printf("%+v\n", c)
	})

	// Graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit
}
