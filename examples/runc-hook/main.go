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
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ocispec "github.com/opencontainers/runtime-spec/specs-go"
	api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
	"github.com/kinvolk/inspektor-gadget/pkg/runcfanotify"
)

var (
	outputList = flag.String("output", "add,remove", "comma-separated list of events to print [add,remove,config]")

	outputAdd    bool
	outputRemove bool
	outputConfig bool

	hookPreStart = flag.String("prestart", "", "command to run in the PreStart hook")
	hookPostStop = flag.String("poststop", "", "command to run in the PostStop hook")
	env          = flag.String("env", "", "the environ")
	dir          = flag.String("dir", "", "dir")
	timeout      = flag.String("timeout", "10s", "timeout")

	timeoutDuration time.Duration

	publishKubernetesEvent = flag.Bool("publish-kubernetes-event", false, "Publish an event using the Kubernetes Event API")
	kubeconfig             = flag.String("kubeconfig", "", "kubeconfig")
	node                   = flag.String("node", "", "Node name")

	client *kubernetes.Clientset
)

func publishEvent(reason, message string) {
	eventTime := metav1.NewTime(time.Now())
	event := &api.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%v.%x", *node, time.Now().UnixNano()),
			Namespace: "default",
		},
		Source: api.EventSource{
			Component: "RuncHook",
			Host:      *node,
		},
		Count:               1,
		ReportingController: "github.com/kinvolk/inspektor-gadget",
		ReportingInstance:   os.Getenv("POD_NAME"), // pod name
		FirstTimestamp:      eventTime,
		LastTimestamp:       eventTime,
		InvolvedObject: api.ObjectReference{
			Kind: "Node",
			Name: *node,
			// Uncomment to make it visible in 'kubectl describe node'
			//UID: types.UID(*node),
		},
		Type:    api.EventTypeNormal,
		Reason:  reason,
		Message: message,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.CoreV1().Events("default").Create(ctx, event, metav1.CreateOptions{}); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create event: %s\n", err)
	}
}

func runCommand(command, dir string, env []string, timeout time.Duration, ociState *ocispec.State) error {
	b, err := json.Marshal(ociState)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(b)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func callback(notif runcfanotify.ContainerEvent) {
	// The OCI State is defined at:
	//     https://github.com/opencontainers/runtime-spec/blob/main/runtime.md#state
	// and is passed to OCI hooks over stdin, see:
	//     https://github.com/opencontainers/runtime-spec/blob/main/config.md#posix-platform-hooks
	// ociState will be given as stdin to the command.
	//
	// This code does not add any hooks in the config but executes the
	// command in the same way that OCI hooks would do. For this we need to
	// synthesise the OCI State.
	ociState := &ocispec.State{
		Version: ocispec.Version,
		ID:      notif.ContainerID,
		Pid:     int(notif.ContainerPID),
		Bundle:  notif.Bundle,
	}
	if notif.ContainerConfig != nil && notif.ContainerConfig.Annotations != nil {
		ociState.Annotations = notif.ContainerConfig.Annotations
	} else {
		ociState.Annotations = make(map[string]string)
	}

	var cmd string
	switch notif.Type {
	case runcfanotify.EventTypeAddContainer:
		ociState.Status = ocispec.StateCreated
		var config string
		if notif.ContainerConfig != nil {
			b, err := json.Marshal(notif.ContainerConfig)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to marshal ContainerConfig: %s\n", err)
			} else {
				config = string(b)
			}
		}
		if outputAdd {
			fmt.Printf("Container added: %v pid %d\n", notif.ContainerID, notif.ContainerPID)
		}
		if outputConfig {
			if config != "" {
				fmt.Printf("%s\n", config)
			} else {
				fmt.Fprintf(os.Stderr, "Error: container config not found for container %s\n", notif.ContainerID)
			}
		}
		if *publishKubernetesEvent {
			if config != "" {
				publishEvent("NewContainerConfig", config)
			} else {
				publishEvent("ContainerConfigNotFound", "")
			}
		}

		if *hookPreStart != "" {
			cmd = *hookPreStart
		}
	case runcfanotify.EventTypeRemoveContainer:
		ociState.Status = ocispec.StateStopped
		if outputRemove {
			fmt.Printf("Container removed: %v pid %d\n", notif.ContainerID, notif.ContainerPID)
		}
		if *hookPostStop != "" {
			cmd = *hookPostStop
		}
	default:
		return
	}

	if cmd != "" {
		err := runCommand(cmd, *dir, strings.Split(*env, " "), timeoutDuration, ociState)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to execute command: %s\n", err)
		}
	}
}

func main() {
	flag.Parse()
	var err error
	timeoutDuration, err = time.ParseDuration(*timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid timeout %q: %s\n", *timeout, err)
		os.Exit(1)
	}
	if *node == "" && os.Getenv("NODE_NAME") != "" {
		*node = os.Getenv("NODE_NAME")
	}

	for _, o := range strings.Split(*outputList, ",") {
		switch o {
		case "add":
			outputAdd = true
		case "remove":
			outputRemove = true
		case "config":
			outputConfig = true
		case "":
			// strings.Split() can generate empty strings
		default:
			fmt.Fprintf(os.Stderr, "invalid option: %q\n", o)
			os.Exit(1)
		}
	}

	if *publishKubernetesEvent {
		if *kubeconfig == "" && os.Getenv("KUBECONFIG") != "" {
			*kubeconfig = os.Getenv("KUBECONFIG")
		}
		client, err = k8sutil.NewClientset(*kubeconfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get Kubernetes client set: %s\n", err)
			os.Exit(1)
		}
	}

	if !runcfanotify.Supported() {
		fmt.Printf("runcfanotify not supported\n")
		os.Exit(1)
	}

	_, err = runcfanotify.NewRuncNotifier(callback)
	if err != nil {
		fmt.Printf("runcfanotify failed: %v\n", err)
		os.Exit(1)
	}

	// Graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGTERM)
	<-exit
}
