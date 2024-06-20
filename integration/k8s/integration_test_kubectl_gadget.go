// Copyright 2019-2024 The Inspektor Gadget authors
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
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/integration"
)

const (
	K8sDistroAKSAzureLinux  = "aks-AzureLinux"
	K8sDistroAKSUbuntu      = "aks-Ubuntu"
	K8sDistroARO            = "aro"
	K8sDistroMinikubeGH     = "minikube-github"
	K8sDistroEKSAmazonLinux = "eks-AmazonLinux"
	K8sDistroGKECOS         = "gke-COS_containerd"

	securityProfileOperatorNamespace = "security-profiles-operator"
)

var cleaningUp = uint32(0)

var (
	doNotDeploySPO = flag.Bool("no-deploy-spo", true, "don't deploy the Security Profiles Operator (SPO)")

	k8sDistro = flag.String("k8s-distro", "", "allows to skip tests that are not supported on a given Kubernetes distribution")

	gadgetRepository  = flag.String("gadget-repository", "ghcr.io/inspektor-gadget/gadget", "repository where gadget images are stored")
	gadgetTag         = flag.String("gadget-tag", "latest", "tag used for gadgets's OCI images")
	gadgetVerifyImage = flag.Bool("gadget-verify-image", true, "verify gadget image before running tests")
)

func cleanupFunc(cleanupCommands []*integration.Command) {
	if !atomic.CompareAndSwapUint32(&cleaningUp, 0, 1) {
		return
	}

	fmt.Println("Cleaning up...")

	// We don't want to wait for each cleanup command to finish before
	// running the next one because in the case the workflow run is
	// cancelled, we have few seconds (7.5s + 2.5s) before the runner kills
	// the entire process tree. Therefore, let's try to, at least, launch
	// the cleanup process in the cluster:
	// https://docs.github.com/en/actions/managing-workflow-runs/canceling-a-workflow#steps-github-takes-to-cancel-a-workflow-run
	for _, cmd := range cleanupCommands {
		err := cmd.StartWithoutTest()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
	}

	for _, cmd := range cleanupCommands {
		err := cmd.WaitWithoutTest()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
	}
}

func testMainInspektorGadget(m *testing.M) int {
	if os.Getenv("KUBECTL_GADGET") == "" {
		fmt.Fprintf(os.Stderr, "please set $KUBECTL_GADGET.")
		return -1
	}

	fmt.Printf("using random seed: %d\n", integration.GetSeed())

	initCommands := []*integration.Command{}
	cleanupCommands := []*integration.Command{integration.DeleteRemainingNamespacesCommand()}

	deploySPO := !integration.CheckNamespace(securityProfileOperatorNamespace) && !*doNotDeploySPO
	if deploySPO {
		limitReplicas := false
		patchWebhookConfig := false
		bestEffortResourceMgmt := false
		if *k8sDistro == K8sDistroMinikubeGH {
			limitReplicas = true
			bestEffortResourceMgmt = true
		}
		if *k8sDistro == K8sDistroAKSUbuntu {
			patchWebhookConfig = true
		}
		initCommands = append(initCommands, integration.DeploySPO(limitReplicas, patchWebhookConfig, bestEffortResourceMgmt))
		cleanupCommands = append(cleanupCommands, integration.CleanupSPO...)
	}

	if integration.CheckNamespace(securityProfileOperatorNamespace) {
		fmt.Println("Using existing installation of SPO in the cluster:")
	}

	notifyInitDone := make(chan bool, 1)

	cancel := make(chan os.Signal, 1)
	signal.Notify(cancel, syscall.SIGINT)

	cancelling := false
	notifyCancelDone := make(chan bool, 1)

	go func() {
		for {
			<-cancel
			fmt.Printf("\nHandling cancellation...\n")

			if cancelling {
				fmt.Println("Warn: Forcing cancellation. Resources couldn't have been cleaned up")
				os.Exit(1)
			}
			cancelling = true

			go func() {
				defer func() {
					// This will actually never be called due to the os.Exit()
					// but the notifyCancelDone channel helps to make the main
					// go routing wait for the handler to finish the clean up.
					notifyCancelDone <- true
				}()

				// Start by stopping the init commands (in the case they are
				// still running) to avoid trying to undeploy resources that are
				// being deployed.
				fmt.Println("Stop init commands (if they are still running)...")
				for _, cmd := range initCommands {
					err := cmd.KillWithoutTest()
					if err != nil {
						fmt.Fprintf(os.Stderr, "%s\n", err)
					}
				}

				// Wait until init commands have exited before starting the
				// cleanup.
				<-notifyInitDone

				cleanupFunc(cleanupCommands)
				os.Exit(1)
			}()
		}
	}()

	fmt.Printf("Running init commands:\n")

	initDone := true
	for _, cmd := range initCommands {
		if cancelling {
			initDone = false
			break
		}

		err := cmd.RunWithoutTest()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			initDone = false
			break
		}
	}

	// Notify the cancelling handler that the init commands finished
	notifyInitDone <- initDone

	defer cleanupFunc(cleanupCommands)

	if !initDone {
		// If needed, wait for the cancelling handler to finish before exiting
		// from the main go routine. Otherwise, the cancelling handler will be
		// terminated as well and the cleanup operations will not be completed.
		if cancelling {
			<-notifyCancelDone
		}

		return 1
	}

	fmt.Println("Start running tests:")
	return m.Run()
}
