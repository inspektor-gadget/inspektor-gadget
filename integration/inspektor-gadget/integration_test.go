// Copyright 2019-2022 The Inspektor Gadget authors
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
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
)

const (
	K8sDistroAKSMariner = "aks-Mariner"
	K8sDistroAKSUbuntu  = "aks-Ubuntu"
	K8sDistroARO        = "aro"
	K8sDistroMinikubeGH = "minikube-github"
)

const (
	DefaultImageFlavour = "default"
	CoreImageFlavour    = "core"
)

const securityProfileOperatorNamespace = "security-profiles-operator"

var (
	supportedK8sDistros = []string{K8sDistroAKSMariner, K8sDistroAKSUbuntu, K8sDistroARO, K8sDistroMinikubeGH}
	cleaningUp          = uint32(0)
)

var (
	integration = flag.Bool("integration", false, "run integration tests")

	// image such as ghcr.io/inspektor-gadget/inspektor-gadget:latest
	image          = flag.String("image", "", "gadget container image")
	imageFlavour   = flag.String("image-flavour", DefaultImageFlavour, "gadget container image flavour.")
	dnsTesterImage = flag.String("dnstester-image", "ghcr.io/inspektor-gadget/dnstester:latest", "dnstester container image")

	doNotDeployIG  = flag.Bool("no-deploy-ig", false, "don't deploy Inspektor Gadget")
	doNotDeploySPO = flag.Bool("no-deploy-spo", false, "don't deploy the Security Profiles Operator (SPO)")

	k8sDistro = flag.String("k8s-distro", "", "allows to skip tests that are not supported on a given Kubernetes distribution")
	k8sArch   = flag.String("k8s-arch", "amd64", "allows to skip tests that are not supported on a given CPU architecture")
)

func cleanupFunc(cleanupCommands []*Command) {
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

func testMain(m *testing.M) int {
	flag.Parse()
	if !*integration {
		fmt.Println("Skipping integration test.")
		return 0
	}

	if os.Getenv("KUBECTL_GADGET") == "" {
		fmt.Fprintf(os.Stderr, "please set $KUBECTL_GADGET.")
		return -1
	}

	if *k8sDistro != "" {
		found := false
		for _, val := range supportedK8sDistros {
			if *k8sDistro == val {
				found = true
				break
			}
		}

		if !found {
			fmt.Fprintf(os.Stderr, "Error: invalid argument '-k8s-distro': %q. Valid values: %s\n",
				*k8sDistro, strings.Join(supportedK8sDistros, ", "))
			return -1
		}
	}

	if *imageFlavour != "" {
		if *imageFlavour != DefaultImageFlavour && *imageFlavour != CoreImageFlavour {
			fmt.Fprintf(os.Stderr, "Error: invalid argument '-image-flavour': %q. Valid values: %s, %s\n",
				*imageFlavour, DefaultImageFlavour, CoreImageFlavour)
			return -1
		}
	}

	seed := time.Now().UTC().UnixNano()
	rand.Seed(seed)
	fmt.Printf("using random seed: %d\n", seed)

	initCommands := []*Command{}
	cleanupCommands := []*Command{DeleteRemainingNamespacesCommand()}

	if !*doNotDeployIG {
		imagePullPolicy := "Always"
		if *k8sDistro == K8sDistroMinikubeGH {
			imagePullPolicy = "Never"
		}
		deployCmd := DeployInspektorGadget(*image, imagePullPolicy)
		initCommands = append(initCommands, deployCmd)

		cleanupCommands = append(cleanupCommands, CleanupInspektorGadget)
	}

	deploySPO := !CheckNamespace(securityProfileOperatorNamespace) && !*doNotDeploySPO
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
		initCommands = append(initCommands, DeploySPO(limitReplicas, patchWebhookConfig, bestEffortResourceMgmt))
		cleanupCommands = append(cleanupCommands, CleanupSPO...)
	}

	if CheckNamespace(securityProfileOperatorNamespace) {
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

func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}
