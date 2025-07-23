// Copyright 2025 The Inspektor Gadget authors
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

package tests

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

// checkRegistryReachable attempts to connect to a TCP address with backoff
func checkRegistryReachable(addr string) error {
	maxRetries := 120 // 1 minute
	retryDelay := 500 * time.Millisecond

	for range maxRetries {
		conn, err := net.DialTimeout("tcp", addr, retryDelay)
		if err == nil {
			conn.Close()
			return nil
		}

		time.Sleep(retryDelay)
	}

	return fmt.Errorf("registry not reachable after %d attempts", maxRetries)
}

func TestRunInsecure(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")

	containerRegistryOpts := []containers.ContainerOption{
		containers.WithContainerImage(gadgettesting.RegistryImage),
	}

	// It's a bit difficutl to implement this on Kubernetes as we'd to use port
	// forwarding to copy the image below.
	if utils.CurrentTestComponent != utils.IgLocalTestComponent {
		t.Skip("Test only sopported on ig")
	}

	if utils.CurrentTestComponent == utils.IgLocalTestComponent && utils.Runtime == "containerd" {
		t.Skip("Skipping test as containerd test utils can't use the network")
	}

	containerRegistry := containerFactory.NewContainer(
		"gadget-registry",
		"registry serve /etc/docker/registry/config.yml",
		containerRegistryOpts...,
	)
	containerRegistry.Start(t)
	t.Cleanup(func() {
		containerRegistry.Stop(t)
	})

	registry := containerRegistry.IP() + ":5000"
	// Check if registry is reachable with backoff
	err = checkRegistryReachable(registry)
	require.NoError(t, err, "registry not reachable")

	srcImage := gadgetrunner.GetGadgetImageName("ci/sched_cls_drop")
	destImage := registry + "/sched_cls_drop:latest"

	srcRepo, err := remote.NewRepository(srcImage)
	require.NoError(t, err)

	destRepo, err := remote.NewRepository(destImage)
	require.NoError(t, err)
	destRepo.PlainHTTP = true // Enable plain HTTP for insecure registry

	// Copy the image
	desc, err := oras.Copy(t.Context(), srcRepo, srcImage, destRepo, destImage, oras.DefaultCopyOptions)
	require.NoError(t, err)
	require.NotNil(t, desc)

	runnerOpts := []igrunner.Option{
		// force pulling to avoid the test passing if the image was pulled by a test before
		igrunner.WithFlags("--pull=always"),
		igrunner.WithFlags("--insecure-registries=" + registry),
		// disable image verification as we aren't copying the signature
		igrunner.WithFlags("--verify-image=false"),
	}
	var testingOpts []igtesting.Option

	runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime), "--timeout=5"))

	schedClsCmd := igrunner.New(destImage, runnerOpts...)
	igtesting.RunTestSteps([]igtesting.TestStep{schedClsCmd}, t, testingOpts...)
}
