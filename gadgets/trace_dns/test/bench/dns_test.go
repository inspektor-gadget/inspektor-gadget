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

package tests

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

const (
	DefaultServerImage = "ghcr.io/mauriciovasquezbernal/dnsbench"
	DefaultClientImage = "ghcr.io/mauriciovasquezbernal/dnsbench"
	NumRuns            = 5 // Number of times to run each test configuration
)

type stat struct {
	cpu float64
	mem float64
}

type statResult struct {
	cpuMean float64
	cpuCI   float64
	memMean float64
	memCI   float64
}

// calculateStats calculates mean and 95% confidence interval for a slice of values
func calculateStats(values []float64) (mean, ci float64) {
	if len(values) == 0 {
		return 0, 0
	}

	// Calculate mean
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean = sum / float64(len(values))

	// Calculate standard deviation
	sumSquares := 0.0
	for _, v := range values {
		diff := v - mean
		sumSquares += diff * diff
	}
	variance := sumSquares / float64(len(values)-1)
	stddev := math.Sqrt(variance)

	// Calculate 95% confidence interval (assuming t-distribution)
	// For small samples, we use t-value. For simplicity, using 2.0 as approximation
	// For more precision, would need to import a stats library
	tValue := 2.0
	if len(values) >= 30 {
		tValue = 1.96 // z-value for large samples
	}

	standardError := stddev / math.Sqrt(float64(len(values)))
	ci = tValue * standardError

	return mean, ci
}

func testTraceDNS(t *testing.T, rps int, usetracer bool) stat {
	const tName = "test-trace-dns"
	const timeoutParam = "--timeout=10"
	const sleepTimeout = 10 * time.Second

	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	if utils.CurrentTestComponent == utils.IgLocalTestComponent && utils.Runtime == "containerd" {
		t.Skip("Skipping test as containerd test utils can't use the network")
	}

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	serverContainerName := fmt.Sprintf("%s-server", tName)
	clientContainerName := fmt.Sprintf("%s-client", tName)

	var nsTest string
	serverContainerOpts := []containers.ContainerOption{containers.WithContainerImage(DefaultServerImage)}
	clientContainerOpts := []containers.ContainerOption{containers.WithContainerImage(DefaultClientImage)}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		nsTest = utils.GenerateTestNamespaceName(t, tName)
		testutils.CreateK8sNamespace(t, nsTest)

		clientContainerOpts = append(clientContainerOpts, containers.WithContainerNamespace(nsTest))
		clientContainerOpts = append(clientContainerOpts, containers.WithUseExistingNamespace())
		serverContainerOpts = append(serverContainerOpts, containers.WithContainerNamespace(nsTest))
		serverContainerOpts = append(serverContainerOpts, containers.WithUseExistingNamespace())
	}

	serverContainer := containerFactory.NewContainer(serverContainerName, "/dnsbench server", serverContainerOpts...)
	serverContainer.Start(t)
	t.Cleanup(func() {
		serverContainer.Stop(t)
	})

	serverIP := serverContainer.IP()

	clientContainer := containerFactory.NewContainer(
		clientContainerName,
		fmt.Sprintf("/dnsbench client %s:5353 %d", serverIP, rps),
		clientContainerOpts...,
	)
	clientContainer.Start(t)
	t.Cleanup(func() {
		clientContainer.Stop(t)
	})

	//clientIP := clientContainer.IP()

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime), timeoutParam))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", nsTest), timeoutParam))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(nsTest)))
	}

	var traceDNSCmd igtesting.TestStep
	if usetracer {
		traceDNSCmd = igrunner.New("trace_dns", runnerOpts...)
	} else {
		traceDNSCmd = utils.Sleep(sleepTimeout)
	}

	cpu := utils.Cpu()
	mem := utils.Memory()

	steps := []igtesting.TestStep{
		// warm up
		utils.Sleep(5 * time.Second),

		// start capturing cpu and memory
		// TODO: is it right to start captuing here?
		cpu,
		mem,

		traceDNSCmd,
	}

	igtesting.RunTestSteps(steps, t, testingOpts...)

	return stat{
		cpu: cpu.Avg(),
		mem: mem.Avg(),
	}
}

func testTraceDNSMultiple(t *testing.T, rps int, usetracer bool) statResult {
	cpuValues := make([]float64, 0, NumRuns)
	memValues := make([]float64, 0, NumRuns)

	for i := 0; i < NumRuns; i++ {
		t.Run(fmt.Sprintf("rps=%d_usetracer=%t_run=%d", rps, usetracer, i+1), func(t *testing.T) {
			t.Logf("Running test %d/%d for rps=%d, usetracer=%t", i+1, NumRuns, rps, usetracer)
			result := testTraceDNS(t, rps, usetracer)
			cpuValues = append(cpuValues, result.cpu)
			memValues = append(memValues, result.mem)

			// Add a small delay between runs to avoid resource contention
			if i < NumRuns-1 {
				time.Sleep(2 * time.Second)
			}
		})
	}

	cpuMean, cpuCI := calculateStats(cpuValues)
	memMean, memCI := calculateStats(memValues)

	return statResult{
		cpuMean: cpuMean,
		cpuCI:   cpuCI,
		memMean: memMean,
		memCI:   memCI,
	}
}

func TestTraceDNS(t *testing.T) {
	rps := []int{ /*1024, 2048, 4096, 8192,*/ 16384, 32768, 65536}

	// Create CSV file
	file, err := os.Create("test_results.csv")
	require.NoError(t, err)
	defer file.Close()

	// Write CSV header
	writer := csv.NewWriter(file)
	defer writer.Flush()
	writer.Write([]string{"Name", "rps", "%cpu", "mem(MB)", "cpu_ci", "mem_ci", "runs"})

	for _, rpsValue := range rps {
		for _, useTracer := range []bool{false, true} {
			tName := "baseline"
			if useTracer {
				tName = "ig"
			}

			t.Logf("Starting test series for %s at %d RPS (%d runs)", tName, rpsValue, NumRuns)
			result := testTraceDNSMultiple(t, rpsValue, useTracer)

			writer.Write([]string{
				tName,
				strconv.Itoa(rpsValue),
				strconv.FormatFloat(result.cpuMean, 'f', 2, 64),
				strconv.FormatFloat(result.memMean, 'f', 2, 64),
				strconv.FormatFloat(result.cpuCI, 'f', 2, 64),
				strconv.FormatFloat(result.memCI, 'f', 2, 64),
				strconv.Itoa(NumRuns),
			})

			// Flush after each test to ensure data is written
			writer.Flush()
		}
	}
}
