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

package benchmarks

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	statsrecorder "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/stats"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

var benchmark = flag.Bool("benchmark", false, "run benchmark tests")

type BenchmarkConfig struct {
	Ntimes int `yaml:"ntimes"`
	//OutputFile        string                `yaml:"output_file"`
	IgPath            string                `yaml:"ig_path"`
	IgFlags           []string              `yaml:"ig_flags"`
	IgRuntime         string                `yaml:"ig_runtime"`
	GadgetTag         string                `yaml:"gadget_tag"`
	GadgetRunDuration int                   `yaml:"gadget_run_duration"`
	WarmUpDuration    int                   `yaml:"warm_up_duration"`
	Tests             map[string]TestConfig `yaml:"tests"`
}

type TestConfig struct {
	GadgetName      string          `yaml:"gadgetName"`
	Server          *ServerConfig   `yaml:"server,omitempty"`
	Generator       GeneratorConfig `yaml:"generator"`
	EventsPerSecond []int           `yaml:"eventsPerSecond"`
	GadgetParams    []string        `yaml:"gadgetParams,omitempty"`
}

type ServerConfig struct {
	Image string `yaml:"image"`
	Cmd   string `yaml:"cmd"`
}

type GeneratorConfig struct {
	Image string `yaml:"image"`
	Cmd   string `yaml:"cmd"`
}

func TestMain(m *testing.M) {
	flag.Parse()

	if !*benchmark {
		fmt.Println("Skipping benchmark tests")
		os.Exit(0)
	}

	fmt.Println("Running benchmark tests")
	os.Exit(m.Run())
}

func TestBenchmarks(t *testing.T) {
	configData, err := os.ReadFile("benchmarks.yaml")
	require.NoError(t, err, "failed to read benchmarks.yaml")

	var config BenchmarkConfig
	err = yaml.Unmarshal(configData, &config)
	require.NoError(t, err, "failed to parse benchmarks.yaml")

	// Calculate total number of runs
	totalRuns := 0
	for _, testConfig := range config.Tests {
		totalRuns += len(testConfig.EventsPerSecond) * 2 * config.Ntimes // 2 for baseline + IG
	}

	// set up the environment for benchmarks
	t.Setenv("IG_PATH", config.IgPath)
	t.Setenv("IG_FLAGS", strings.Join(config.IgFlags, " "))
	t.Setenv("IG_RUNTIME", config.IgRuntime)
	t.Setenv("GADGET_TAG", config.GadgetTag)

	filePath := fmt.Sprintf("test_results_%s.csv", time.Now().Format("20060102_150405"))
	file, err := os.Create(filePath)
	require.NoError(t, err)
	defer file.Close()

	r := RunResult{}
	_, err = file.WriteString(r.HeaderString() + "\n")
	require.NoError(t, err, "failed to write header to file")

	currentRun := 0

	for gadgetName, testConfig := range config.Tests {
		t.Run(gadgetName, func(t *testing.T) {
			for _, eventsPerSecond := range testConfig.EventsPerSecond {
				// TODO: another t.run for each RPS value?
				for _, useTracer := range []bool{false, true} {
					tName := "baseline"
					if useTracer {
						tName = "ig"
					}

					t.Logf("Starting test series for %s at %d RPS (%d runs)", tName, eventsPerSecond, config.Ntimes)

					for i := 0; i < config.Ntimes; i++ {
						currentRun++
						remainingRuns := totalRuns - currentRun
						t.Run(fmt.Sprintf("comb=%v_usetracer=%t_run=%d", eventsPerSecond, useTracer, i+1), func(t *testing.T) {
							t.Logf("Running test %d/%d for comb=%d, usetracer=%t (Run %d of %d, %d remaining: %2.f%%)",
								i+1, config.Ntimes, eventsPerSecond, useTracer, currentRun, totalRuns, remainingRuns, 100.0*float64(currentRun)/float64(totalRuns))
							result := testGadgetSingle(t, &config, &testConfig, eventsPerSecond, useTracer)
							result.GadgetName = testConfig.GadgetName
							result.TestName = tName
							result.Run = i + 1
							result.EventsPerSecond = eventsPerSecond

							resultStr := result.String()
							fmt.Printf("Test result: %s\n", resultStr)
							_, err := file.WriteString(resultStr + "\n")
							require.NoError(t, err, "failed to write result to file")
						})
					}
				}
			}
		})
	}
}

type linesCounter struct {
	lines uint64
}

func (c *linesCounter) Write(p []byte) (n int, err error) {
	// Count the number of lines in the input
	for _, b := range p {
		if b == '\n' {
			c.lines++
		}
	}
	return len(p), nil
}

// singleRunResult holds the results of a single run of a gadget test
type RunResult struct {
	GadgetName      string
	TestName        string
	Run             int
	EventsPerSecond int
	Cpu             float64
	Mem             float64
	IgCpu           float64
	IgMem           float64
	Lost            uint64
}

func (r *RunResult) HeaderString() string {
	// format as csv header line
	return "GadgetName,TestName,Run,EventsPerSecond,Cpu,Mem,IgCpu,IgMem,Lost"
}

func (r *RunResult) String() string {
	// format as csv line
	return fmt.Sprintf("%s,%s,%d,%d,%.2f,%.2f,%.2f,%.2f,%d",
		r.GadgetName,
		r.TestName,
		r.Run,
		r.EventsPerSecond,
		r.Cpu,
		r.Mem,
		r.IgCpu,
		r.IgMem,
		r.Lost,
	)
}

func testGadgetSingle(t *testing.T, bc *BenchmarkConfig, tc *TestConfig, conf any, usetracer bool) RunResult {
	tName := fmt.Sprintf("test-%s", tc.GadgetName)

	runDuration := bc.GadgetRunDuration
	timeoutParam := fmt.Sprintf("--timeout=%d", runDuration)
	sleepTimeout := time.Duration(runDuration) * time.Second
	warmUpTimeout := time.Duration(bc.WarmUpDuration) * time.Second
	// TODO: is it fine?
	cpuAndMemoryInitialDelay := (time.Duration(runDuration) * time.Second) / 4

	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	serverContainerName := fmt.Sprintf("%s-server", tName)
	clientContainerName := fmt.Sprintf("%s-client", tName)

	var nsTest string
	// serverContainerOpts := []containers.ContainerOption{containers.WithContainerImage(tc.ServerImage)}
	clientContainerOpts := []containers.ContainerOption{containers.WithContainerImage(tc.Generator.Image)}

	// TODO: kubectl support is future work
	//	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
	//		nsTest = utils.GenerateTestNamespaceName(t, tName)
	//		testutils.CreateK8sNamespace(t, nsTest)
	//
	//		clientContainerOpts = append(clientContainerOpts, containers.WithContainerNamespace(nsTest))
	//		clientContainerOpts = append(clientContainerOpts, containers.WithUseExistingNamespace())
	//		serverContainerOpts = append(serverContainerOpts, containers.WithContainerNamespace(nsTest))
	//		serverContainerOpts = append(serverContainerOpts, containers.WithUseExistingNamespace())
	//	}

	var serverIP string

	if tc.Server != nil {
		serverContainerOpts := []containers.ContainerOption{containers.WithContainerImage(tc.Server.Image)}
		serverContainer := containerFactory.NewContainer(serverContainerName, tc.Server.Cmd, serverContainerOpts...)
		serverContainer.Start(t)
		t.Cleanup(func() {
			serverContainer.Stop(t)
		})

		serverIP = serverContainer.IP()
	}

	clientCmd := tc.Generator.Cmd
	// Replace placeholders with actual values
	clientCmd = strings.ReplaceAll(clientCmd, "{serverIP}", serverIP)
	clientCmd = strings.ReplaceAll(clientCmd, "{eventsPerSecond}", fmt.Sprintf("%d", conf))

	clientContainer := containerFactory.NewContainer(
		clientContainerName,
		clientCmd,
		clientContainerOpts...,
	)
	clientContainer.Start(t)
	t.Cleanup(func() {
		clientContainer.Stop(t)
	})

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime), timeoutParam))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", nsTest), timeoutParam))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(nsTest)))
	}

	runnerOpts = append(runnerOpts, igrunner.WithFlags(tc.GadgetParams...))

	lost := uint64(0)

	var gadgetCmd igtesting.TestStep
	var lWriter *linesCounter
	if usetracer {
		// Count dropped events.
		runnerOpts = append(runnerOpts, igrunner.WithValidateStderrOutput(func(t *testing.T, output string) {
			// Parse output to count lost samples
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "lost") && strings.Contains(line, "samples") {
					// Extract number from "lost <number> samples"
					parts := strings.Fields(line)
					for i, part := range parts {
						if part == "lost" && i+1 < len(parts) {
							if num, err := strconv.ParseUint(parts[i+1], 10, 64); err == nil {
								lost += num
							}
							break
						}
					}
				}
			}
		}))

		// check that the gadget captured data
		lWriter = &linesCounter{}
		runnerOpts = append(runnerOpts, igrunner.WithStdOutWriter(lWriter))
		gadgetCmd = igrunner.New(tc.GadgetName, runnerOpts...)
	} else {
		gadgetCmd = utils.Sleep(sleepTimeout)
	}

	initialDelay := cpuAndMemoryInitialDelay // Start capturing CPU and memory after an initial delay to avoid initial spikes
	if !usetracer {
		// If not using tracer, we can start capturing immediately
		initialDelay = 0
	}

	opts := []statsrecorder.Option{
		statsrecorder.WithInitialDelay(initialDelay),
	}

	if usetracer {
		opts = append(opts, statsrecorder.WithComms([]string{"ig"}))
	}

	// skip beginning and end of the run to avoid initial spikes
	cpuAndMemory := statsrecorder.New(runDuration-2*int(initialDelay.Seconds()), opts...)

	steps := []igtesting.TestStep{
		// warm up
		utils.Sleep(warmUpTimeout),

		cpuAndMemory,
		gadgetCmd,
	}

	igtesting.RunTestSteps(steps, t, testingOpts...)

	// TODO: how to associate to the number of generated events?
	if lWriter != nil {
		require.Greater(t, lWriter.lines, uint64(0), "Gadget %s should have captured some data", tc.GadgetName)
	}

	cpuAndMemoryAvg := cpuAndMemory.Stats()

	ret := RunResult{
		//GadgetName: tc.GadgetName,
		Cpu:  cpuAndMemoryAvg.System.CPUPercentage,
		Mem:  float64(cpuAndMemoryAvg.System.Memory) / (1024 * 1024),
		Lost: lost / uint64(runDuration), // Convert lost events to per second
	}

	if usetracer {
		require.Contains(t, cpuAndMemoryAvg.Processes, "ig", "IG should be running")
		igStats := cpuAndMemoryAvg.Processes["ig"]
		ret.IgCpu = igStats.CPUPercentage
		ret.IgMem = float64(igStats.Memory) / (1024 * 1024)
	}

	return ret
}
