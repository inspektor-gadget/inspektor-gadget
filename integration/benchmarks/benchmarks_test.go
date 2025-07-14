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
	"os/exec"
	"runtime"
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
	Ntimes            int          `yaml:"ntimes"`
	IgPath            string       `yaml:"igPath"`
	IgFlags           []string     `yaml:"igFlags"`
	IgRuntime         string       `yaml:"igRuntime"`
	GadgetRunDuration int          `yaml:"gadgetRunDuration"`
	WarmUpDuration    int          `yaml:"warmUpDuration"`
	Tests             []TestConfig `yaml:"tests"`
}

type TestConfig struct {
	Name            string           `yaml:"name"`
	GadgetName      string           `yaml:"gadgetName"`
	Server          *ContainerConfig `yaml:"server,omitempty"`
	Generator       ContainerConfig  `yaml:"generator"`
	EventsPerSecond []int            `yaml:"eventsPerSecond"`
	GadgetParams    []string         `yaml:"gadgetParams,omitempty"`
}

type ContainerConfig struct {
	Image   string            `yaml:"image"`
	Cmd     string            `yaml:"cmd"`
	Sysctls map[string]string `yaml:"sysctls,omitempty"`
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

// getMachineSpecs gathers system specifications for the benchmark
func getMachineSpecs() string {
	specs := []string{}

	// Get processor information
	if cpuInfo, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		lines := strings.Split(string(cpuInfo), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "model name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					specs = append(specs, fmt.Sprintf("# Processor: %s", strings.TrimSpace(parts[1])))
					break
				}
			}
		}
	}

	// Get memory information
	if memInfo, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.Split(string(memInfo), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if memKB, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
						memGB := float64(memKB) / (1024 * 1024)
						specs = append(specs, fmt.Sprintf("# Memory: %.1f GB", memGB))
					}
				}
				break
			}
		}
	}

	// Get Linux distribution
	if osRelease, err := os.ReadFile("/etc/os-release"); err == nil {
		lines := strings.Split(string(osRelease), "\n")
		var name, version string
		for _, line := range lines {
			if strings.HasPrefix(line, "NAME=") {
				name = strings.Trim(strings.TrimPrefix(line, "NAME="), "\"")
			} else if strings.HasPrefix(line, "VERSION=") {
				version = strings.Trim(strings.TrimPrefix(line, "VERSION="), "\"")
			}
		}
		if name != "" {
			distro := name
			if version != "" {
				distro += " " + version
			}
			specs = append(specs, fmt.Sprintf("# Distribution: %s", distro))
		}
	}

	// Get kernel version
	if cmd := exec.Command("uname", "-r"); cmd != nil {
		if output, err := cmd.Output(); err == nil {
			kernel := strings.TrimSpace(string(output))
			specs = append(specs, fmt.Sprintf("# Kernel: %s", kernel))
		}
	}

	// Get Go version and architecture
	specs = append(specs, fmt.Sprintf("# Go Version: %s", runtime.Version()))
	specs = append(specs, fmt.Sprintf("# Architecture: %s", runtime.GOARCH))

	// Add timestamp
	specs = append(specs, fmt.Sprintf("# Benchmark Date: %s", time.Now().Format("2006-01-02 15:04:05 MST")))

	return strings.Join(specs, "\n") + "\n"
}

func TestBenchmarks(t *testing.T) {
	configData, err := os.ReadFile("benchmarks.yaml")
	require.NoError(t, err, "failed to read benchmarks.yaml")

	var config BenchmarkConfig
	err = yaml.Unmarshal(configData, &config)
	require.NoError(t, err, "failed to parse benchmarks.yaml")

	// validate some things before runnning
	// Other runtimes don't check if the workload finished correctly.
	require.Equal(t, "docker", config.IgRuntime, "only docker runtime is supported for benchmarks")

	// Calculate total number of runs
	totalRuns := 0
	for _, testConfig := range config.Tests {
		totalRuns += len(testConfig.EventsPerSecond) * 2 * config.Ntimes // 2 for baseline + IG
	}

	// set up the environment for benchmarks
	t.Setenv("IG_PATH", config.IgPath)
	t.Setenv("IG_FLAGS", strings.Join(config.IgFlags, " "))
	t.Setenv("IG_RUNTIME", config.IgRuntime)

	filePath := fmt.Sprintf("test_results_%s.csv", time.Now().Format("20060102_150405"))
	file, err := os.Create(filePath)
	require.NoError(t, err)
	defer file.Close()

	// Write machine specifications as comments at the beginning
	machineSpecs := getMachineSpecs()
	_, err = file.WriteString(machineSpecs)
	require.NoError(t, err, "failed to write machine specs to file")

	r := RunResult{}
	_, err = file.WriteString(r.HeaderString() + "\n")
	require.NoError(t, err, "failed to write header to file")

	currentRun := 0

	for _, testConfig := range config.Tests {
		t.Run(testConfig.Name, func(t *testing.T) {
			for _, eventsPerSecond := range testConfig.EventsPerSecond {
				// TODO: another t.run for each RPS value?
				for _, useTracer := range []bool{false, true} {
					tCase := "baseline"
					if useTracer {
						tCase = "ig"
					}

					t.Logf("Starting test series for %s at %d RPS (%d runs)", tCase, eventsPerSecond, config.Ntimes)

					for i := 0; i < config.Ntimes; i++ {
						currentRun++
						t.Run(fmt.Sprintf("comb=%v_usetracer=%t_run=%d", eventsPerSecond, useTracer, i+1), func(t *testing.T) {
							t.Logf("Running test %d/%d for comb=%d, usetracer=%t (Run %d of %d: %2.f%%)",
								i+1, config.Ntimes, eventsPerSecond, useTracer, currentRun, totalRuns, 100.0*float64(currentRun)/float64(totalRuns))
							result := testGadgetSingle(t, &config, &testConfig, eventsPerSecond, useTracer)
							result.TestName = testConfig.Name
							result.TestCase = tCase
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
	TestName        string
	TestCase        string
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
	return "TestName,TestCase,Run,EventsPerSecond,Cpu,Mem,IgCpu,IgMem,Lost"
}

func (r *RunResult) String() string {
	// format as csv line
	return fmt.Sprintf("%s,%s,%d,%d,%.2f,%.2f,%.2f,%.2f,%d",
		r.TestName,
		r.TestCase,
		r.Run,
		r.EventsPerSecond,
		r.Cpu,
		r.Mem,
		r.IgCpu,
		r.IgMem,
		r.Lost,
	)
}

func testGadgetSingle(t *testing.T, bc *BenchmarkConfig, tc *TestConfig, eventsPerSecond int, usetracer bool) RunResult {
	tName := fmt.Sprintf("test-%s", tc.Name)

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
	clientContainerOpts := []containers.ContainerOption{
		containers.WithContainerImage(tc.Generator.Image),
		containers.WithSysctls(tc.Generator.Sysctls),
		containers.WithExpectedExitCode(0),
	}

	// TODO: kubectl support is future work
	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		t.Skip("Skipping benchmark test in kubernetes for now")
	}

	var serverIP string

	if tc.Server != nil {
		serverContainerOpts := []containers.ContainerOption{
			containers.WithContainerImage(tc.Server.Image),
			containers.WithSysctls(tc.Server.Sysctls),
			containers.WithExpectedExitCode(0),
		}
		serverContainer := containerFactory.NewContainer(serverContainerName, tc.Server.Cmd, serverContainerOpts...)
		serverContainer.Start(t)
		defer serverContainer.Stop(t)

		serverIP = serverContainer.IP()
	}

	clientCmd := tc.Generator.Cmd
	// Replace placeholders with actual values
	clientCmd = strings.ReplaceAll(clientCmd, "{{.ServerIP}}", serverIP)
	clientCmd = strings.ReplaceAll(clientCmd, "{{.EventsPerSecond}}", fmt.Sprintf("%d", eventsPerSecond))

	clientContainer := containerFactory.NewContainer(
		clientContainerName,
		clientCmd,
		clientContainerOpts...,
	)
	clientContainer.Start(t)
	defer clientContainer.Stop(t)

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
	opts := []statsrecorder.Option{
		statsrecorder.WithInitialDelay(initialDelay),
	}

	if usetracer {
		opts = append(opts, statsrecorder.WithComms([]string{"ig"}))
	}

	// skip beginning and end of the run to avoid spikes.
	// runDuration is the total duration of the run, we need to subtract the
	// initial delay and the end of the run
	cpuAndMemory := statsrecorder.New(runDuration-2*int(initialDelay.Seconds()), opts...)

	steps := []igtesting.TestStep{
		// warm up
		utils.Sleep(warmUpTimeout),

		cpuAndMemory,
		gadgetCmd,
	}

	igtesting.RunTestSteps(steps, t, testingOpts...)

	if lWriter != nil {
		require.Greater(t, lWriter.lines, uint64(0), "Gadget %s should have captured some data", tc.GadgetName)

		// for tracers, check if they captured enough events
		if strings.HasPrefix(tc.GadgetName, "trace_") {
			require.Greater(t, float64(lWriter.lines), 0.95*float64(runDuration*eventsPerSecond))
		}
	}

	cpuAndMemoryAvg := cpuAndMemory.Stats()

	ret := RunResult{
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
