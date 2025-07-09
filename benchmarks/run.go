package benchmark

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
	DefaultNRuns = 5
)

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

type GadgetBenchTest struct {
	Gadget       string
	GadgetParams []string

	GeneratorImage string
	GeneratorCmd   func(serverIP string, conf any) string

	// TestConfs is a list of test configurations to run. Cmd is called with each
	// configuration in the list.
	TestConfs []any

	// Optional: some tests require a server, this is used to define a container
	// that is executed before running the test container above. The IP address
	// of this container is passed to the ClientCmd function.
	ServerImage string
	ServerCmd   func(conf any) string
}

func testGadgetSingle(t *testing.T, c *GadgetBenchTest, conf any, usetracer bool) stat {
	tName := fmt.Sprintf("test-%s", c.Gadget)

	// TODO: make all of this configurable
	const timeoutParam = "--timeout=15"
	const sleepTimeout = 15 * time.Second
	const warmUpTimeout = 5 * time.Second
	const cpuAndMemoryInitialDelay = 5 * time.Second

	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	//if utils.CurrentTestComponent == utils.IgLocalTestComponent && utils.Runtime == "containerd" {
	//	t.Skip("Skipping test as containerd test utils can't use the network")
	//}

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	serverContainerName := fmt.Sprintf("%s-server", tName)
	clientContainerName := fmt.Sprintf("%s-client", tName)

	var nsTest string
	serverContainerOpts := []containers.ContainerOption{containers.WithContainerImage(c.ServerImage)}
	clientContainerOpts := []containers.ContainerOption{containers.WithContainerImage(c.GeneratorImage)}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		nsTest = utils.GenerateTestNamespaceName(t, tName)
		testutils.CreateK8sNamespace(t, nsTest)

		clientContainerOpts = append(clientContainerOpts, containers.WithContainerNamespace(nsTest))
		clientContainerOpts = append(clientContainerOpts, containers.WithUseExistingNamespace())
		serverContainerOpts = append(serverContainerOpts, containers.WithContainerNamespace(nsTest))
		serverContainerOpts = append(serverContainerOpts, containers.WithUseExistingNamespace())
	}

	var serverIP string

	if c.ServerCmd != nil {

		serverCmd := c.ServerCmd(conf)
		serverContainer := containerFactory.NewContainer(serverContainerName, serverCmd, serverContainerOpts...)
		serverContainer.Start(t)
		t.Cleanup(func() {
			serverContainer.Stop(t)
		})

		serverIP = serverContainer.IP()
	}

	clientCmd := c.GeneratorCmd(serverIP, conf)
	clientContainer := containerFactory.NewContainer(
		clientContainerName,
		clientCmd,
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

	runnerOpts = append(runnerOpts, igrunner.WithFlags(c.GadgetParams...))

	var gadgetCmd igtesting.TestStep
	var lWriter *linesCounter
	if usetracer {
		// Check the gadget didn't drop any sample.
		runnerOpts = append(runnerOpts, igrunner.WithValidateStderrOutput(func(t *testing.T, output string) {
			require.NotContains(t, output, "lost", "Gadget output should not contain 'dropped' messages")
		}))

		// check that the gadget captured data
		lWriter = &linesCounter{}
		runnerOpts = append(runnerOpts, igrunner.WithStdWriter(lWriter))
		gadgetCmd = igrunner.New(c.Gadget, runnerOpts...)
	} else {
		gadgetCmd = utils.Sleep(sleepTimeout)
	}

	initialDelay := cpuAndMemoryInitialDelay // Start capturing CPU and memory after an initial delay to avoid initial spikes
	if !usetracer {
		// If not using tracer, we can start capturing immediately
		initialDelay = 0
	}
	cpu := utils.Cpu(initialDelay)
	mem := utils.Memory(initialDelay)

	steps := []igtesting.TestStep{
		// warm up
		utils.Sleep(warmUpTimeout),

		cpu,
		mem,

		gadgetCmd,
	}

	igtesting.RunTestSteps(steps, t, testingOpts...)

	// TODO: how to associate to the number of generated events?
	if lWriter != nil {
		require.Greater(t, lWriter.lines, uint64(0), "Gadget %s should have captured some data", c.Gadget)
	}

	return stat{
		cpu: cpu.Avg(),
		mem: mem.Avg(),
	}
}

func testGadgetMultiple(t *testing.T, c *GadgetBenchTest, comb any, usetracer bool, nRuns int) statResult {
	cpuValues := make([]float64, 0, nRuns)
	memValues := make([]float64, 0, nRuns)

	for i := 0; i < nRuns; i++ {
		t.Run(fmt.Sprintf("comb=%v_usetracer=%t_run=%d", comb, usetracer, i+1), func(t *testing.T) {
			t.Logf("Running test %d/%d for comb=%d, usetracer=%t", i+1, nRuns, comb, usetracer)
			result := testGadgetSingle(t, c, comb, usetracer)
			cpuValues = append(cpuValues, result.cpu)
			memValues = append(memValues, result.mem)
		})
	}

	cpuMean, cpuCI := CalculateStats(cpuValues)
	fmt.Printf("CPU Mean: %.2f, CPU CI: %.2f\n", cpuMean, cpuCI)

	memMean, memCI := CalculateStats(memValues)

	return statResult{
		cpuMean: cpuMean,
		cpuCI:   cpuCI,
		memMean: memMean,
		memCI:   memCI,
	}
}

func RunGadgetBenchmark(t *testing.T, c *GadgetBenchTest) {
	t.Helper()

	nRums := DefaultNRuns
	if os.Getenv("IG_N_RUNS") != "" {
		var err error
		nRums, err = strconv.Atoi(os.Getenv("IG_N_RUNS"))
		require.NoError(t, err, "failed to parse IG_N_RUNS environment variable")
	}

	filePath := fmt.Sprintf("test_results_%s.csv", c.Gadget)
	if os.Getenv("IG_OUTPUT_FOLDER") != "" {
		filePath = fmt.Sprintf("%s/%s", os.Getenv("IG_OUTPUT_FOLDER"), filePath)
	}

	file, err := os.Create(filePath)
	require.NoError(t, err)
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()
	writer.Write([]string{"Name", "rps", "%cpu", "mem(MB)", "cpu_ci", "mem_ci", "runs"})

	for _, comb := range c.TestConfs {
		for _, useTracer := range []bool{false, true} {
			tName := "baseline"
			if useTracer {
				tName = "ig"
			}

			t.Logf("Starting test series for %s at %d RPS (%d runs)", tName, comb, nRums)

			result := testGadgetMultiple(t, c, comb, useTracer, nRums)

			writer.Write([]string{
				tName,
				fmt.Sprintf("%v", comb),
				//strconv.Itoa(rpsValue),
				strconv.FormatFloat(result.cpuMean, 'f', 2, 64),
				strconv.FormatFloat(result.memMean, 'f', 2, 64),
				strconv.FormatFloat(result.cpuCI, 'f', 2, 64),
				strconv.FormatFloat(result.memCI, 'f', 2, 64),
				strconv.Itoa(nRums),
			})

			// Flush after each test to ensure data is written
			writer.Flush()
		}
	}
}

// calculateStats calculates mean and 95% confidence interval for a slice of values
func CalculateStats(values []float64) (mean, ci float64) {
	if len(values) == 0 {
		return 0, 0
	}

	// Calculate mean
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean = sum / float64(len(values))

	if len(values) == 1 {
		// If only one value, confidence interval is not defined
		return mean, 0
	}

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
