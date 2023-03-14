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

package gadgets

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/tracer"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"

	// TODO: find out why those gadgets don't work in the tests
	//_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/block-io/tracer"
	//_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/block-io/tracer"

	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/advise/seccomp/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/audit/seccomp/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/file/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/tcp/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/bind/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/fsslower/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/mount/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/oomkill/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/sni/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpconnect/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/traceloop/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

type Attacher interface {
	AttachContainer(container *containercollection.Container) error
	DetachContainer(*containercollection.Container) error
}

type MountNsMapSetter interface {
	SetMountNsMap(*ebpf.Map)
}

type TestOperator struct{}

type TestOperatorContext string

func (t *TestOperator) Name() string {
	return "TestOperator"
}

func (t *TestOperator) Description() string {
	return "TestOperator allows to run tests with many fake containers"
}

func (t *TestOperator) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (t *TestOperator) ParamDescs() params.ParamDescs {
	return nil
}

func (t *TestOperator) Dependencies() []string {
	return nil
}

func (t *TestOperator) CanOperateOn(desc gadgets.GadgetDesc) bool {
	// Accept all gadgets. Check for interfaces later in PreGadgetRun.
	return true
}

func (t *TestOperator) Init(params *params.Params) error {
	return nil
}

func (t *TestOperator) Close() error {
	return nil
}

func (t *TestOperator) Instantiate(gadgetContext operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	attacher, _ := gadgetInstance.(Attacher)
	mountNsMapSetter, _ := gadgetInstance.(MountNsMapSetter)
	return &TestOperatorInstance{
		TestOperator:     t, // for Name()
		attacher:         attacher,
		mountNsMapSetter: mountNsMapSetter,
		containers:       gadgetContext.Context().Value(TestOperatorContext("containers")).([]*containercollection.Container),
		testingTB:        gadgetContext.Context().Value(TestOperatorContext("testing.TB")).(testing.TB),
	}, nil
}

type TestOperatorInstance struct {
	*TestOperator
	attacher         Attacher
	mountNsMapSetter MountNsMapSetter
	containers       []*containercollection.Container
	testingTB        testing.TB
	tc               *tracercollection.TracerCollection
}

func (t *TestOperatorInstance) PreGadgetRun() error {
	if t.attacher != nil {
		for i := range t.containers {
			err := t.attacher.AttachContainer(t.containers[i])
			if err != nil {
				t.testingTB.Fatal(err)
			}
		}
	}
	if t.mountNsMapSetter != nil {
		tc, err := tracercollection.NewTracerCollectionTest(nil)
		if err != nil {
			t.testingTB.Fatal(err)
		}
		t.tc = tc
		tc.AddTracer("test-tracer", containercollection.ContainerSelector{})

		mountnsmap, err := tc.TracerMountNsMap("test-tracer")
		if err != nil {
			t.testingTB.Fatal(err)
		}
		t.mountNsMapSetter.SetMountNsMap(mountnsmap)
	}
	return nil
}

func (t *TestOperatorInstance) PostGadgetRun() error {
	if t.attacher != nil {
		for i := range t.containers {
			err := t.attacher.DetachContainer(t.containers[i])
			if err != nil {
				t.testingTB.Fatal(err)
			}

		}
	}
	if t.mountNsMapSetter != nil {
		t.tc.Close()
	}
	return nil
}

func (t *TestOperatorInstance) EnrichEvent(ev any) error {
	return nil
}

func init() {
	operators.Register(&TestOperatorInstance{})
}

func BenchmarkAllGadgetsWithContainers(b *testing.B) {
	utilstest.RequireRoot(b)

	// Prepare runtime
	runtime := &local.Runtime{}
	err := runtime.Init(nil)
	if err != nil {
		b.Fatalf("initializing runtime: %s", err)
	}
	defer runtime.Close()

	containerCounts := []int{0, 1, 10, 100}
	for _, containerCount := range containerCounts {
		b.Run(fmt.Sprintf("container%d", containerCount), func(b *testing.B) {
			// Prepare fake containers
			runnerConfig := &utilstest.RunnerConfig{}
			var containers []*containercollection.Container
			for i := 0; i < containerCount; i++ {
				runner := utilstest.NewRunnerWithTest(b, runnerConfig)
				container := &containercollection.Container{
					ID:    fmt.Sprintf("container%d", i),
					Mntns: runner.Info.MountNsID,
					Netns: runner.Info.NetworkNsID,
					Pid:   uint32(runner.Info.Tid),
				}
				containers = append(containers, container)
			}

			allGadgets := gadgetregistry.GetAll()

			for _, gadgetDesc := range allGadgets {
				gadgetDesc := gadgetDesc

				// Skip unwanted gadgets
				categoryAndName := fmt.Sprintf("%s-%s", gadgetDesc.Category(), gadgetDesc.Name())
				skipRegex := os.Getenv("IG_BENCHMARKS_GADGET_REGEX")
				if skipRegex != "" {
					matched, _ := regexp.Match(skipRegex, []byte(categoryAndName))
					if !matched {
						continue
					}
				}

				if _, ok := gadgetDesc.(gadgets.GadgetInstantiate); !ok {
					continue
				}

				validOperators := operators.GetOperatorsForGadget(gadgetDesc)
				operatorsParamCollection := validOperators.ParamCollection()

				err = validOperators.Init(nil)
				if err != nil {
					b.Fatalf("initializing operators: %s", err)
				}
				defer validOperators.Close()

				b.Run(categoryAndName, func(b *testing.B) {
					for n := 0; n < b.N; n++ {
						ctx, cancel := context.WithTimeout(context.TODO(), 0)
						ctx = context.WithValue(ctx, TestOperatorContext("containers"), containers)
						ctx = context.WithValue(ctx, TestOperatorContext("testing.TB"), b)

						paramDescs := gadgetDesc.ParamDescs()

						parser := gadgetDesc.Parser()
						if parser != nil {
							parser.SetEventCallback(func(any) {})
							paramDescs = append(paramDescs, gadgets.GadgetParams(gadgetDesc, parser)...)
						}

						gadgetParams := paramDescs.ToParams()

						gadgetCtx := gadgetcontext.New(
							ctx,
							"",
							runtime,
							gadgetDesc,
							gadgetParams,
							operatorsParamCollection,
							parser,
							logger.DefaultLogger(),
						)

						_, err := runtime.RunGadget(gadgetCtx)
						if err != nil {
							b.Fatalf("running gadget: %s", err)
						}

						cancel()
					}
				})
			}
		})
	}
}
func generateEvent(b *testing.B, categoryAndName string) error {
	switch categoryAndName {
	case "trace-open":
		fd, err := unix.Open("/dev/null", 0, 0)
		if err != nil {
			return fmt.Errorf("opening file: %w", err)
		}
		unix.Close(fd)

	case "trace-bind":
		bindSocketFn("127.0.0.1", unix.AF_INET, unix.SOCK_STREAM, 5556)()
	default:
		time.Sleep(time.Second)
	}
	return nil
}

// bindSocketFn returns a function that creates a socket, binds it and
// returns the port the socket was bound to.
func bindSocketFn(ipStr string, domain, typ int, port int) func() (uint16, error) {
	return func() (uint16, error) {
		return bindSocket(ipStr, domain, typ, port)
	}
}

func bindSocket(ipStr string, domain, typ int, port int) (uint16, error) {
	return bindSocketWithOpts(ipStr, domain, typ, port)
}

func bindSocketWithOpts(ipStr string, domain, typ int, port int) (uint16, error) {
	fd, err := unix.Socket(domain, typ, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	var sa unix.Sockaddr

	ip := net.ParseIP(ipStr)

	if ip.To4() != nil {
		sa4 := &unix.SockaddrInet4{Port: port}
		copy(sa4.Addr[:], ip.To4())
		sa = sa4
	} else if ip.To16() != nil {
		sa6 := &unix.SockaddrInet6{Port: port}
		copy(sa6.Addr[:], ip.To16())
		sa = sa6
	} else {
		return 0, fmt.Errorf("invalid IP address")
	}

	if err := unix.Bind(fd, sa); err != nil {
		return 0, fmt.Errorf("Bind: %w", err)
	}

	sa2, err := unix.Getsockname(fd)
	if err != nil {
		return 0, fmt.Errorf("Getsockname: %w", err)
	}

	if ip.To4() != nil {
		return uint16(sa2.(*unix.SockaddrInet4).Port), nil
	} else if ip.To16() != nil {
		return uint16(sa2.(*unix.SockaddrInet6).Port), nil
	} else {
		return 0, fmt.Errorf("invalid IP address")
	}
}

func BenchmarkAllGadgetsWithEvents(b *testing.B) {
	utilstest.RequireRoot(b)

	// Prepare runtime
	runtime := &local.Runtime{}
	err := runtime.Init(nil)
	if err != nil {
		b.Fatalf("initializing runtime: %s", err)
	}
	defer runtime.Close()

	// Prepare fake container
	runnerConfig := &utilstest.RunnerConfig{}
	var containers []*containercollection.Container
	runner := utilstest.NewRunnerWithTest(b, runnerConfig)
	container := &containercollection.Container{
		ID:    "container1",
		Mntns: runner.Info.MountNsID,
		Netns: runner.Info.NetworkNsID,
		Pid:   uint32(runner.Info.Tid),
	}
	containers = append(containers, container)

	allGadgets := gadgetregistry.GetAll()

	for _, gadgetDesc := range allGadgets {
		gadgetDesc := gadgetDesc

		// Skip unwanted gadgets
		categoryAndName := fmt.Sprintf("%s-%s", gadgetDesc.Category(), gadgetDesc.Name())
		skipRegex := os.Getenv("IG_BENCHMARKS_GADGET_REGEX")
		if skipRegex != "" {
			matched, _ := regexp.Match(skipRegex, []byte(categoryAndName))
			if !matched {
				continue
			}
		}

		if _, ok := gadgetDesc.(gadgets.GadgetInstantiate); !ok {
			continue
		}

		validOperators := operators.GetOperatorsForGadget(gadgetDesc)
		operatorsParamCollection := validOperators.ParamCollection()

		err = validOperators.Init(nil)
		if err != nil {
			b.Fatalf("initializing operators: %s", err)
		}
		defer validOperators.Close()

		b.Run(categoryAndName, func(b *testing.B) {
			ctx, cancel := context.WithCancel(context.TODO())
			ctx = context.WithValue(ctx, TestOperatorContext("containers"), containers)
			ctx = context.WithValue(ctx, TestOperatorContext("testing.TB"), b)

			paramDescs := gadgetDesc.ParamDescs()

			parser := gadgetDesc.Parser()
			if parser != nil {
				parser.SetEventCallback(func(any) {})
				paramDescs = append(paramDescs, gadgets.GadgetParams(gadgetDesc, parser)...)
			}

			gadgetParams := paramDescs.ToParams()

			gadgetCtx := gadgetcontext.New(
				ctx,
				"",
				runtime,
				gadgetDesc,
				gadgetParams,
				operatorsParamCollection,
				parser,
				logger.DefaultLogger(),
			)

			config := &tracer.Config{
				MaxRows:  0,   // no max
				Interval: 0,   // no ticker
				SortBy:   nil, // no need to sort
			}
			ebpftracer, err := tracer.NewTracer(config, nil, nil)
			if err != nil {
				b.Fatalf("starting ebpf tracer: %s", err)
			}

			// Due to the way the tracer works, it needs to be called once to
			// initialize startStats
			_, _ = ebpftracer.NextStats()

			var wg sync.WaitGroup
			go func() {
				wg.Add(1)
				defer wg.Done()
				_, err = runtime.RunGadget(gadgetCtx)
				if err != nil {
					b.Fatalf("running gadget: %s", err)
				}
			}()

			// Wait until runtime.RunGadget() has finished starting with Start()
			// TODO: Fix RunGadget() so we can get notified without sleeping.
			time.Sleep(time.Second)

			// This benchmark is not about the setup time but about measuring
			// event processing in ebpf
			b.ResetTimer()

			for n := 0; n < b.N; n++ {
				utilstest.RunWithRunner(b, runner, func() error {
					return generateEvent(b, categoryAndName)
				})

			}
			stats, err := ebpftracer.NextStats()
			if err != nil {
				b.Fatalf("reading stats from ebpf tracer: %s", err)
			}
			totalRuntime := int64(0)
			totalRunCount := uint64(0)
			for _, stat := range stats {
				ours := false
				if stat.Name == "ig_top_ebpf_it" {
					continue
				}
				for _, p := range stat.Processes {
					if int(p.Pid) == os.Getpid() {
						ours = true
					}
				}
				if ours {
					//fmt.Printf("%s: program %s: runtime=%d runcount=%d (N=%d)\n",
					//	categoryAndName, stat.Name,
					//	stat.CumulativeRuntime, stat.CumulativeRunCount,
					//	b.N)
					totalRuntime += stat.CumulativeRuntime
					totalRunCount += stat.CumulativeRunCount
				}
			}

			cancel()
			wg.Wait()

			b.ReportMetric(float64(totalRuntime)/float64(b.N), "ebpfns/op")
			b.ReportMetric(float64(totalRunCount)/float64(b.N), "ebpfexec/op")
			//fmt.Printf("%s: Reporting %d/%d %d/%d\n",
			//	categoryAndName, totalRuntime, b.N, totalRunCount, b.N)
		})
	}
}
