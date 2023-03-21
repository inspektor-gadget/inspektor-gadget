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

// Package gadgets provides benchmarks for all gadgets. They can be executed
// with the command:
//
//	$ make gadgets-benchmarks
//
// Results are published automatically by the GitHub Action:
// https://inspektor-gadget.github.io/ig-benchmarks/dev/bench/index.html
package gadgets

import (
	"context"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"

	// TODO: find out why those gadgets don't work in the tests
	// _ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/block-io/tracer"
	// _ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/block-io/tracer"

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
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpdrop/tracer"
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

// BenchmarkAllGadgetsWithContainers measures the performance of all gadget
// startups with various amount of containers.
func BenchmarkAllGadgetsWithContainers(b *testing.B) {
	utilstest.RequireRoot(b)

	// Prepare runtime
	runtime := local.New()
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

				categoryAndName := fmt.Sprintf("%s-%s", gadgetDesc.Category(), gadgetDesc.Name())
				b.Run(categoryAndName, func(b *testing.B) {
					for n := 0; n < b.N; n++ {
						// This benchmark only measure gadget startup time.
						// Use a timeout of 0s, so it will immediately timeout
						// and runtime.RunGadget() will be stopped immediately
						// via '<-gadgetCtx.Context().Done()' once the gadget
						// is started.
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
							runtime.ParamDescs().ToParams(),
							gadgetDesc,
							gadgetParams,
							operatorsParamCollection,
							parser,
							logger.DefaultLogger(),
							0,
						)

						_, err := runtime.RunGadget(gadgetCtx)
						if err != nil {
							b.Fatalf("running gadget: %s", err)
						}

						gadgetCtx.Cancel()
						cancel()
					}
				})
			}
		})
	}
}
