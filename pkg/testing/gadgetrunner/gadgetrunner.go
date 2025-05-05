// Copyright 2024 The Inspektor Gadget authors
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

package gadgetrunner

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"

	// TODO: create a common package with all operators
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/filter"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/formatters"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/limiter"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/socketenricher"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/sort"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/uidgidresolver"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/wasm"
)

type GadgetRunnerOpts[T any] struct {
	Image              string
	Timeout            time.Duration
	MntnsFilterMap     *ebpf.Map
	ParamValues        api.ParamValues
	GlobalParamsValues api.ParamValues

	OnGadgetRun     func(gadgetCtx operators.GadgetContext) error
	BeforeGadgetRun func() error
	NormalizeEvent  func(event *T)
}

type GadgetRunner[T any] struct {
	image             string
	timeout           time.Duration
	mntnsFilterMap    *ebpf.Map
	paramValues       api.ParamValues
	globalParamValues api.ParamValues
	runtimeParams     *params.Params
	testCtx           *testing.T

	gadgetCtx     *gadgetcontext.GadgetContext
	DataFunc      datasource.DataFunc
	DataOperator  []operators.DataOperator
	JsonFormatter *igjson.Formatter

	CapturedEvents  []T
	onGadgetRun     func(gadgetCtx operators.GadgetContext) error
	beforeGadgetRun func() error
	normalizeEvent  func(event *T)
}

func NewGadgetRunner[T any](t *testing.T, opts GadgetRunnerOpts[T]) *GadgetRunner[T] {
	if opts.Image == "" {
		require.Fail(t, "invalid image name")
		return nil
	}
	if opts.Timeout <= 0 {
		require.Fail(t, "invalid timeout")
		return nil
	}

	verifyImage := strings.ToLower(os.Getenv("IG_VERIFY_IMAGE"))
	if verifyImage == "true" || verifyImage == "false" {
		if opts.GlobalParamsValues == nil {
			opts.GlobalParamsValues = map[string]string{
				"operator.oci.verify-image": verifyImage,
			}
		} else {
			opts.GlobalParamsValues["operator.oci.verify-image"] = verifyImage
		}
	}

	gadgetImage := GetGadgetImageName(opts.Image)
	return &GadgetRunner[T]{
		image:             gadgetImage,
		timeout:           opts.Timeout,
		paramValues:       opts.ParamValues,
		globalParamValues: opts.GlobalParamsValues,
		CapturedEvents:    make([]T, 0),
		mntnsFilterMap:    opts.MntnsFilterMap,
		testCtx:           t,

		onGadgetRun:     opts.OnGadgetRun,
		beforeGadgetRun: opts.BeforeGadgetRun,
		normalizeEvent:  opts.NormalizeEvent,
	}
}

func (g *GadgetRunner[T]) RunGadget() {
	var mu sync.Mutex
	if g.DataFunc == nil {
		// Use default data function if none is provided
		g.DataFunc = func(source datasource.DataSource, data datasource.Data) error {
			mu.Lock()
			event := new(T)
			jsonOutput := g.JsonFormatter.Marshal(data)
			err := json.Unmarshal(jsonOutput, event)
			require.NoError(g.testCtx, err, "unmarshalling event")

			if g.normalizeEvent != nil {
				g.normalizeEvent(event)
			}

			g.CapturedEvents = append(g.CapturedEvents, *event)
			mu.Unlock()
			return nil
		}
	}
	gadgetOperatorOpts := []simple.Option{
		simple.WithPriority(math.MaxInt), // This operator is a sink
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				jsonFormatter, err := igjson.New(d,
					igjson.WithShowAll(true),
				)
				require.NoError(g.testCtx, err, "json formatter error")
				g.JsonFormatter = jsonFormatter
				d.Subscribe(g.DataFunc, 50000)
			}
			return nil
		}),
	}
	if g.mntnsFilterMap != nil {
		gadgetOperatorOpts = append(gadgetOperatorOpts,
			// On PreStart set the mount ns filter map
			simple.OnPreStart(func(gadgetCtx operators.GadgetContext) error {
				gadgetCtx.SetVar(gadgets.MntNsFilterMapName, g.mntnsFilterMap)
				gadgetCtx.SetVar(gadgets.FilterByMntNsName, true)

				return nil
			}),
		)
	}
	// Only add OnStart option if OnGadgetRun is defined
	if g.onGadgetRun != nil {
		gadgetOperatorOpts = append(gadgetOperatorOpts, simple.OnStart(g.onGadgetRun))
	}

	g.DataOperator = append(g.DataOperator, ocihandler.OciHandler)
	for _, dataOperator := range operators.GetDataOperators() {
		g.DataOperator = append(g.DataOperator, dataOperator)
	}
	g.DataOperator = append(g.DataOperator, simple.New("gadget", gadgetOperatorOpts...))

	gadgetContextOps := []gadgetcontext.Option{
		gadgetcontext.WithDataOperators(g.DataOperator...),
	}
	if g.timeout != 0 {
		gadgetContextOps = append(gadgetContextOps, gadgetcontext.WithTimeout(g.timeout))
	}

	if strings.ToLower(os.Getenv("IG_DEBUG_LOGS")) == "true" {
		l := logger.DefaultLogger()
		l.SetLevel(logger.DebugLevel)
		gadgetContextOps = append(gadgetContextOps, gadgetcontext.WithLogger(l))
	}

	g.gadgetCtx = gadgetcontext.New(context.Background(), g.image, gadgetContextOps...)
	runtime := local.New()

	for _, op := range g.DataOperator {
		opParams := apihelpers.ToParamDescs(op.GlobalParams()).ToParams()
		err := opParams.CopyFromMap(g.globalParamValues, "operator."+op.Name()+".")
		require.NoError(g.testCtx, err, "copying global params error")

		err = op.Init(opParams)
		require.NoError(g.testCtx, err, "operator initialization error")
	}

	err := runtime.Init(nil)
	require.NoError(g.testCtx, err, "runtime initialization error")

	// Run the gadget
	if g.beforeGadgetRun != nil {
		err = g.beforeGadgetRun()
		require.NoError(g.testCtx, err, "before gadget run error")
	}
	err = runtime.RunGadget(g.gadgetCtx, g.runtimeParams, g.paramValues)
	require.NoError(g.testCtx, err, "running gadget error")
}

func GetGadgetImageName(gadget string) string {
	repository := os.Getenv("GADGET_REPOSITORY")
	tag := os.Getenv("GADGET_TAG")
	if repository != "" {
		gadget = fmt.Sprintf("%s/%s", repository, gadget)
	}
	if tag != "" {
		gadget = fmt.Sprintf("%s:%s", gadget, tag)
	}
	return gadget
}
