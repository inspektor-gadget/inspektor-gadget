// Copyright 2026 The Inspektor Gadget authors
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

package ebpfoperator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/tchandler"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// Only ELF loading is replaced: OCI delegates PreStart to the real eBPF
// instance, and the real local manager subscribes and calls its attach/detach
// methods. No kernel objects are needed before the barrier operator stops Run.
type netnsLifecycleImageOperator struct {
	instance *ebpfInstance
}

func (o *netnsLifecycleImageOperator) Name() string { return "ebpf" }

func (o *netnsLifecycleImageOperator) InstantiateImageOperator(
	ctx operators.GadgetContext, _ oras.ReadOnlyTarget, _ ocispec.Descriptor, values api.ParamValues,
) (operators.ImageOperatorInstance, error) {
	o.instance.paramValues = values
	ctx.SetVar("ebpfInstance", o.instance)
	ctx.SetVar("NeedContainerEvents", true)
	return o.instance, nil
}

func TestNetnsPathBeforeManagerCallbacks(t *testing.T) {
	const mediaType = "application/vnd.inspektor-gadget.test.netns-lifecycle"
	const imageName = "example.com/netns-lifecycle:latest"

	for _, withTC := range []bool{false, true} {
		t.Run(fmt.Sprintf("tc=%t", withTC), func(t *testing.T) {
			var logs bytes.Buffer
			log := logrus.New()
			log.SetOutput(&logs)
			log.SetLevel(logrus.DebugLevel)

			i := &ebpfInstance{
				bpfOperator:    &ebpfOperator{},
				logger:         log,
				collectionSpec: &ebpf.CollectionSpec{},
				params: map[string]*param{
					ParamNetnsPath: {Param: &api.Param{Key: ParamNetnsPath}},
				},
				containers:     make(map[string]*containercollection.Container),
				networkTracers: map[string]*networktracer.Tracer[api.GadgetData]{"socket": {}},
				tcHandlers:     make(map[string]*tchandler.Handler),
			}
			if withTC {
				i.tcHandlers["tc"] = &tchandler.Handler{}
			}
			operators.RegisterOperatorForMediaType(mediaType, &netnsLifecycleImageOperator{instance: i})

			store := memory.New()
			push := func(mediaType string, data []byte) ocispec.Descriptor {
				desc := content.NewDescriptorFromBytes(mediaType, data)
				require.NoError(t, store.Push(t.Context(), desc, bytes.NewReader(data)))
				return desc
			}
			manifest := ocispec.Manifest{
				MediaType: ocispec.MediaTypeImageManifest,
				Config:    push("application/vnd.inspektor-gadget.config.v1+yaml", []byte("{}")),
				Layers:    []ocispec.Descriptor{push(mediaType, []byte("lifecycle fixture"))},
			}
			manifest.SchemaVersion = 2
			manifestBytes, err := json.Marshal(manifest)
			require.NoError(t, err)
			manifestDesc := push(ocispec.MediaTypeImageManifest, manifestBytes)
			manifestDesc.Platform = &ocispec.Platform{Architecture: runtime.GOARCH, OS: "linux"}
			index := ocispec.Index{
				MediaType: ocispec.MediaTypeImageIndex,
				Manifests: []ocispec.Descriptor{manifestDesc},
			}
			index.SchemaVersion = 2
			indexBytes, err := json.Marshal(index)
			require.NoError(t, err)
			require.NoError(t, store.Tag(t.Context(), push(ocispec.MediaTypeImageIndex, indexBytes), imageName))

			var cc containercollection.ContainerCollection
			require.NoError(t, cc.Initialize(containercollection.WithPubSub()))
			t.Cleanup(cc.Close)
			container := &containercollection.Container{
				Runtime: containercollection.RuntimeMetadata{
					BasicRuntimeMetadata: types.BasicRuntimeMetadata{
						ContainerID: "initial-container", ContainerName: "fixture", ContainerPID: ^uint32(0),
					},
				},
			}
			cc.AddContainer(container)
			tc, err := tracercollection.NewTracerCollectionTest(&cc)
			require.NoError(t, err)
			t.Cleanup(tc.Close)
			manager := localmanager.NewLocalManager(&cc, tc)

			barrier := errors.New("stop before loading BPF")
			managerFinished := false
			checkCallbacks := simple.New("after-manager", simple.WithPriority(manager.Priority()+1),
				simple.OnPreStart(func(ctx operators.GadgetContext) error {
					managerFinished = true
					if withTC {
						return barrier
					}
					require.Contains(t, i.containers, "initial-container", "manager must replay its initial containers")
					require.NotEmpty(t, i.netnsPath, "namespace-path mode must precede container callbacks")
					cc.RemoveContainer("initial-container")
					require.Empty(t, i.containers, "manager must deliver removal callbacks too")
					cc.AddContainer(container)
					require.Contains(t, i.containers, "initial-container", "manager must deliver live add callbacks")
					return barrier
				}),
			)
			ctx := gadgetcontext.New(t.Context(), imageName,
				gadgetcontext.WithLogger(log),
				gadgetcontext.WithOrasReadonlyTarget(store),
				// Intentionally unsorted: Run must order real OCI before manager.
				gadgetcontext.WithDataOperators(manager, checkCallbacks, ocihandler.New()),
			)
			err = ctx.Run(api.ParamValues{
				"operator.oci.ebpf.netns-path": fmt.Sprintf("/proc/%d/ns/net", os.Getpid()),
			})
			if withTC {
				require.ErrorContains(t, err, "not yet supported for TC programs")
				require.False(t, managerFinished)
				require.Empty(t, i.containers, "TC rejection must precede any container callbacks")
				require.NotContains(t, logs.String(), "calling gadget.AttachContainer()")
				return
			}
			require.ErrorIs(t, err, barrier)
			require.True(t, managerFinished)
			require.Contains(t, logs.String(), "calling gadget.AttachContainer()")
			require.Contains(t, logs.String(), "calling gadget.DetachContainer()")
			require.NotContains(t, logs.String(), "start tracing container", "invalid container PID must never reach a network tracer")
			require.NotContains(t, logs.String(), "stop tracing container", "container removals must not reach a network tracer")
		})
	}
}
