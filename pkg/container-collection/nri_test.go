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

package containercollection

import (
	"context"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type fakeNRIRuntimeClient struct{}

func (*fakeNRIRuntimeClient) GetContainers() ([]*runtimeclient.ContainerData, error) {
	return nil, nil
}

func (*fakeNRIRuntimeClient) GetContainer(id string) (*runtimeclient.ContainerData, error) {
	return &runtimeclient.ContainerData{
		Runtime: runtimeclient.RuntimeContainerData{
			ContainerID:          id,
			ContainerImageID:     "sha256:image-id",
			ContainerImageDigest: "sha256:image-digest",
		},
	}, nil
}

func (*fakeNRIRuntimeClient) GetContainerDetails(string) (*runtimeclient.ContainerDetailsData, error) {
	return nil, nil
}

func (*fakeNRIRuntimeClient) Close() error {
	return nil
}

func newNRIContainerCollection(t *testing.T, options ...ContainerCollectionOption) *ContainerCollection {
	t.Helper()

	var cc ContainerCollection
	var namespace uint64
	options = append(options, func(cc *ContainerCollection) error {
		cc.containerEnrichers = append(cc.containerEnrichers, func(container *Container) bool {
			namespace++
			container.Mntns = namespace
			container.Netns = namespace
			container.K8s.ownerReference = &metav1.OwnerReference{}
			return true
		})
		return nil
	})
	require.NoError(t, cc.Initialize(options...))
	t.Cleanup(cc.Close)
	return &cc
}

func newNRIPlugin(t *testing.T, cc *ContainerCollection) *nriPlugin {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	plugin := &nriPlugin{
		cc:             cc,
		runtimeName:    types.RuntimeNameContainerd,
		runtime:        &fakeNRIRuntimeClient{},
		wakeup:         make(chan struct{}, 1),
		deferredWakeup: make(chan struct{}, 1),
		containers:     make(map[string]struct{}),
	}
	plugin.wg.Add(2)
	go plugin.run(ctx)
	go plugin.runDeferred(ctx)
	t.Cleanup(func() {
		cancel()
		plugin.wg.Wait()
	})
	return plugin
}

func waitNRIPlugin(t *testing.T, plugin *nriPlugin) {
	t.Helper()

	done := make(chan struct{})
	plugin.enqueue(func() {
		close(done)
	})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for NRI events")
	}
}

func TestNRIPluginContainerLifecycle(t *testing.T) {
	cc := newNRIContainerCollection(t)
	plugin := newNRIPlugin(t, cc)

	pod := &api.PodSandbox{
		Id:        "pod-id",
		Name:      "pod-name",
		Uid:       "pod-uid",
		Namespace: "namespace",
		Labels:    map[string]string{"app": "test"},
	}
	running := &api.Container{
		Id:           "running",
		PodSandboxId: pod.Id,
		Name:         "container",
		State:        api.ContainerState_CONTAINER_RUNNING,
		Pid:          123,
		Annotations:  map[string]string{"io.kubernetes.cri.image-name": "busybox:latest"},
	}
	stopped := &api.Container{
		Id:           "stopped",
		PodSandboxId: pod.Id,
		State:        api.ContainerState_CONTAINER_STOPPED,
		Pid:          456,
	}

	_, err := plugin.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{running, stopped})
	require.NoError(t, err)
	waitNRIPlugin(t, plugin)
	require.Nil(t, cc.GetContainer(stopped.Id))

	container := cc.GetContainer(running.Id)
	require.NotNil(t, container)
	require.Equal(t, types.RuntimeNameContainerd, container.Runtime.RuntimeName)
	require.Equal(t, running.Pid, container.Runtime.ContainerPID)
	require.Equal(t, "busybox:latest", container.Runtime.ContainerImageName)
	require.Equal(t, "sha256:image-digest", container.Runtime.ContainerImageDigest)
	require.Equal(t, pod.Namespace, container.K8s.Namespace)
	require.Equal(t, pod.Name, container.K8s.PodName)
	require.Equal(t, pod.Uid, container.K8s.PodUID)
	require.Equal(t, running.Name, container.K8s.ContainerName)
	require.Equal(t, pod.Labels, container.K8s.PodLabels)

	started := &api.Container{Id: "started", Name: "second", Pid: 789}
	require.NoError(t, plugin.PostStartContainer(context.Background(), pod, started))
	waitNRIPlugin(t, plugin)
	require.NotNil(t, cc.GetContainer(started.Id))

	_, err = plugin.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{
		{
			Id:           started.Id,
			PodSandboxId: pod.Id,
			Name:         started.Name,
			State:        api.ContainerState_CONTAINER_RUNNING,
			Pid:          started.Pid,
		},
	})
	require.NoError(t, err)
	waitNRIPlugin(t, plugin)
	require.Nil(t, cc.GetContainer(running.Id))

	_, err = plugin.StopContainer(context.Background(), pod, started)
	require.NoError(t, err)
	waitNRIPlugin(t, plugin)
	require.Nil(t, cc.GetContainer(started.Id))
}

func TestNRIPluginIgnoresIncompleteContainer(t *testing.T) {
	cc := newNRIContainerCollection(t)
	plugin := newNRIPlugin(t, cc)
	require.NoError(t, plugin.PostStartContainer(context.Background(), &api.PodSandbox{}, &api.Container{Id: "no-pid"}))
	waitNRIPlugin(t, plugin)
	require.Zero(t, cc.ContainerLen())
}

func TestNRIPluginEnrichesCrioImageMetadata(t *testing.T) {
	cc := newNRIContainerCollection(t)
	plugin := newNRIPlugin(t, cc)
	plugin.runtimeName = types.RuntimeNameCrio

	pod := &api.PodSandbox{Id: "pod", Name: "pod", Namespace: "namespace"}
	require.NoError(t, plugin.PostStartContainer(context.Background(), pod, &api.Container{
		Id: "container", Name: "container", Pid: 123,
	}))
	waitNRIPlugin(t, plugin)

	container := cc.GetContainer("container")
	require.NotNil(t, container)
	require.Equal(t, "sha256:image-id", container.Runtime.ContainerImageID)
	require.Equal(t, "sha256:image-digest", container.Runtime.ContainerImageDigest)
}

func TestNRIPluginDeferredEventsDoNotBlockLifecycle(t *testing.T) {
	cc := newNRIContainerCollection(t)
	plugin := newNRIPlugin(t, cc)
	deferredStarted := make(chan struct{})
	releaseDeferred := make(chan struct{})
	defer close(releaseDeferred)
	plugin.enqueueDeferred(func(context.Context) {
		close(deferredStarted)
		<-releaseDeferred
	})
	<-deferredStarted

	lifecycleDone := make(chan struct{})
	plugin.enqueue(func() {
		close(lifecycleDone)
	})
	select {
	case <-lifecycleDone:
	case <-time.After(time.Second):
		t.Fatal("deferred event blocked lifecycle processing")
	}
}

func TestNRIPluginSerializesLifecycleEvents(t *testing.T) {
	syncStarted := make(chan struct{})
	continueSync := make(chan struct{})
	cc := newNRIContainerCollection(t, func(cc *ContainerCollection) error {
		cc.containerEnrichers = append(cc.containerEnrichers, func(container *Container) bool {
			if container.Runtime.ContainerID == "synchronized" {
				close(syncStarted)
				<-continueSync
			}
			return true
		})
		return nil
	})
	plugin := newNRIPlugin(t, cc)
	pod := &api.PodSandbox{Id: "pod", Name: "pod", Namespace: "namespace"}

	_, err := plugin.Synchronize(context.Background(), []*api.PodSandbox{pod}, []*api.Container{{
		Id:           "synchronized",
		PodSandboxId: pod.Id,
		Name:         "first",
		State:        api.ContainerState_CONTAINER_RUNNING,
		Pid:          123,
	}})
	require.NoError(t, err)
	<-syncStarted

	require.NoError(t, plugin.PostStartContainer(context.Background(), pod, &api.Container{
		Id: "started", Name: "second", Pid: 456,
	}))
	close(continueSync)
	waitNRIPlugin(t, plugin)

	require.NotNil(t, cc.GetContainer("synchronized"))
	require.NotNil(t, cc.GetContainer("started"))
}
