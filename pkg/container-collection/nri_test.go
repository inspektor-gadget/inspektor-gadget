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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

func TestResolveNRISocketPath(t *testing.T) {
	hostRoot := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(hostRoot, "ig-test/nri"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(hostRoot, "ig-test/nri/nri.sock"), nil, 0o600))
	// Absolute symlinks must resolve inside the host root.
	require.NoError(t, os.Symlink("/ig-test", filepath.Join(hostRoot, "ig-test-link")))

	oldHostRoot := host.HostRoot
	host.HostRoot = hostRoot
	t.Cleanup(func() { host.HostRoot = oldHostRoot })

	require.Equal(t, filepath.Join(hostRoot, "ig-test/nri/nri.sock"), resolveNRISocketPath("/ig-test/nri/nri.sock"))
	require.Equal(t, filepath.Join(hostRoot, "ig-test/nri/nri.sock"), resolveNRISocketPath("/ig-test-link/nri/nri.sock"))
	require.Equal(t, "/missing/nri.sock", resolveNRISocketPath("/missing/nri.sock"))

	existing := filepath.Join(t.TempDir(), "nri.sock")
	require.NoError(t, os.WriteFile(existing, nil, 0o600))
	require.Equal(t, existing, resolveNRISocketPath(existing))
}

type fakeNRIRuntimeClient struct {
	getContainerCalls int
}

func (*fakeNRIRuntimeClient) GetContainers() ([]*runtimeclient.ContainerData, error) {
	return nil, nil
}

func (f *fakeNRIRuntimeClient) GetContainer(id string) (*runtimeclient.ContainerData, error) {
	f.getContainerCalls++
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
	require.NoError(t, plugin.StartContainer(context.Background(), pod, started))
	require.NotNil(t, cc.GetContainer(started.Id), "container must be added before StartContainer returns")

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
	require.NoError(t, plugin.StartContainer(context.Background(), &api.PodSandbox{}, &api.Container{Id: "no-pid"}))
	require.Zero(t, cc.ContainerLen())
}

func TestNRIPluginEnrichesCrioImageMetadata(t *testing.T) {
	cc := newNRIContainerCollection(t)
	plugin := newNRIPlugin(t, cc)
	plugin.runtimeName = types.RuntimeNameCrio

	pod := &api.PodSandbox{Id: "pod", Name: "pod", Namespace: "namespace"}
	require.NoError(t, plugin.StartContainer(context.Background(), pod, &api.Container{
		Id: "container", Name: "container", Pid: 123,
	}))

	container := cc.GetContainer("container")
	require.NotNil(t, container)
	require.Equal(t, "sha256:image-id", container.Runtime.ContainerImageID)
	require.Equal(t, "sha256:image-digest", container.Runtime.ContainerImageDigest)
}

func TestNRIPluginUsesNRIMetadata(t *testing.T) {
	cc := newNRIContainerCollection(t)
	plugin := newNRIPlugin(t, cc)
	plugin.runtimeName = types.RuntimeNameCrio
	runtimeClient := &fakeNRIRuntimeClient{}
	plugin.runtime = runtimeClient

	pod := &api.PodSandbox{
		Id: "pod", Name: "pod", Namespace: "namespace",
		Labels: map[string]string{
			"app":                          "demo",
			"io.kubernetes.container.name": "POD",
			"io.kubernetes.pod.name":       "pod",
			"io.kubernetes.pod.namespace":  "namespace",
			"io.kubernetes.pod.uid":        "uid",
			"io.cri-containerd.kind":       "sandbox",
			"oci_runtime_type":             "io.containerd.runc.v2",
		},
	}
	require.NoError(t, plugin.StartContainer(context.Background(), pod, &api.Container{
		Id: "container", Name: "container", Pid: 123,
		Annotations: map[string]string{"io.kubernetes.cri-o.Name": "k8s_container_pod_namespace_uid_0"},
		Image: &api.Image{
			Name:         "docker.io/library/busybox:1.36",
			Digest:       "sha256:manifest",
			ConfigDigest: "sha256:config",
		},
	}))

	container := cc.GetContainer("container")
	require.NotNil(t, container)
	require.Zero(t, runtimeClient.getContainerCalls)
	require.Equal(t, "docker.io/library/busybox:1.36", container.Runtime.ContainerImageName)
	require.Equal(t, "sha256:manifest", container.Runtime.ContainerImageDigest)
	require.Equal(t, "sha256:config", container.Runtime.ContainerImageID)
	require.Equal(t, "k8s_container_pod_namespace_uid_0", container.Runtime.ContainerName)
	require.Equal(t, "container", container.K8s.ContainerName)
	require.Equal(t, map[string]string{"app": "demo"}, container.K8s.PodLabels)
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

	startDone := make(chan error)
	go func() {
		startDone <- plugin.StartContainer(context.Background(), pod, &api.Container{
			Id: "started", Name: "second", Pid: 456,
		})
	}()
	close(continueSync)
	require.NoError(t, <-startDone)

	require.NotNil(t, cc.GetContainer("synchronized"))
	require.NotNil(t, cc.GetContainer("started"))
}

func TestNRIPluginStartContainerWaitIsBounded(t *testing.T) {
	cc := newNRIContainerCollection(t)
	plugin := newNRIPlugin(t, cc)
	release := make(chan struct{})
	plugin.enqueue(func() {
		<-release
	})

	start := time.Now()
	require.NoError(t, plugin.StartContainer(context.Background(), &api.PodSandbox{Id: "pod", Name: "pod", Namespace: "namespace"},
		&api.Container{Id: "late", Name: "late", Pid: 123}))
	require.Less(t, time.Since(start), 2*time.Second)
	require.Nil(t, cc.GetContainer("late"))

	close(release)
	waitNRIPlugin(t, plugin)
	require.NotNil(t, cc.GetContainer("late"))
}
