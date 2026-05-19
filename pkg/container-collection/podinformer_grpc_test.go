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

package containercollection

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	v1 "k8s.io/api/core/v1"
	kubeletpodsv1alpha1 "k8s.io/kubelet/pkg/apis/pods/v1alpha1"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// mockPodsServer implements kubeletpodsv1alpha1.PodsServer for unit tests.
type mockPodsServer struct {
	kubeletpodsv1alpha1.UnimplementedPodsServer
	watchFn func(*kubeletpodsv1alpha1.WatchPodsRequest, kubeletpodsv1alpha1.Pods_WatchPodsServer) error
	listFn  func(context.Context, *kubeletpodsv1alpha1.ListPodsRequest) (*kubeletpodsv1alpha1.ListPodsResponse, error)
}

func (m *mockPodsServer) WatchPods(req *kubeletpodsv1alpha1.WatchPodsRequest, stream kubeletpodsv1alpha1.Pods_WatchPodsServer) error {
	if m.watchFn != nil {
		return m.watchFn(req, stream)
	}
	<-stream.Context().Done()
	return nil
}

func (m *mockPodsServer) ListPods(ctx context.Context, req *kubeletpodsv1alpha1.ListPodsRequest) (*kubeletpodsv1alpha1.ListPodsResponse, error) {
	if m.listFn != nil {
		return m.listFn(ctx, req)
	}
	return &kubeletpodsv1alpha1.ListPodsResponse{}, nil
}

// startMockPodsServer starts a mock gRPC Pods server on a temp Unix socket and
// returns a connected client. The server is stopped automatically via t.Cleanup.
func startMockPodsServer(t *testing.T, srv *mockPodsServer) kubeletpodsv1alpha1.PodsClient {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "pods-api.sock")
	lis, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	grpcSrv := grpc.NewServer()
	kubeletpodsv1alpha1.RegisterPodsServer(grpcSrv, srv)
	go grpcSrv.Serve(lis) //nolint:errcheck
	t.Cleanup(grpcSrv.Stop)
	conn, err := grpc.NewClient("unix:"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return kubeletpodsv1alpha1.NewPodsClient(conn)
}

// startMockPodsServerAt starts a mock gRPC Pods server at the given socket path
// (creating parent directories as needed). Used by probeKubeletPodsAPI tests.
func startMockPodsServerAt(t *testing.T, socketPath string, srv *mockPodsServer) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(socketPath), 0o755))
	lis, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	grpcSrv := grpc.NewServer()
	kubeletpodsv1alpha1.RegisterPodsServer(grpcSrv, srv)
	go grpcSrv.Serve(lis) //nolint:errcheck
	t.Cleanup(grpcSrv.Stop)
}

func marshalPod(t *testing.T, pod *v1.Pod) []byte {
	t.Helper()
	b, err := pod.Marshal()
	require.NoError(t, err)
	return b
}

func makePod(name, namespace, nodeName string) *v1.Pod {
	p := &v1.Pod{}
	p.Name = name
	p.Namespace = namespace
	p.Spec.NodeName = nodeName
	return p
}

func TestKubeletGRPCPodInformer_AddedFlowsToUpdatedChan(t *testing.T) {
	t.Parallel()
	pod := makePod("pod1", "default", "node1")
	podBytes := marshalPod(t, pod)

	client := startMockPodsServer(t, &mockPodsServer{
		watchFn: func(_ *kubeletpodsv1alpha1.WatchPodsRequest, stream kubeletpodsv1alpha1.Pods_WatchPodsServer) error {
			_ = stream.Send(&kubeletpodsv1alpha1.WatchPodsEvent{Type: kubeletpodsv1alpha1.EventType_ADDED, Pod: podBytes})
			<-stream.Context().Done()
			return nil
		},
	})

	informer, err := newKubeletGRPCPodInformer(context.Background(), client, "node1")
	require.NoError(t, err)
	defer informer.Stop()

	select {
	case got := <-informer.UpdatedChan():
		require.Equal(t, "pod1", got.Name)
		require.Equal(t, "default", got.Namespace)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for ADDED event on UpdatedChan")
	}
}

func TestKubeletGRPCPodInformer_ModifiedFlowsToUpdatedChan(t *testing.T) {
	t.Parallel()
	pod := makePod("pod2", "ns2", "node1")
	podBytes := marshalPod(t, pod)

	client := startMockPodsServer(t, &mockPodsServer{
		watchFn: func(_ *kubeletpodsv1alpha1.WatchPodsRequest, stream kubeletpodsv1alpha1.Pods_WatchPodsServer) error {
			_ = stream.Send(&kubeletpodsv1alpha1.WatchPodsEvent{Type: kubeletpodsv1alpha1.EventType_MODIFIED, Pod: podBytes})
			<-stream.Context().Done()
			return nil
		},
	})

	informer, err := newKubeletGRPCPodInformer(context.Background(), client, "node1")
	require.NoError(t, err)
	defer informer.Stop()

	select {
	case got := <-informer.UpdatedChan():
		require.Equal(t, "pod2", got.Name)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for MODIFIED event on UpdatedChan")
	}
}

func TestKubeletGRPCPodInformer_DeletedFlowsToDeletedChan(t *testing.T) {
	t.Parallel()
	pod := makePod("pod3", "ns3", "node1")
	podBytes := marshalPod(t, pod)

	client := startMockPodsServer(t, &mockPodsServer{
		watchFn: func(_ *kubeletpodsv1alpha1.WatchPodsRequest, stream kubeletpodsv1alpha1.Pods_WatchPodsServer) error {
			_ = stream.Send(&kubeletpodsv1alpha1.WatchPodsEvent{Type: kubeletpodsv1alpha1.EventType_DELETED, Pod: podBytes})
			<-stream.Context().Done()
			return nil
		},
	})

	informer, err := newKubeletGRPCPodInformer(context.Background(), client, "node1")
	require.NoError(t, err)
	defer informer.Stop()

	select {
	case key := <-informer.DeletedChan():
		require.Equal(t, "ns3/pod3", key)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for DELETED event on DeletedChan")
	}
}

func TestKubeletGRPCPodInformer_InitialSyncCompleteIsNoOp(t *testing.T) {
	t.Parallel()
	// Send INITIAL_SYNC_COMPLETE followed by an ADDED event. Only the ADDED event
	// should produce output; INITIAL_SYNC_COMPLETE is a stream marker.
	pod := makePod("pod-after-sync", "default", "")
	podBytes := marshalPod(t, pod)

	client := startMockPodsServer(t, &mockPodsServer{
		watchFn: func(_ *kubeletpodsv1alpha1.WatchPodsRequest, stream kubeletpodsv1alpha1.Pods_WatchPodsServer) error {
			_ = stream.Send(&kubeletpodsv1alpha1.WatchPodsEvent{Type: kubeletpodsv1alpha1.EventType_INITIAL_SYNC_COMPLETE})
			_ = stream.Send(&kubeletpodsv1alpha1.WatchPodsEvent{Type: kubeletpodsv1alpha1.EventType_ADDED, Pod: podBytes})
			<-stream.Context().Done()
			return nil
		},
	})

	informer, err := newKubeletGRPCPodInformer(context.Background(), client, "")
	require.NoError(t, err)
	defer informer.Stop()

	select {
	case got := <-informer.UpdatedChan():
		require.Equal(t, "pod-after-sync", got.Name)
	case <-informer.DeletedChan():
		t.Fatal("unexpected delete event (INITIAL_SYNC_COMPLETE must be a no-op)")
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: ADDED event following INITIAL_SYNC_COMPLETE never arrived")
	}
}

func TestKubeletGRPCPodInformer_NodeNameFilter(t *testing.T) {
	t.Parallel()
	podRight := makePod("right-pod", "default", "node1")
	podWrong := makePod("wrong-pod", "default", "node2")
	rightBytes := marshalPod(t, podRight)
	wrongBytes := marshalPod(t, podWrong)

	client := startMockPodsServer(t, &mockPodsServer{
		watchFn: func(_ *kubeletpodsv1alpha1.WatchPodsRequest, stream kubeletpodsv1alpha1.Pods_WatchPodsServer) error {
			// wrong-node pod must be filtered; right-node pod must pass through
			_ = stream.Send(&kubeletpodsv1alpha1.WatchPodsEvent{Type: kubeletpodsv1alpha1.EventType_ADDED, Pod: wrongBytes})
			_ = stream.Send(&kubeletpodsv1alpha1.WatchPodsEvent{Type: kubeletpodsv1alpha1.EventType_ADDED, Pod: rightBytes})
			<-stream.Context().Done()
			return nil
		},
	})

	informer, err := newKubeletGRPCPodInformer(context.Background(), client, "node1")
	require.NoError(t, err)
	defer informer.Stop()

	select {
	case got := <-informer.UpdatedChan():
		require.Equal(t, "right-pod", got.Name, "pod on node2 should be filtered; only node1 pod should arrive")
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for node-filtered pod")
	}
}

func TestKubeletGRPCPodInformer_ReconnectsOnStreamError(t *testing.T) {
	t.Parallel()
	pod := makePod("reconnect-pod", "default", "")
	podBytes := marshalPod(t, pod)

	var mu sync.Mutex
	callCount := 0

	client := startMockPodsServer(t, &mockPodsServer{
		watchFn: func(_ *kubeletpodsv1alpha1.WatchPodsRequest, stream kubeletpodsv1alpha1.Pods_WatchPodsServer) error {
			mu.Lock()
			n := callCount
			callCount++
			mu.Unlock()
			if n == 0 {
				return errors.New("simulated stream error")
			}
			_ = stream.Send(&kubeletpodsv1alpha1.WatchPodsEvent{Type: kubeletpodsv1alpha1.EventType_ADDED, Pod: podBytes})
			<-stream.Context().Done()
			return nil
		},
	})

	informer, err := newKubeletGRPCPodInformer(context.Background(), client, "")
	require.NoError(t, err)
	defer informer.Stop()

	// Allow up to 10 s so JitterUntilWithContext can complete its 1±0.5 s backoff.
	select {
	case got := <-informer.UpdatedChan():
		require.Equal(t, "reconnect-pod", got.Name)
	case <-time.After(10 * time.Second):
		t.Fatal("timeout: pod never arrived after reconnect")
	}
}

func TestKubeletGRPCPodInformer_StopDuringStream(t *testing.T) {
	t.Parallel()
	var once sync.Once
	streamStarted := make(chan struct{})

	client := startMockPodsServer(t, &mockPodsServer{
		watchFn: func(_ *kubeletpodsv1alpha1.WatchPodsRequest, stream kubeletpodsv1alpha1.Pods_WatchPodsServer) error {
			once.Do(func() { close(streamStarted) })
			<-stream.Context().Done()
			return nil
		},
	})

	informer, err := newKubeletGRPCPodInformer(context.Background(), client, "")
	require.NoError(t, err)

	select {
	case <-streamStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("stream never started")
	}

	done := make(chan struct{})
	go func() {
		informer.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return within the deadline")
	}
}

func TestKubeletGRPCPodInformer_ContainerIDSanityWarning(t *testing.T) {
	t.Parallel()
	// Pod has container statuses but all ContainerIDs are empty; the informer
	// should emit a one-shot warning but still forward the pod event.
	pod := makePod("no-id-pod", "default", "")
	pod.Status.ContainerStatuses = []v1.ContainerStatus{{Name: "container1"}}
	podBytes := marshalPod(t, pod)

	client := startMockPodsServer(t, &mockPodsServer{
		watchFn: func(_ *kubeletpodsv1alpha1.WatchPodsRequest, stream kubeletpodsv1alpha1.Pods_WatchPodsServer) error {
			_ = stream.Send(&kubeletpodsv1alpha1.WatchPodsEvent{Type: kubeletpodsv1alpha1.EventType_ADDED, Pod: podBytes})
			<-stream.Context().Done()
			return nil
		},
	})

	informer, err := newKubeletGRPCPodInformer(context.Background(), client, "")
	require.NoError(t, err)
	defer informer.Stop()

	select {
	case got := <-informer.UpdatedChan():
		require.Equal(t, "no-id-pod", got.Name)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: pod with empty container IDs should still be forwarded to UpdatedChan")
	}
}

// TestProbeKubeletPodsAPI_AbsentSocket verifies that probeKubeletPodsAPI returns
// available=false (silently) when the Kubelet pods-api socket does not exist.
func TestProbeKubeletPodsAPI_AbsentSocket(t *testing.T) {
	// Modifies package-level host.HostRoot; must not run in parallel.
	orig := host.HostRoot
	host.HostRoot = t.TempDir() // empty dir: no pods-api.sock
	defer func() { host.HostRoot = orig }()

	result := probeKubeletPodsAPI(context.Background())
	require.False(t, result.available)
	require.Nil(t, result.conn)
}

// TestProbeKubeletPodsAPI_DialButListPodsFails verifies that probeKubeletPodsAPI
// returns available=false when the socket exists but the ListPods health-check fails.
func TestProbeKubeletPodsAPI_DialButListPodsFails(t *testing.T) {
	// Modifies package-level host.HostRoot; must not run in parallel.
	tmpRoot := t.TempDir()
	sockPath := filepath.Join(tmpRoot, "var", "lib", "kubelet", "pods-api", "pods-api.sock")
	startMockPodsServerAt(t, sockPath, &mockPodsServer{
		listFn: func(_ context.Context, _ *kubeletpodsv1alpha1.ListPodsRequest) (*kubeletpodsv1alpha1.ListPodsResponse, error) {
			return nil, errors.New("simulated ListPods failure")
		},
	})

	orig := host.HostRoot
	host.HostRoot = tmpRoot
	defer func() { host.HostRoot = orig }()

	result := probeKubeletPodsAPI(context.Background())
	require.False(t, result.available)
	require.Nil(t, result.conn)
}

// TestProbeKubeletPodsAPI_SocketPresentAndHealthy verifies that probeKubeletPodsAPI
// returns available=true when the socket is reachable and the ListPods health-check succeeds.
// On a real cluster this requires the PodsAPI feature gate (Kubernetes 1.36+ alpha).
func TestProbeKubeletPodsAPI_SocketPresentAndHealthy(t *testing.T) {
	// Modifies package-level host.HostRoot; must not run in parallel.
	tmpRoot := t.TempDir()
	sockPath := filepath.Join(tmpRoot, "var", "lib", "kubelet", "pods-api", "pods-api.sock")
	startMockPodsServerAt(t, sockPath, &mockPodsServer{}) // default ListPods returns empty success

	orig := host.HostRoot
	host.HostRoot = tmpRoot
	defer func() { host.HostRoot = orig }()

	result := probeKubeletPodsAPI(context.Background())
	require.True(t, result.available)
	require.NotNil(t, result.conn)
	require.NotNil(t, result.client)
	_ = result.conn.Close()
}
