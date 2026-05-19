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
	"net"
	"os"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	kubeletpodsv1alpha1 "k8s.io/kubelet/pkg/apis/pods/v1alpha1"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// kubeletPodsAPI caches the result of probing the kubelet pods-api Unix socket
// (KEP-4188, https://github.com/kubernetes/enhancements/issues/4188).
//
// Feature gate: PodsAPI (Kubernetes 1.36+ alpha).
// Socket path: <host.HostRoot>/var/lib/kubelet/pods-api/pods-api.sock
//
// Probed once at ContainerCollection.Initialize() time and re-used by all four
// call sites in options.go. available==false means every site uses the
// apiserver REST fallback for the lifetime of this ContainerCollection.
//
// Invariant: available==true ⟹ conn != nil ∧ client != nil.
// conn is owned by ContainerCollection; informers borrow the client only.
// Closed by ContainerCollection.Close() via cleanUpFuncs.
type kubeletPodsAPI struct {
	socketPath string
	available  bool
	conn       *grpc.ClientConn
	client     kubeletpodsv1alpha1.PodsClient
}

// probeKubeletPodsAPI runs once at Initialize(). It performs:
//  1. SecureJoin + os.Stat on the socket path
//  2. grpc.NewClient + WithContextDialer over Unix
//  3. ListPods health-check (2 s timeout)
//
// On any failure the REST path is silently used (no log when socket is absent;
// one log.Info when the socket exists but the probe fails). No error is
// returned — REST fallback is always valid.
//
// Note: connect(2) on a unix-domain socket inode requires the calling process
// to have read+write permission on the socket file's mode bits (typically
// srw-rw---- owned by root), but does NOT require the containing volume mount
// to be writable. The kernel checks the socket's own mode/uid/gid, not the
// mount's MS_RDONLY flag. The /host/var volume in the gadget daemonset is
// mounted readOnly: true, which is therefore fine for connect(2).
func probeKubeletPodsAPI(ctx context.Context) *kubeletPodsAPI {
	socketPath, err := securejoin.SecureJoin(host.HostRoot, "/var/lib/kubelet/pods-api/pods-api.sock")
	if err != nil {
		// SecureJoin failure on host.HostRoot is exotic; treat as not available
		// silently — REST fallback is always valid.
		return &kubeletPodsAPI{}
	}
	result := &kubeletPodsAPI{socketPath: socketPath}

	if _, err := os.Stat(socketPath); err != nil {
		if os.IsNotExist(err) {
			// Common case on clusters without the feature gate: silent fallback.
			return result
		}
		log.Infof("Kubelet pods API (KEP-4188) not available at %s (%v); using apiserver REST", socketPath, err)
		return result
	}

	// NOTE: grpc.NewClient requires a target with a scheme prefix for Unix
	// sockets ("unix:"+path). WithContextDialer performs the actual dial;
	// the target string is only used by gRPC's resolver/balancer plumbing.
	conn, err := grpc.NewClient("unix:"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		}),
	)
	if err != nil {
		log.Infof("Kubelet pods API (KEP-4188) dial failed at %s (%v); using apiserver REST", socketPath, err)
		return result
	}

	client := kubeletpodsv1alpha1.NewPodsClient(conn)
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := client.ListPods(probeCtx, &kubeletpodsv1alpha1.ListPodsRequest{}); err != nil {
		log.Infof("Kubelet pods API (KEP-4188) ListPods probe failed at %s (%v); using apiserver REST", socketPath, err)
		_ = conn.Close()
		return result
	}

	log.Infof("Kubelet pods API (KEP-4188) available at %s; using gRPC for node-local pod lookups", socketPath)
	result.available = true
	result.conn = conn
	result.client = client
	return result
}
