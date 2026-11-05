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
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	securejoin "github.com/cyphar/filepath-securejoin"
	log "github.com/sirupsen/logrus"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/cri"
	ociannotations "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/oci-annotations"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	// DefaultNRISocketPath is the runtime socket path inside the gadget container.
	DefaultNRISocketPath  = "/run/nri/nri.sock"
	nriReconnectDelay     = time.Second
	nriMaxReconnectDelay  = time.Minute
	nriOwnerLookupTimeout = 30 * time.Second
	// nriDefaultStartWait is used if the runtime did not send its request
	// timeout. NRI's default request timeout is 2s.
	nriDefaultStartWait = time.Second

	crioContainerNameAnnotation = "io.kubernetes.cri-o.Name"
)

type nriPlugin struct {
	cc             *ContainerCollection
	runtimeName    types.RuntimeName
	runtime        runtimeclient.ContainerRuntimeClient
	stub           stub.Stub
	closed         chan struct{}
	wakeup         chan struct{}
	deferredWakeup chan struct{}

	mu sync.Mutex

	eventsMu sync.Mutex
	// NRI callbacks must return promptly, so lifecycle and slow enrichment work
	// are queued independently without blocking the runtime.
	events         []func()
	deferredEvents []func(context.Context)
	wg             sync.WaitGroup

	containers map[string]struct{}
}

// WithNRI uses the Node Resource Interface to get initial containers and
// container start/remove notifications from the runtime.
//
// If socketPath does not exist and HOST_ROOT is set (e.g. /host with "kubectl
// debug node"), socketPath is looked up under HOST_ROOT.
func WithNRI(socketPath string) ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		socketPath = resolveNRISocketPath(socketPath)
		plugin := &nriPlugin{
			cc:             cc,
			closed:         make(chan struct{}, 1),
			wakeup:         make(chan struct{}, 1),
			deferredWakeup: make(chan struct{}, 1),
			containers:     make(map[string]struct{}),
		}

		nriStub, err := stub.New(
			plugin,
			stub.WithPluginName("inspektor-gadget"),
			// Only observe containers, after other plugins adjusted them.
			stub.WithPluginIdx("90"),
			stub.WithSocketPath(socketPath),
			stub.WithOnClose(func() {
				select {
				case plugin.closed <- struct{}{}:
				default:
				}
			}),
		)
		if err != nil {
			return fmt.Errorf("creating NRI plugin: %w", err)
		}
		plugin.stub = nriStub

		ctx, cancel := context.WithCancel(context.Background())
		plugin.wg.Add(2)
		go plugin.run(ctx)
		go plugin.runDeferred(ctx)
		if err := nriStub.Start(ctx); err != nil {
			cancel()
			plugin.wg.Wait()
			plugin.removeAllContainers()
			plugin.closeRuntime()
			return fmt.Errorf("starting NRI plugin: %w", err)
		}

		plugin.wg.Add(1)
		go plugin.reconnect(ctx)
		cc.cleanUpFuncs = append(cc.cleanUpFuncs, func() {
			cancel()
			nriStub.Stop()
			plugin.wg.Wait()
			plugin.closeRuntime()
		})

		return nil
	}
}

// Container hooks to detect new containers, see WithContainerHook.
const (
	ContainerHookAuto     = "auto"
	ContainerHookFanotify = "fanotify"
	ContainerHookNRI      = "nri"
)

// ContainerHooks lists the values accepted by WithContainerHook.
var ContainerHooks = []string{ContainerHookAuto, ContainerHookFanotify, ContainerHookNRI}

// WithContainerHook detects new containers with fanotify, with NRI, or with
// NRI if its socket is reachable and fanotify otherwise (auto). NRI only
// reports containers managed via CRI, e.g. Kubernetes pods.
func WithContainerHook(hook, nriSocketPath string, fanotify ContainerCollectionOption) ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		switch hook {
		case ContainerHookFanotify:
			return fanotify(cc)
		case ContainerHookNRI:
			return WithNRI(nriSocketPath)(cc)
		case ContainerHookAuto:
			if err := WithNRI(nriSocketPath)(cc); err != nil {
				log.Debugf("NRI unavailable, using fanotify: %s", err)
				return fanotify(cc)
			}
			log.Debugf("Using NRI to detect new containers")
			return nil
		default:
			return fmt.Errorf("invalid container hook %q, supported values: %v", hook, ContainerHooks)
		}
	}
}

func resolveNRISocketPath(socketPath string) string {
	if _, err := os.Stat(socketPath); err == nil || host.HostRoot == "/" {
		return socketPath
	}
	hostSocketPath, err := securejoin.SecureJoin(host.HostRoot, socketPath)
	if err != nil {
		return socketPath
	}
	if _, err := os.Stat(hostSocketPath); err != nil {
		return socketPath
	}
	return hostSocketPath
}

func (p *nriPlugin) Configure(_ context.Context, _ string, runtime, _ string) (stub.EventMask, error) {
	runtimeName := types.String2RuntimeName(runtime)

	p.mu.Lock()
	if p.runtime != nil {
		p.mu.Unlock()
		return 0, nil
	}
	p.runtimeName = runtimeName
	p.mu.Unlock()

	if p.cc.runtimeEnrichment {
		// The container collection already has enrichers using runtime
		// clients configured by the caller, e.g. ig's localmanager.
		return 0, nil
	}

	socketPath, err := getSocketPathFromConfig(runtimeName)
	if err != nil {
		log.Warnf("NRI: runtime enrichment unavailable: getting %s socket path: %s", runtimeName, err)
		return 0, nil
	}
	runtimeClient, err := containerutils.NewContainerRuntimeClient(&containerutilsTypes.RuntimeConfig{
		Name:            runtimeName,
		SocketPath:      socketPath,
		RuntimeProtocol: containerutilsTypes.RuntimeProtocolCRI,
	})
	if err != nil {
		log.Warnf("NRI: runtime enrichment unavailable: creating %s runtime client: %s", runtimeName, err)
		return 0, nil
	}

	p.mu.Lock()
	p.runtime = runtimeClient
	p.mu.Unlock()
	return 0, nil
}

func (p *nriPlugin) Synchronize(_ context.Context, pods []*api.PodSandbox, containers []*api.Container) ([]*api.ContainerUpdate, error) {
	p.enqueue(func() {
		p.synchronize(pods, containers)
	})
	return nil, nil
}

func (p *nriPlugin) synchronize(pods []*api.PodSandbox, containers []*api.Container) {
	podsByID := make(map[string]*api.PodSandbox, len(pods))
	for _, pod := range pods {
		podsByID[pod.GetId()] = pod
	}

	running := make(map[string]struct{}, len(containers))
	for _, container := range containers {
		if container.GetState() != api.ContainerState_CONTAINER_RUNNING {
			continue
		}
		if p.addContainer(podsByID[container.GetPodSandboxId()], container) {
			running[container.GetId()] = struct{}{}
		}
	}

	p.mu.Lock()
	var stale []string
	for id := range p.containers {
		if _, ok := running[id]; !ok {
			stale = append(stale, id)
		}
	}
	p.containers = running
	p.mu.Unlock()

	for _, id := range stale {
		p.cc.RemoveContainer(id)
	}
}

// StartContainer is called after the container's process is created, but
// before it is resumed. Wait until the container is added so that gadgets see
// it before its entrypoint runs. The add goes through the event queue so it
// stays ordered after a pending Synchronize. Waiting is bounded below the NRI
// request timeout, because a timeout makes the runtime drop the plugin.
func (p *nriPlugin) StartContainer(ctx context.Context, pod *api.PodSandbox, container *api.Container) error {
	done := make(chan struct{})
	p.enqueue(func() {
		defer close(done)
		p.addContainer(pod, container)
	})

	wait := nriDefaultStartWait
	if p.stub != nil && p.stub.RequestTimeout() > 0 {
		wait = p.stub.RequestTimeout() / 2
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-done:
	case <-ctx.Done():
	case <-timer.C:
		log.Debugf("NRI: container %s not added within %s, continuing asynchronously", container.GetId(), wait)
	}
	return nil
}

func (p *nriPlugin) StopContainer(_ context.Context, _ *api.PodSandbox, container *api.Container) ([]*api.ContainerUpdate, error) {
	p.enqueue(func() {
		p.removeContainer(container.GetId())
	})
	return nil, nil
}

func (p *nriPlugin) RemoveContainer(_ context.Context, _ *api.PodSandbox, container *api.Container) error {
	p.enqueue(func() {
		p.removeContainer(container.GetId())
	})
	return nil
}

func (p *nriPlugin) removeContainer(id string) {
	p.mu.Lock()
	delete(p.containers, id)
	p.mu.Unlock()
	p.cc.RemoveContainer(id)
}

func (p *nriPlugin) addContainer(pod *api.PodSandbox, container *api.Container) bool {
	if pod == nil || container.GetId() == "" || container.GetPid() == 0 {
		log.Warnf("NRI: ignoring container with incomplete metadata: pod=%v container=%q pid=%d",
			pod != nil, container.GetId(), container.GetPid())
		return false
	}

	p.mu.Lock()
	runtimeName := p.runtimeName
	p.mu.Unlock()

	c := &Container{
		Runtime: RuntimeMetadata{
			BasicRuntimeMetadata: types.BasicRuntimeMetadata{
				RuntimeName:   runtimeName,
				ContainerID:   container.GetId(),
				ContainerName: container.GetName(),
				ContainerPID:  container.GetPid(),
			},
		},
		K8s: K8sMetadata{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     pod.GetNamespace(),
				PodName:       pod.GetName(),
				ContainerName: container.GetName(),
			},
			PodUID:              pod.GetUid(),
			deferOwnerReference: true,
		},
		SandboxId: pod.GetId(),
	}
	if img := container.GetImage(); img != nil {
		// Set by containerd >= 2.4, and by CRI-O with
		// https://github.com/cri-o/cri-o/pull/10528. If name and digest are
		// set, the runtime enricher below does not need a CRI call.
		c.Runtime.ContainerImageName = img.GetName()
		c.Runtime.ContainerImageDigest = img.GetDigest()
		c.Runtime.ContainerImageID = img.GetConfigDigest()
	}
	if resolver, err := ociannotations.NewResolver(runtimeName.String()); err == nil && c.Runtime.ContainerImageName == "" {
		c.Runtime.ContainerImageName = resolver.ContainerImageName(container.GetAnnotations())
	}
	if runtimeName == types.RuntimeNameCrio {
		// Same composed name (k8s_<container>_<pod>_...) as the CRI client.
		if name := container.GetAnnotations()[crioContainerNameAnnotation]; name != "" {
			c.Runtime.ContainerName = name
		}
	}
	c.SetPodLabels(cri.FilterPodLabels(pod.GetLabels()))
	if ociConfig, err := ociConfigForContainer(c); err != nil {
		log.Warnf("NRI: getting OCI config for container %s: %s", container.GetId(), err)
	} else {
		c.OciConfig = ociConfig
	}
	p.mu.Lock()
	runtimeClient := p.runtime
	p.mu.Unlock()
	if runtimeClient != nil && !containerRuntimeEnricher(runtimeName, runtimeClient, c, true) {
		return false
	}

	p.cc.AddContainer(c)
	if p.cc.GetContainer(container.GetId()) == nil {
		return false
	}

	p.mu.Lock()
	p.containers[container.GetId()] = struct{}{}
	p.mu.Unlock()
	if !p.cc.k8sEnrichment {
		return true
	}
	p.enqueueDeferred(func(ctx context.Context) {
		if p.cc.GetContainer(container.GetId()) != c {
			return
		}
		ctx, cancel := context.WithTimeout(ctx, nriOwnerLookupTimeout)
		defer cancel()
		if _, err := c.getOwnerReference(ctx, p.cc.kubeconfigPath); err != nil &&
			!errors.Is(err, context.Canceled) {
			log.Errorf("NRI: failed to get owner reference for container %s: %s", container.GetId(), err)
		}
	})
	return true
}

func (p *nriPlugin) enqueue(event func()) {
	p.eventsMu.Lock()
	p.events = append(p.events, event)
	p.eventsMu.Unlock()
	select {
	case p.wakeup <- struct{}{}:
	default:
	}
}

func (p *nriPlugin) enqueueDeferred(event func(context.Context)) {
	p.eventsMu.Lock()
	p.deferredEvents = append(p.deferredEvents, event)
	p.eventsMu.Unlock()
	select {
	case p.deferredWakeup <- struct{}{}:
	default:
	}
}

func (p *nriPlugin) run(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.wakeup:
		}

	drain:
		for {
			p.eventsMu.Lock()
			var event func()
			switch {
			case len(p.events) > 0:
				event = p.events[0]
				p.events[0] = nil
				if len(p.events) == 1 {
					p.events = nil
				} else {
					p.events = p.events[1:]
				}
			default:
				p.eventsMu.Unlock()
				break drain
			}
			p.eventsMu.Unlock()
			event()
		}
	}
}

func (p *nriPlugin) runDeferred(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.deferredWakeup:
		}

	drain:
		for {
			p.eventsMu.Lock()
			if len(p.deferredEvents) == 0 {
				p.eventsMu.Unlock()
				break drain
			}
			event := p.deferredEvents[0]
			p.deferredEvents[0] = nil
			if len(p.deferredEvents) == 1 {
				p.deferredEvents = nil
			} else {
				p.deferredEvents = p.deferredEvents[1:]
			}
			p.eventsMu.Unlock()
			event(ctx)
		}
	}
}

func (p *nriPlugin) closeRuntime() {
	p.mu.Lock()
	runtimeClient := p.runtime
	p.runtime = nil
	p.mu.Unlock()
	if runtimeClient != nil {
		if err := runtimeClient.Close(); err != nil {
			log.Warnf("NRI: closing runtime client: %s", err)
		}
	}
}

func (p *nriPlugin) removeAllContainers() {
	p.mu.Lock()
	containers := p.containers
	p.containers = make(map[string]struct{})
	p.mu.Unlock()
	for id := range containers {
		p.cc.RemoveContainer(id)
	}
}

func (p *nriPlugin) reconnect(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.closed:
		}

		delay := nriReconnectDelay
		for {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}

			if err := p.stub.Start(ctx); err != nil {
				log.Warnf("NRI: reconnecting: %s", err)
				delay *= 2
				if delay > nriMaxReconnectDelay {
					delay = nriMaxReconnectDelay
				}
				continue
			}
			log.Info("NRI: reconnected")
			break
		}
	}
}
