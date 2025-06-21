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

package dnsgenerator

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"

	generators "github.com/inspektor-gadget/inspektor-gadget/pkg/event-generators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

const (
	name = "dns"

	paramName       = "name"
	paramQueryType  = "qtype"
	paramNameserver = "nameserver"

	defaultPort = "53"
)

type dnsGenerator struct {
	logger logger.Logger

	// name is the domain name to query.
	name string
	// qt is the query type (A, AAAA, CNAME, etc.).
	qt string
	// nameserver is the DNS nameserver to use for queries.
	nameserver string
	// env is the environment where the generator runs (host or kubernetes).
	env generators.Environment
	// count is the number of queries to send (0 means infinite).
	count int
	// interval is the time between queries.
	interval time.Duration

	// stopCh is closed by Cleanup() to signal generation should stop.
	stopCh chan struct{}
	// doneCh is closed by the background goroutine once it really stops.
	doneCh chan struct{}
	// errs for reporting aggregated errors (buffer size 1)
	errs chan error
}

// New creates a new DNS generator.
func New(
	logger logger.Logger,
	env generators.Environment,
	count int,
	interval time.Duration,
	params map[string]string,
) (generators.Generator, error) {
	name, ok := params[paramName]
	if !ok || name == "" {
		return nil, fmt.Errorf("name parameter is required")
	}

	qt := params[paramQueryType]
	if qt == "" {
		qt = "A"
	}

	ns := params[paramNameserver]
	switch env {
	case generators.EnvHost:
		if ns == "" {
			servers, _ := nameserverFromResolvConf()
			if len(servers) == 0 {
				return nil, fmt.Errorf("no nameservers found in /etc/resolv.conf")
			}
			ns = servers[0]
		}
		ns = fmt.Sprintf("%s:%s", ns, defaultPort)
	case generators.EnvK8sNode:
		// Verify we can write static pods
		if err := generators.VerifyManifestDir(); err != nil {
			return nil, fmt.Errorf("verifying manifest directory %s: %w", generators.ManifestDir, err)
		}
	case generators.EnvK8sPod:
		// Nothing to do here, we will use the kubelet's DNS configuration
	default:
		return nil, fmt.Errorf("unsupported environment %q", env)
	}

	return &dnsGenerator{
		logger:     logger,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
		errs:       make(chan error, 1),
		name:       name,
		qt:         qt,
		nameserver: ns,
		env:        env,
		count:      count,
		interval:   interval,
	}, nil
}

func (d dnsGenerator) Generate() error {
	// Give some time to IG to start tracing DNS events
	// TODO: Register to ds that notify when gadget is running
	time.Sleep(3 * time.Second)

	// Dispatch by environment
	switch d.env {
	case generators.EnvK8sNode:
		return d.generateFromK8sNode(d.name, d.qt, d.nameserver)
	case generators.EnvHost:
		d.generateFromHost(d.name, d.qt, d.nameserver)
		return nil
	case generators.EnvK8sPod:
		return d.generateFromK8sPod(d.name, d.qt, d.nameserver)
	default:
		return fmt.Errorf("unsupported environment %q", d.env)
	}
}

func (d *dnsGenerator) generateFromHost(domain, qt, ns string) {
	d.logger.Debugf("Host mode: DNS %q type=%q ns %s every %s (max %d)",
		domain, qt, ns, d.interval, d.count,
	)

	client := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion(domain, dns.StringToType[qt])

	ticker := time.NewTicker(d.interval)
	go func() {
		defer ticker.Stop()
		defer close(d.doneCh)

		var errs []error
		sent := 0

		for {
			select {
			case <-d.stopCh:
				d.logger.Debugf("Stopping DNS generator for %s", domain)

				if len(errs) > 0 {
					d.errs <- errors.Join(errs...)
				}
				return

			case <-ticker.C:
				_, _, err := client.Exchange(msg, ns)
				if err != nil {
					errs = append(errs, err)
				}
				sent++
				if d.count > 0 && sent >= d.count {
					if len(errs) > 0 {
						d.errs <- errors.Join(errs...)
					}

					d.logger.Debugf("Reached max count %d for DNS queries to %s", d.count, domain)
					return
				}
			}
		}
	}()
}

func (d *dnsGenerator) generateFromK8sNode(name, qt, ns string) error {
	const namespace = "kube-system"
	const prefix = "dns-test"

	// Ensure unique pod name and container name
	podName, err := generators.GenerateRandomPodName(prefix + "-pod")
	if err != nil {
		return fmt.Errorf("could not generate pod name: %w", err)
	}
	containerName, err := generators.GenerateRandomContainerName(prefix + "-container")
	if err != nil {
		return fmt.Errorf("could not generate container name: %w", err)
	}

	secs := fmt.Sprintf("%g", d.interval.Seconds())

	// Static Pod manifest for DNS event generation
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  restartPolicy: Never
  containers:
  - name: %s
    image: busybox:latest
    command:
      - sh
      - -c
      - |
        i=0
        while true; do
          nslookup -debug -type=%s %s %s || exit 1
          i=$(expr $i + 1)
          if [ %d -gt 0 ] && [ "$i" -ge %d ]; then
            exit 0
          fi
          sleep %s
        done
`, podName, namespace, containerName, qt, name, ns, d.count, d.count, secs)

	d.logger.Debugf("K8sNode mode: DNS %q type=%q ns %s every %s (max %d)",
		name, qt, ns, secs, d.count)

	manifestPath := filepath.Join(generators.ManifestDir, "dns-test.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		return fmt.Errorf("writing static-pod manifest: %w", err)
	}

	go func() {
		defer func() {
			// Delete manifest so that kubelet kills the Pod
			if err := os.Remove(manifestPath); err != nil {
				d.errs <- fmt.Errorf("removing manifest: %w", err)
				return
			}

			// Signal that the goroutine is done
			close(d.doneCh)
		}()

		// wait for Cleanup() to signal stop
		<-d.stopCh

		// Capture the container's exit code and logs.
		// Note: We cannot use the kubelet’s kubeconfig and the Kubernetes API
		// to fetch pod logs here because the “system:node:<nodeName>” identity
		// (from /var/lib/kubelet/kubeconfig) is not granted the pods/log
		// subresource.
		cid, err := generators.FindDNSContainerID(containerName)
		if err != nil {
			d.errs <- fmt.Errorf("could not find %q container: %w", containerName, err)
			return
		}

		exitCode, logs, inspectErr := generators.InspectAndFetchLogs(cid)
		if inspectErr != nil {
			d.errs <- fmt.Errorf("inspecting %q container: %w", containerName, inspectErr)
			return
		}
		if exitCode != 0 {
			d.errs <- fmt.Errorf("%q container exited with code %d and logs:\n==== container logs ====\n%s\n==== container logs ====", containerName, exitCode, logs)
		}

		d.logger.Debugf("%q container exited with code %d and logs:\n%s", containerName, exitCode, logs)
	}()

	return nil
}

func (d *dnsGenerator) Cleanup() error {
	// Tell the generator (in the background goroutine) to stop
	close(d.stopCh)

	// Wait until the goroutine has truly exited
	<-d.doneCh

	// Log any aggregated error
	select {
	case err := <-d.errs:
		d.logger.Errorf("Generating DNS traffic: %v", err)
	default:
	}
	return nil
}

func nameserverFromResolvConf() ([]string, error) {
	rcPath := filepath.Clean("/etc/resolv.conf")
	rc, err := os.ReadFile(rcPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", rcPath, err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(rc))
	var ns []string
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if s, ok := strings.CutPrefix(line, "nameserver"); ok {
			ns = append(ns, strings.TrimSpace(s))
		}
	}
	if len(ns) == 0 {
		return nil, fmt.Errorf("no nameservers found in %s", rcPath)
	}
	return ns, nil
}

func (d *dnsGenerator) generateFromK8sPod(name, qt, ns string) error {
	const namespace = "gadget"
	const prefix = "dns-test"

	// Ensure unique pod name and container name
	podName, err := generators.GenerateRandomPodName(prefix + "-pod")
	if err != nil {
		return fmt.Errorf("could not generate pod name: %w", err)
	}
	containerName, err := generators.GenerateRandomContainerName(prefix + "-container")
	if err != nil {
		return fmt.Errorf("could not generate container name: %w", err)
	}

	secs := fmt.Sprintf("%g", d.interval.Seconds())

	// Static Pod manifest for DNS event generation
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  restartPolicy: Never
  containers:
  - name: %s
    image: busybox:latest
    command:
      - sh
      - -c
      - |
        i=0
        while true; do
          nslookup -debug -type=%s %s %s || exit 1
          i=$(expr $i + 1)
          if [ %d -gt 0 ] && [ "$i" -ge %d ]; then
            exit 0
          fi
          sleep %s
        done
`, podName, namespace, containerName, qt, name, ns, d.count, d.count, secs)

	d.logger.Debugf("K8sNode mode: DNS %q type=%q ns %s every %s (max %d)",
		name, qt, ns, secs, d.count)

	k8sClient, err := k8sutil.NewClientset("", "event-generator-dns")
	if err != nil {
		return fmt.Errorf("creating Kubernetes clientset: %w", err)
	}

	// Decode manifest YAML into a Pod object
	var pod corev1.Pod
	if err := yaml.NewYAMLOrJSONDecoder(strings.NewReader(manifest), 4096).Decode(&pod); err != nil {
		return fmt.Errorf("decoding pod manifest: %w", err)
	}

	// Create the pod in the cluster
	_, err = k8sClient.CoreV1().Pods(namespace).Create(context.TODO(), &pod, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("creating pod: %w", err)
	}

	d.logger.Debugf("Pod %q created in namespace %q", podName, namespace)

	go func() {
		defer func() {
			// Delete the pod so that Kubernetes cleans it up
			deletePolicy := metav1.DeletePropagationForeground
			err := k8sClient.CoreV1().Pods(namespace).Delete(
				context.TODO(),
				podName,
				metav1.DeleteOptions{
					PropagationPolicy: &deletePolicy,
				},
			)
			if err != nil {
				d.errs <- fmt.Errorf("deleting pod: %w", err)
				// Still close doneCh to avoid deadlock
			}

			// Signal that the goroutine is done
			close(d.doneCh)
		}()

		// wait for Cleanup() to signal stop
		<-d.stopCh

		// Capture the pod's exit code and logs.
		// Wait for the pod to complete and get its exit code and logs
		var exitCode int32 = -1
		var logs string
		for {
			pod, err := k8sClient.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
			if err != nil {
				d.errs <- fmt.Errorf("getting pod: %w", err)
				return
			}
			if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
				// Find the container status
				for _, cs := range pod.Status.ContainerStatuses {
					if cs.Name == containerName && cs.State.Terminated != nil {
						exitCode = cs.State.Terminated.ExitCode
						break
					}
				}
				break
			}
			time.Sleep(1 * time.Second)
		}

		// Get pod logs
		req := k8sClient.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{Container: containerName})
		logBytes, err := req.Do(context.TODO()).Raw()
		if err != nil {
			logs = fmt.Sprintf("error fetching logs: %v", err)
		} else {
			logs = string(logBytes)
		}

		if exitCode != 0 {
			d.errs <- fmt.Errorf("%q container exited with code %d and logs:\n==== container logs ====\n%s\n==== container logs ====", containerName, exitCode, logs)
		}
		d.logger.Debugf("%q container exited with code %d and logs:\n%s", containerName, exitCode, logs)

		// d.logger.Debugf("%q container exited with code %d and logs:\n%s", containerName, exitCode, logs)
	}()

	return nil
}

func init() {
	generators.Register(name, New)
}
