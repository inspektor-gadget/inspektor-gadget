package dns

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/vishvananda/netns"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/nsenter"
)

type Generator struct {
	clientset           *kubernetes.Clientset
	config              *rest.Config
	logger              logger.Logger
	containerCollection *containercollection.ContainerCollection
	namespace           string
	podName             string
	containerName       string
	origNetNS           netns.NsHandle // Store original namespace
}

func NewNSGenerator(config *rest.Config, log logger.Logger) (*Generator, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating Kubernetes client: %w", err)
	}

	// Get node name from pod first
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: "spec.nodeName=minikube-docker", // Your node name
	})
	if err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("no pods found on node")
	}

	nodeName := pods.Items[0].Spec.NodeName

	// Create container collection instance
	cc := &containercollection.ContainerCollection{}

	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithPubSub(),
		containercollection.WithCgroupEnrichment(),
		containercollection.WithLinuxNamespaceEnrichment(),
		containercollection.WithKubernetesEnrichment(nodeName, config),
		containercollection.WithProcEnrichment(),
	}

	err = cc.Initialize(opts...)
	if err != nil {
		return nil, fmt.Errorf("initializing container collection: %w", err)
	}

	// Store current network namespace
    origNetNS, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("getting current network namespace: %w", err)
	}

	return &Generator{
		clientset:           clientset,
		config:              config,
		logger:              log,
		containerCollection: cc,
		origNetNS:           origNetNS,
	}, nil
}

func (d *Generator) Generate(params map[string]string, count int, interval time.Duration) error {
	// Lock OS thread for namespace operations
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Extract parameters
	d.namespace = params["namespace"]
	d.podName = params["pod"]
	d.containerName = params["container"]
	domain, ok := params["domain"]
	if !ok || domain == "" {
		return fmt.Errorf("domain parameter is required for DNS event generation")
	}

    	// Validate required parameters
	if d.namespace == "" || d.podName == "" || d.containerName == "" {
		return fmt.Errorf("namespace, pod and container parameters are required")
	}

	// Get pod to find its node
	pod, err := d.clientset.CoreV1().Pods(d.namespace).Get(context.TODO(), d.podName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("getting pod %s/%s: %w", d.namespace, d.podName, err)
	}

	// Get node name from pod
	nodeName := pod.Spec.NodeName
	if nodeName == "" {
		return fmt.Errorf("pod %s/%s not scheduled to any node", d.namespace, d.podName)
	}

	// Create K8sClient for the node
	k8sClient, err := containercollection.NewK8sClient(nodeName)
	if err != nil {
		return fmt.Errorf("creating k8s client for node %s: %w", nodeName, err)
	}
	defer k8sClient.Close()

	// Get running containers
	containers := k8sClient.GetRunningContainers(pod)
	if len(containers) == 0 {
		return fmt.Errorf("no running containers found in pod %s/%s", d.namespace, d.podName)
	}

	fmt.Printf("target container found: %+v\n", containers)

	if len(containers) == 0 {
		return fmt.Errorf("no containers found for pod %s/%s", d.namespace, d.podName)
	}

	var targetContainer *containercollection.Container
	for _, c := range containers {
		if c.K8s.ContainerName == d.containerName {
			targetContainer = &c
			break
		}
	}

	if targetContainer == nil {
		return fmt.Errorf("container %s not found in pod %s/%s", d.containerName, d.namespace, d.podName)
	}
    d.logger.Debugf("Found target container: PID=%d, ContainerID=%s",
    targetContainer.Runtime.ContainerPID, targetContainer.Runtime.ContainerID)

    d.logger.Debugf("Container Details:")
    d.logger.Debugf("- PID: %d", targetContainer.Runtime.ContainerPID)
    d.logger.Debugf("- NetworkNS: %d", targetContainer.Netns)
    d.logger.Debugf("- HostNetwork: %v", targetContainer.HostNetwork)

    pid := targetContainer.Runtime.ContainerPID
    // Get container's network namespace
    netnse, err := containerutils.GetNetNs(int(pid))
	if err != nil {
		d.logger.Debugf("Direct GetNetNs error: %v", err)
	}  else {
		d.logger.Debugf("Direct NetworkNS value: %d", netnse)
	}

	err = nsenter.NetnsEnter(int(pid), func() error {
		i := 1
		for i <= count || count == -1 {
			if err := d.generateDNSQuery(domain); err != nil {
				d.logger.Warnf("DNS query failed: %v", err)
			}
			if i < count || count == -1 {
				time.Sleep(interval)
			}
			i++
		}
        return nil
	})
    if err != nil {
        return fmt.Errorf("executing DNS Queryin network namespace: %w", err)
    }

    return nil
}

func (d *Generator) generateDNSQuery(domain string) error {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	m := new(dns.Msg)
	m.SetQuestion(domain, dns.TypeA)
	m.RecursionDesired = true

	c := new(dns.Client)
	r, _, err := c.Exchange(m, "1.1.1.1:53")
	if err != nil {
		return fmt.Errorf("DNS query failed: %w", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS query returned non-success code: %v", r.Rcode)
	}

	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			d.logger.Debugf("Got IP: %s", a.A)
		}
	}

	return nil
}

func (d *Generator) Cleanup() (string, error) {
	// Ensure we're back in original namespace
	if d.origNetNS != 0 {
		err := netns.Set(d.origNetNS)
		if err != nil {
			return "", fmt.Errorf("restoring original network namespace: %w", err)
		}
		d.origNetNS.Close()
	}
	return "", nil
}
