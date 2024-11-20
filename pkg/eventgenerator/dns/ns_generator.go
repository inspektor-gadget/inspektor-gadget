package dns

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/vishvananda/netns"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	// "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Generator struct {
    clientset           *kubernetes.Clientset
    config             *rest.Config
    logger             logger.Logger
    containerCollection *containercollection.ContainerCollection
    namespace          string
    podName            string
    containerName      string
    origNetNS          netns.NsHandle // Store original namespace
}

func NewNSGenerator(config *rest.Config, log logger.Logger) (*Generator, error) {
    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        return nil, fmt.Errorf("creating Kubernetes client: %w", err)
    }

    // Create container collection instance
    cc := &containercollection.ContainerCollection{}
    err = cc.Initialize()
    if err != nil {
        return nil, fmt.Errorf("initializing container collection: %w", err)
    }

    // Store current network namespace
    origNetNS, err := netns.Get()
    if err != nil {
        return nil, fmt.Errorf("getting current network namespace: %w", err)
    }
    
    fmt.Printf("Original network namespace: %+v\n", origNetNS)


    return &Generator{
        clientset:           clientset,
        config:             config,
        logger:             log,
        containerCollection: cc,
        origNetNS:          origNetNS,
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
    fmt.Printf("pod found: %+v\n", pod)

    // Get node name from pod
    nodeName := pod.Spec.NodeName
    if nodeName == "" {
        return fmt.Errorf("pod %s/%s not scheduled to any node", d.namespace, d.podName)
    }
    fmt.Printf("nodename found: %+v\n", nodeName)

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

    // Get container's network namespace
    containerNetNS := targetContainer.Netns
    if containerNetNS == 0 {
        return fmt.Errorf("could not get network namespace for container")
    }

    fmt.Printf("container's network namespace: %+v\n", containerNetNS)


    // Switch to container's network namespace
    newNS, err := netns.GetFromPath(fmt.Sprintf("/proc/%d/ns/net", targetContainer.Runtime.ContainerPID))
    if err != nil {
        return fmt.Errorf("getting container network namespace: %w", err)
    }
    defer newNS.Close()

    fmt.Printf("switching to network namespace: %+v\n", newNS)


    err = netns.Set(newNS)
    if err != nil {
        return fmt.Errorf("setting network namespace: %w", err)
    }

    // Generate DNS queries
    i := 1
    for i <= count || count == -1 {
        err := d.generateDNSQuery(domain)
        if err != nil {
            d.logger.Warnf("DNS query failed: %v", err)
        }

        if i < count || count == -1 {
            time.Sleep(interval)
        }
        i++
    }

    // Return to original namespace
    err = netns.Set(d.origNetNS)
    if err != nil {
        return fmt.Errorf("restoring original network namespace: %w", err)
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

    d.logger.Debugf("DNS query for %s successful", domain)
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