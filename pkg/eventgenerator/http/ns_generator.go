package http

// Using exact same imports as DNS generator
import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

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

func NewHTTPNSGenerator(config *rest.Config, log logger.Logger) (*Generator, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating Kubernetes client: %w", err)
	}

	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("no pods found")
	}

	nodeName := pods.Items[0].Spec.NodeName

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

func (h *Generator) Generate(params map[string]string, count int, interval time.Duration) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	h.namespace = params["namespace"]
	h.podName = params["pod"]
	h.containerName = params["container"]
	url, ok := params["url"]
	if !ok {
		return fmt.Errorf("url parameter is required for HTTP event generation")
	}

	if h.namespace == "" || h.podName == "" || h.containerName == "" {
		return fmt.Errorf("namespace, pod and container parameters are required")
	}

	pod, err := h.clientset.CoreV1().Pods(h.namespace).Get(context.TODO(), h.podName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("getting pod %s/%s: %w", h.namespace, h.podName, err)
	}

	nodeName := pod.Spec.NodeName
	if nodeName == "" {
		return fmt.Errorf("pod %s/%s not scheduled to any node", h.namespace, h.podName)
	}

	k8sClient, err := containercollection.NewK8sClient(nodeName)
	if err != nil {
		return fmt.Errorf("creating k8s client for node %s: %w", nodeName, err)
	}
	defer k8sClient.Close()

	containers := k8sClient.GetRunningContainers(pod)
	if len(containers) == 0 {
		return fmt.Errorf("no running containers found in pod %s/%s", h.namespace, h.podName)
	}

	var targetContainer *containercollection.Container
	for _, c := range containers {
		if c.K8s.ContainerName == h.containerName {
			targetContainer = &c
			break
		}
	}

	if targetContainer == nil {
		return fmt.Errorf("container %s not found in pod %s/%s", h.containerName, h.namespace, h.podName)
	}

	pid := targetContainer.Runtime.ContainerPID
	netnse, err := containerutils.GetNetNs(int(pid))
	if err != nil {
		h.logger.Debugf("Direct GetNetNs error: %v", err)
	} else {
		h.logger.Debugf("Direct NetworkNS value: %d", netnse)
	}

	err = nsenter.NetnsEnter(int(pid), func() error {
		i := 1
		for i <= count || count == -1 {
			if err := h.generateHTTPQuery(url); err != nil {
				h.logger.Warnf("HTTP request failed: %v", err)
			}
			if i < count || count == -1 {
				time.Sleep(interval)
			}
			i++
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("executing HTTP Query in network namespace: %w", err)
	}

	return nil
}

func (h *Generator) generateHTTPQuery(url string) error {
    if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
        url = "http://" + url
    }

    client := &http.Client{
        Timeout: 10 * time.Second,
    }
    
    resp, err := client.Get(url)
    if err != nil {
        return fmt.Errorf("HTTP request failed: %w", err)
    }
    defer resp.Body.Close()
    
    h.logger.Debugf("HTTP request to %s returned status code: %d", url, resp.StatusCode)
    return nil
}
// func (h *Generator) generateHTTPQuery(url string) error {
//     // Try different possible paths for curl
//     curlPaths := []string{
//         "/usr/bin/curl",
//         "/bin/curl",
//         "/usr/local/bin/curl",
//         "curl",  // if it's in PATH
//     }

//     var cmd *exec.Cmd
//     var output []byte
//     var err error

//     for _, curlPath := range curlPaths {
//         cmd = exec.Command("/usr/bin/curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-L", url)
//         output, err = cmd.CombinedOutput()
//         if err == nil {
//             h.logger.Debugf("HTTP request to %s returned status code: %s", url, string(output))
//             return nil
//         }
//         h.logger.Debugf("Tried curl at %s: %v", curlPath, err)
//     }
    
//     return fmt.Errorf("HTTP request failed: no working curl found")
// }

func (h *Generator) Cleanup() (string, error) {
	// Ensure we are back in original namespace
	if h.origNetNS != 0 {
		err := netns.Set(h.origNetNS)
		if err != nil {
			return "", fmt.Errorf("restoring original network namespace: %w", err)
		}
		h.origNetNS.Close()
	}
	return "", nil
}
