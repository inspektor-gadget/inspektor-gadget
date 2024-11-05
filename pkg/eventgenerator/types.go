package eventgenerator

import (
	"fmt"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/eventgenerator/dns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/eventgenerator/http"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

// Generator defines the interface for event generators
type Generator interface {
	Generate(params map[string]string, count int, interval time.Duration) error
	Cleanup() (string, error)
}

const (
	InfiniteCount = -1
)

// NewGenerator creates a new event generator based on the type
func NewGenerator(eventType string, log logger.Logger) (Generator, error) {
	config, err := getKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("getting Kubernetes config: %w", err)
	}

	switch eventType {
	case "dns":
		return dns.NewGenerator(config, log)
	case "http":
		return http.NewGenerator(config, log)
	default:
		return nil, fmt.Errorf("unknown generator type: %s", eventType)
	}
}

// k8sutils can't be used here because utils.KubernetesConfigFlags is only available when using kubectl-gadget.
// To make ig talk to API server we also need to expose Kubernetes flags.
func getKubeConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}

	kubeconfig := clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename()
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}
