package eventgenerator

import (
	"fmt"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/eventgenerator/dns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/eventgenerator/http"
)

// Generator defines the interface for event generators
type Generator interface {
	Generate(target, countStr, intervalStr string) (string, string, string, error)
	Cleanup() (string, error)
}

// NewGenerator creates a new event generator based on the type
func NewGenerator(eventType string, log logger.Logger) (Generator, error) {
	config, err := getKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get Kubernetes config: %v", err)
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

func getKubeConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}

	kubeconfig := clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename()
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}