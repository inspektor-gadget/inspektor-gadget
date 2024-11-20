package eventgenerator

import (
	"fmt"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/eventgenerator/dns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Generator interface {
    Generate(params map[string]string, count int, interval time.Duration) error
    Cleanup() (string, error)
}

const (
	InfiniteCount = -1
)

func NewPodGenerator(eventType string, log logger.Logger) (Generator, error) {
    config, err := getKubeConfig()
    if err != nil {
        return nil, fmt.Errorf("getting Kubernetes config: %w", err)
    }

    switch eventType {
    case "dns":
        return dns.NewPodGenerator(config, log)
    default:
        return nil, fmt.Errorf("unknown generator type: %s", eventType)
    }
}

func NewNamespaceGenerator(eventType string, log logger.Logger) (Generator, error) {
    config, err := getKubeConfig()
    if err != nil {
        return nil, fmt.Errorf("getting Kubernetes config: %w", err)
    }

    switch eventType {
    case "dns":
        return dns.NewNSGenerator(config, log)
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