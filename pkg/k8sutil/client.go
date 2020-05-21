package k8sutil

import (
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func NewClientset(kubeconfigPath string) (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error
	if kubeconfigPath == "" {
		config, err = rest.InClusterConfig()
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}

	if err != nil {
		return nil, err
	}

	apiclientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return apiclientset, nil
}
