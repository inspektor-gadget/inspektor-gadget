package k8sutil

import (
	"path/filepath"

	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func NewClientset(kubeconfigPath string) (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error
	if kubeconfigPath != "" {
		// kubeconfig is set explicitly (-kubeconfig flag or $KUBECONFIG variable)
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	} else {
		// kubeconfig from a pod Service Account token
		config, err = rest.InClusterConfig()
		if err == rest.ErrNotInCluster {
			// kubeconfig from $HOME/.kube/config
			if home := homedir.HomeDir(); home != "" {
				config, err = clientcmd.BuildConfigFromFlags("", filepath.Join(home, ".kube", "config"))
			}
		}
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

func NewClientsetFromConfigFlags(flags *genericclioptions.ConfigFlags) (*kubernetes.Clientset, error) {
	config, err := flags.ToRESTConfig()
	if err != nil {
		return nil, err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return client, nil
}
