package factory

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

// SetKubernetesDefaults sets default values on the provided client config for accessing the
// Kubernetes API or returns an error if any of the defaults are impossible or invalid.
// TODO this isn't what we want.  Each clientset should be setting defaults as it sees fit.
func SetKubernetesDefaults(config *rest.Config) error {
	// TODO remove this hack.  This is allowing the GetOptions to be serialized.
	config.GroupVersion = &schema.GroupVersion{Group: "", Version: "v1"}

	if config.APIPath == "" {
		config.APIPath = "/api"
	}
	if config.NegotiatedSerializer == nil {
		// This codec factory ensures the resources are not converted. Therefore, resources
		// will not be round-tripped through internal versions. Defaulting does not happen
		// on the client.
		config.NegotiatedSerializer = &serializer.WithoutConversionCodecFactory{CodecFactory: scheme.Codecs}
	}
	return rest.SetKubernetesDefaults(config)
}
