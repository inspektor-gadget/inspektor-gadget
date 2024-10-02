package eventgen

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	name                = "eventgen"
	ParamEventGenEnable = "eventgen-enable"
	ParamEventGenType   = "eventgen-type"
	ParamEventGenTarget = "eventgen-target"
)

type Generator interface {
	Generate(target string) (string, error)
	Cleanup(podName string) error
}

type eventGenOperator struct{}

func (e eventGenOperator) Name() string {
	return name
}

func (e eventGenOperator) Init(params *params.Params) error {
	return nil
}

func (e eventGenOperator) GlobalParams() api.Params {
	return nil
}

func (e eventGenOperator) InstanceParams() api.Params {
	return api.Params{
		&api.Param{
			Key:         ParamEventGenEnable,
			Description: "Enable event generation",
			TypeHint:    "bool",
		},
		&api.Param{
			Key:         ParamEventGenType,
			Description: "Type of event to generate (dns or http)",
		},
		&api.Param{
			Key:         ParamEventGenTarget,
			Description: "Target for event generator",
		},
	}
}

func (e eventGenOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	enable, _ := instanceParamValues[ParamEventGenEnable]
	eventType, _ := instanceParamValues[ParamEventGenType]
	target, _ := instanceParamValues[ParamEventGenTarget]

	return &eventGenOperatorInstance{
		enable:    enable == "true",
		eventType: eventType,
		target:    target,
	}, nil
}

func (e eventGenOperator) Priority() int {
	return 0
}

type eventGenOperatorInstance struct {
	enable    bool
	eventType string
	target    string
	generator Generator
	podName   string
}

func (e eventGenOperatorInstance) Name() string {
	return name
}

func (e *eventGenOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	if !e.enable {
		gadgetCtx.Logger().Info("Eventgen not enabled, skipping")
		return nil
	}

	if e.eventType == "" {
		return fmt.Errorf("eventgen-type not specified")
	}

	if e.target == "" {
		return fmt.Errorf("eventgen-target not specified")
	}

	gadgetCtx.Logger().Infof("Starting EventGen with type: %s, target: %s", e.eventType, e.target)

	var err error
	e.generator, err = NewGenerator(e.eventType)
	if err != nil {
		return fmt.Errorf("failed to create generator: %v", err)
	}

	e.podName, err = e.generator.Generate(e.target)
	if err != nil {
		return fmt.Errorf("failed to generate event: %v", err)
	}

	gadgetCtx.Logger().Infof("Generated %s event using pod %s", e.eventType, e.podName)
	return nil
}

func (e *eventGenOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	if e.generator != nil && e.podName != "" {
		err := e.generator.Cleanup(e.podName)
		if err != nil {
			return fmt.Errorf("failed to cleanup event pod: %v", err)
		}
		gadgetCtx.Logger().Infof("Cleaned up event pod %s", e.podName)
	}
	return nil
}

func NewGenerator(eventType string) (Generator, error) {
	config, err := getKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get Kubernetes config: %v", err)
	}

	switch eventType {
	case "dns":
		return NewDNSGenerator(config)
	case "http":
		return NewHTTPGenerator(config)
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

var EventGen = &eventGenOperator{}

func init() {
	operators.RegisterDataOperator(EventGen)
}
