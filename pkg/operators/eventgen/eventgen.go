package eventgen

import (
	"fmt"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	name                  = "eventgen"
	ParamEventGenEnable   = "eventgen-enable"
	ParamEventGenType     = "eventgen-type"
	ParamEventGenTarget   = "eventgen-target"
	ParamEventGenCount    = "eventgen-count"
	ParamEventGenInterval = "eventgen-interval"
)

const (
	EventTypeDNS  = "dns"
	EVentTypeHTTP = "http"
)

type Generator interface {
	Generate(domain, countStr, intervalStr string) (string, string, string, error)
	Cleanup() (string, error)
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
			Key:            ParamEventGenType,
			Description:    "Type of event to generate",
			TypeHint:       api.TypeString,
			PossibleValues: []string{EventTypeDNS, EVentTypeHTTP},
		},
		&api.Param{
			Key:         ParamEventGenTarget,
			Description: "Target for event generator",
		},
		&api.Param{
			Key:          ParamEventGenCount,
			Description:  "Number of events to generate (infinite loop bu default)",
			TypeHint:     api.TypeInt,
			DefaultValue: "-1",
		},
		&api.Param{
			Key:          ParamEventGenInterval,
			Description:  "Interval between events in seconds(default 1s)",
			TypeHint:     api.TypeFloat32,
			DefaultValue: "1",
		},
	}
}

func (e eventGenOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	enable, _ := instanceParamValues[ParamEventGenEnable]
	eventType, _ := instanceParamValues[ParamEventGenType]
	target, _ := instanceParamValues[ParamEventGenTarget]
	count, _ := instanceParamValues[ParamEventGenCount]
	interval, _ := instanceParamValues[ParamEventGenInterval]

	return &eventGenOperatorInstance{
		enable:    enable == "true",
		eventType: eventType,
		target:    target,
		count:     count,
		interval:  interval,
	}, nil
}

func (e eventGenOperator) Priority() int {
	return 0
}

type eventGenOperatorInstance struct {
	enable    bool
	eventType string
	target    string
	count     string
	interval  string
	generator Generator
	podName   string
	namespace string
	container string
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

	gadgetCtx.Logger().Debugf("Starting EventGen with type: %s, target: %s", e.eventType, e.target)

	var err error
	e.generator, err = NewGenerator(e.eventType, gadgetCtx.Logger())
	if err != nil {
		return fmt.Errorf("failed to create generator: %v", err)
	}

	e.namespace, e.podName, e.container, err = e.generator.Generate(e.target, e.count, e.interval)
	if err != nil {
		return fmt.Errorf("failed to generate event: %v", err)
	}

	gadgetCtx.Logger().Debugf("Generated %s event successfully using: \n"+
		"Namespace: %s \n"+
		"pod: %s \n"+
		"container: %s", e.eventType, e.namespace, e.podName, e.container)
	return nil
}

func (e *eventGenOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	if e.generator != nil {
		_, err := e.generator.Cleanup()
		if err != nil {
			return fmt.Errorf("failed to cleanup event pod: %v", err)
		}
		gadgetCtx.Logger().Debugf("Successfully terminated pod %s", e.podName)
	}
	return nil
}

func NewGenerator(eventType string, log logger.Logger) (Generator, error) {
	config, err := getKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get Kubernetes config: %v", err)
	}

	switch eventType {
	case "dns":
		return NewDNSGenerator(config, log)
	case "http":
		return NewHTTPGenerator(config, log)
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
