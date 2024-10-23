package eventgen

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/eventgenerator"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type eventGenOperator struct{}

func (e eventGenOperator) Name() string {
	return name
}

func (e eventGenOperator) Init(params *params.Params) error {
	return nil
}

func (e eventGenOperator) GlobalParams() api.Params {
	return getGlobalParams()
}

func (e eventGenOperator) InstanceParams() api.Params {
	return getInstanceParams()
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
	generator eventgenerator.Generator
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
	e.generator, err = eventgenerator.NewGenerator(e.eventType, gadgetCtx.Logger())
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

// Export the operator instance
var EventGen = &eventGenOperator{}