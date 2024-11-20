package eventgen

import (
    "fmt"
    "strconv"
    "time"

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
    enable, exists := instanceParamValues[ParamEventGenEnable]
    eventType, _ := instanceParamValues[ParamEventGenType]
    paramsStr, _ := instanceParamValues[ParamEventGenParams]
    countVal, _ := instanceParamValues[ParamEventGenCount]
    intervalVal, _ := instanceParamValues[ParamEventGenInterval]
    namespace, hasNamespace := instanceParamValues[ParamEventGenNamespace]
    podName, _ := instanceParamValues[ParamEventGenPodName]
    container, _ := instanceParamValues[ParamEventGenContainer]

    if !exists || enable != "true" {
        return &eventGenOperatorInstance{enable: false}, nil
    }

    if eventType == "" {
        return nil, fmt.Errorf("eventgen-type not specified")
    }

    // Determine which approach to use
    useNamespaceApproach := hasNamespace && namespace != ""

    if useNamespaceApproach {
        if podName == "" || container == "" {
            return nil, fmt.Errorf("pod name and container name are required when using namespace approach")
        }
    }

    // Parse count
    count := eventgenerator.InfiniteCount
    if countVal != "" {
        parsedCount, err := strconv.Atoi(countVal)
        if err != nil {
            count = eventgenerator.InfiniteCount
        } else {
            count = parsedCount
        }
    }

    // Parse interval
    interval := time.Second
    if intervalVal != "" {
        parsedInterval, err := time.ParseDuration(intervalVal)
        if err != nil {
            return nil, fmt.Errorf("invalid interval format: %w", err)
        }
        interval = parsedInterval
    }

    // Create params map
    params := ParseParams(paramsStr)
    
    // Add namespace approach params to the map if using that approach
    if useNamespaceApproach {
        params["namespace"] = namespace
        params["pod"] = podName
        params["container"] = container
    }

    return &eventGenOperatorInstance{
        enable:              true,
        eventType:          eventType,
        params:             params,
        count:              count,
        interval:           interval,
        namespace:          namespace,
        podName:            podName,
        container:          container,
        useNamespaceApproach: useNamespaceApproach,
    }, nil
}

func (e eventGenOperator) Priority() int {
    return 0
}

type eventGenOperatorInstance struct {
    enable      bool
    eventType   string
    params      map[string]string
    count       int
    interval    time.Duration
    generator   eventgenerator.Generator
    namespace   string
    podName     string
    container   string
    useNamespaceApproach bool
}

func (e *eventGenOperatorInstance) Name() string {
	return name
}


func (e *eventGenOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
    if !e.enable {
        if e.eventType != "" {
            gadgetCtx.Logger().Info("Eventgen not enabled, skipping")
        }
        return nil
    }

    gadgetCtx.Logger().Debugf("Starting EventGen with type: %s, params: %v", e.eventType, e.params)
    var err error

    if e.useNamespaceApproach {
        switch e.eventType {
        case EventTypeDNS:
            e.generator, err = eventgenerator.NewNamespaceGenerator(e.eventType, gadgetCtx.Logger())
        case EventTypeHTTP:
            return fmt.Errorf("HTTP events with namespace approach not implemented yet")
        default:
            return fmt.Errorf("unsupported event type for namespace approach: %s", e.eventType)
        }
    } else {
        // Use original pod-based approach
        switch e.eventType {
        case EventTypeDNS:
            e.generator, err = eventgenerator.NewPodGenerator(e.eventType, gadgetCtx.Logger())
        case EventTypeHTTP:
            return fmt.Errorf("HTTP events not implemented yet")
        default:
            return fmt.Errorf("unsupported event type: %s", e.eventType)
        }
    }

    if err != nil {
        return fmt.Errorf("creating generator: %w", err)
    }

    // Generate events using selected generator
    err = e.generator.Generate(e.params, e.count, e.interval)
    if err != nil {
        return fmt.Errorf("generating event: %w", err)
    }

    gadgetCtx.Logger().Debugf("Generated %s event successfully using %s approach", 
        e.eventType, 
        map[bool]string{true: "namespace", false: "pod"}[e.useNamespaceApproach])
    return nil
}

func (e *eventGenOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
    if e.generator != nil {
        _, err := e.generator.Cleanup()
        if err != nil {
            return fmt.Errorf("cleaning up event generator: %w", err)
        }
    }
    return nil
}

var EventGen = &eventGenOperator{}