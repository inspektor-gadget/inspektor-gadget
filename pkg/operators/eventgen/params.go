package eventgen

import (
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

const (
	name                   = "eventgen"
	ParamEventGenEnable    = "eventgen-enable"
	ParamEventGenType      = "eventgen-type"
	ParamEventGenParams    = "eventgen-params"
	ParamEventGenCount     = "eventgen-count"
	ParamEventGenInterval  = "eventgen-interval"
	ParamEventGenPodName   = "eventgen-pod"
	ParamEventGenNamespace = "eventgen-namespace"
	ParamEventGenContainer = "eventgen-container"
)

const (
	EventTypeDNS  = "dns"
	EventTypeHTTP = "http"
)

// ParseParams converts a comma-separated key-value string into a map
func ParseParams(paramStr string) map[string]string {
	params := make(map[string]string)
	if paramStr == "" {
		return params
	}

	pairs := strings.Split(paramStr, ",")
	for _, pair := range pairs {
		kv := strings.Split(pair, ":")
		if len(kv) == 2 {
			params[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return params
}

// getGlobalParams returns the operator's global parameters
func getGlobalParams() api.Params {
	return api.Params{}
}

// getInstanceParams returns the operator's instance parameters
func getInstanceParams() api.Params {
	return api.Params{
		// TODO:: put --eventgen-enable parameter in global parameters section
		&api.Param{
			Key:         ParamEventGenEnable,
			Description: "Enable event generation",
			TypeHint:    "bool",
		},
		&api.Param{
			Key:            ParamEventGenType,
			Description:    "Type of event to generate",
			TypeHint:       api.TypeString,
			PossibleValues: []string{EventTypeDNS, EventTypeHTTP},
		},
		&api.Param{
			Key:         ParamEventGenParams,
			Description: "Comma-separated list of param:value pairs to pass to the event generator, e.g. eventgen-params=domain:example.com,port:80",
			TypeHint:    api.TypeString,
		},
		&api.Param{
			Key:          ParamEventGenCount,
			Description:  "Number of events to generate (use -1 for unlimited)",
			TypeHint:     api.TypeInt,
			DefaultValue: "-1",
		},
		&api.Param{
			Key:          ParamEventGenInterval,
			Description:  "Interval between events in seconds",
			TypeHint:     api.TypeString,
			DefaultValue: "1s",
		},
		&api.Param{
			Key:         ParamEventGenPodName,
			Description: "Name of the target pod",
			TypeHint:    api.TypeString,
		},
		&api.Param{
			Key:         ParamEventGenNamespace,
			Description: "Namespace of the target pod",
			TypeHint:    api.TypeString,
		},
		&api.Param{
			Key:         ParamEventGenContainer,
			Description: "container to generate events from",
			TypeHint:    api.TypeString,
		},
	}
}
