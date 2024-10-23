package eventgen

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
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
	EventTypeHTTP = "http"
)

// getGlobalParams returns the operator's global parameters
func getGlobalParams() api.Params {
	return api.Params{
		&api.Param{
			Key:         ParamEventGenEnable,
			Description: "Enable event generation",
			TypeHint:    "bool",
		},
	}
}

// getInstanceParams returns the operator's instance parameters
func getInstanceParams() api.Params {
	return api.Params{
		&api.Param{
			Key:            ParamEventGenType,
			Description:    "Type of event to generate",
			TypeHint:       api.TypeString,
			PossibleValues: []string{EventTypeDNS, EventTypeHTTP},
		},
		&api.Param{
			Key:         ParamEventGenTarget,
			Description: "Target for event generator",
		},
		&api.Param{
			Key:          ParamEventGenCount,
			Description:  "Number of events to generate (infinite loop by default)",
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